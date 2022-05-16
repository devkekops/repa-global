import subprocess
import re
import xml.etree.ElementTree as etree
from shutil import copyfile, rmtree
import config
import os, time
from app import socketio
from datetime import datetime
from flask import json, escape
import plistlib
from xml.dom import minidom
from bs4 import BeautifulSoup
from models import AuditDB
from models import CheckDB
from models import User
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from general.classes import CheckEncoder
from app import app
from app import db

def saveAndSendResults(audit):
    results = {'os': audit.os, 'custom': audit.custom, 'packageId': audit.packageId, 'packageVersion': audit.packageVersion,
               'packageCodeVersion': audit.packageCodeVersion, 'time': audit.time, 'checks': {}}

    print(results)

    for check in audit.checks:
        if not check.tag:
            check.setTag(config.CHECKSINFO[check.name]['tag'])
        if not check.severity:
            check.setSeverity(config.CHECKSINFO[check.name]['severity'])
        if not check.info:
            check.setInfo(config.CHECKSINFO[check.name]['info'])
        if not config.ANDROIDBINARYSEARCHOFF:
            check.decodePattern()

    sortChecks(audit.checks, results['checks'])

    socketio.emit("progressText", "Ready!", namespace=config.NS)
    socketio.emit("results", results, namespace=config.NS)

    print("test")
    auditDB = AuditDB.query.get(audit.id)
    auditDB.status = "finished"
    auditDB.packageId = audit.packageId
    auditDB.packageVersion = audit.packageVersion
    auditDB.packageCodeVersion = audit.packageCodeVersion
    auditDB.time = audit.time

    i = 0
    for checkDB in auditDB.checks:
        checkDB.found = audit.checks[i].found
        checkDB.proofs = audit.checks[i].proofs
        i += 1
    db.session.commit()

def sortChecks(checks, result):
    for check in checks:
        if check.tag in result:
            result[check.tag].append(json.dumps(check, cls=CheckEncoder))
        else:
            result[check.tag] = [json.dumps(check, cls=CheckEncoder)]

def androidAudit(audit):
    time.sleep(1)
    socketio.emit("progressText", "Reversing...", namespace=config.NS)
    for line in doApktool(audit.filepath, audit.folderpath):
        if line.startswith('I: Decoding AndroidManifest.xml'):
            socketio.emit("progress", {"text": 3}, namespace=config.NS)
            socketio.emit("progressText", "Reversing: 12%", namespace=config.NS)
        if line.startswith('I: Decoding values'):
            socketio.emit("progress", {"text": 6}, namespace=config.NS)
            socketio.emit("progressText", "Reversing: 25%", namespace=config.NS)
        if line.startswith('I: Copying assets'):
            socketio.emit("progress", {"text": 25}, namespace=config.NS)
            socketio.emit("progressText", "Reversing: 89%", namespace=config.NS)
    socketio.emit("progress", {"text": 28}, namespace=config.NS)

    socketio.emit("progressText", "Audit Manifest...", namespace=config.NS)
    auditManifest(audit)
    socketio.emit("progress", {"text": 30}, namespace=config.NS)

    socketio.emit("progressText", "Searching Patterns...", namespace=config.NS)
    search(audit)
    socketio.emit("progress", {"text": 100}, namespace=config.NS)

    os.remove(audit.filepath)
    rmtree(audit.folderpath)

    endTime = datetime.utcnow()
    auditTime = str(endTime - audit.startTime).split('.')[0]
    audit.setTime(auditTime)

    saveAndSendResults(audit)

def iosAudit(audit):
    time.sleep(1)
    socketio.emit("progressText", "Extracting...", namespace=config.NS)
    doUnzip(audit.filepath, audit.folderpath)
    socketio.emit("progress", {"text": 5}, namespace=config.NS)

    socketio.emit("progressText", "Audit Info.plist...", namespace=config.NS)
    auditInfoPlist(audit)
    socketio.emit("progress", {"text": 10}, namespace=config.NS)

    socketio.emit("progressText", "Searching Patterns...", namespace=config.NS)
    search(audit)
    socketio.emit("progress", {"text": 100}, namespace=config.NS)

    os.remove(audit.filepath)
    rmtree(audit.folderpath)

    endTime = datetime.utcnow()
    auditTime = str(endTime - audit.startTime).split('.')[0]
    #print(auditTime)
    audit.setTime(auditTime)

    saveAndSendResults(audit)

def auditInfoPlist(audit):
    payloadPath = audit.folderpath + 'Payload/'
    infoPlistPath = payloadPath + next(os.walk(payloadPath))[1][0] + '/Info.plist'
    with open(infoPlistPath, 'rb') as fp:
        pl = plistlib.load(fp)

        if 'CFBundleIdentifier' in pl:
            audit.setPackageId(pl['CFBundleIdentifier'])

        if 'CFBundleShortVersionString' in pl:
            audit.setPackageVersion(pl['CFBundleShortVersionString'])

        if 'CFBundleVersion' in pl:
            audit.setPackageCodeVersion(pl['CFBundleVersion'])

        audit.checks[0].setFound('no')
        audit.checks[0].setProofs('-')
        audit.checks[1].setFound('no')
        audit.checks[1].setProofs('-')
        audit.checks[2].setFound('no')
        audit.checks[2].setProofs('-')
        audit.checks[3].setFound('no')
        audit.checks[3].setProofs('-')
        audit.checks[4].setFound('no')
        audit.checks[4].setProofs('-')

        if config.NSAPPTRANSPORTSECURITY in pl:
            cleanInfoPlistPath = infoPlistPath.split(config.UPLOAD_FOLDER)[1][9:]
            if config.NSALLOWSARBITRARYLOADS in pl[config.NSAPPTRANSPORTSECURITY]:
                if pl[config.NSAPPTRANSPORTSECURITY][config.NSALLOWSARBITRARYLOADS] is True:
                    audit.checks[0].setFound('yes')
                    audit.checks[0].setProofs(json.dumps(pl[config.NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + cleanInfoPlistPath)

            if config.NSALLOWSARBITRARYLOADSFORMEDIA in pl[config.NSAPPTRANSPORTSECURITY]:
                if pl[config.NSAPPTRANSPORTSECURITY][config.NSALLOWSARBITRARYLOADSFORMEDIA] is True:
                    audit.checks[1].setFound('yes')
                    audit.checks[1].setProofs(json.dumps(pl[config.NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + cleanInfoPlistPath)

            if config.NSALLOWSARBITRARYLOADSINWEBCONTENT in pl[config.NSAPPTRANSPORTSECURITY]:
                if pl[config.NSAPPTRANSPORTSECURITY][config.NSALLOWSARBITRARYLOADSINWEBCONTENT] is True:
                    audit.checks[2].setFound('yes')
                    audit.checks[2].setProofs(json.dumps(pl[config.NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + cleanInfoPlistPath)

            if config.NSALLOWSLOCALNETWORKING in pl[config.NSAPPTRANSPORTSECURITY]:
                if pl[config.NSAPPTRANSPORTSECURITY][config.NSALLOWSLOCALNETWORKING] is True:
                    audit.checks[3].setFound('yes')
                    audit.checks[3].setProofs(json.dumps(pl[config.NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + cleanInfoPlistPath)

            if config.NSEXCEPTIONDOMAINS in pl[config.NSAPPTRANSPORTSECURITY]:
                audit.checks[4].setFound('yes')
                audit.checks[4].setProofs(json.dumps(pl[config.NSAPPTRANSPORTSECURITY], sort_keys = True, indent = 4) + ":\n" + cleanInfoPlistPath)

        fp.close()

def doApktool(filepath, folderpath):
    popen = subprocess.Popen(['apktool', 'd', '-f', filepath, '-o', folderpath], stdout=subprocess.PIPE)
    for line in popen.stdout:
        yield line.decode()
    popen.stdout.close()
    popen.wait()

def doApkx(filepath):
    subprocess.call(['apkx', filepath])

def doUnzip(filepath, folderpath):
    subprocess.call(['unzip', '-o', filepath, '-d', folderpath], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

def auditManifest(audit):
    folderpath = audit.folderpath
    manifestpath = folderpath + 'AndroidManifest.xml'
    tree = etree.parse(manifestpath)
    root = tree.getroot()
    app = root.find('application')
    appAttrs = app.attrib

    rootAttrs = root.attrib
    if 'package' in rootAttrs:
        audit.setPackageId(rootAttrs['package'])

    p = subprocess.Popen([config.AAPTPATH, 'dump', 'badging', audit.filepath], stdout=subprocess.PIPE)
    aaptOutput = p.communicate()[0].decode("utf-8")
    version = re.findall('versionName=\'([^\s]+)\'', aaptOutput)[0]
    codeVersion = re.findall('versionCode=\'([^\s]+)\'', aaptOutput)[0]
    if version:
        audit.setPackageVersion(version)
    if codeVersion:
        audit.setPackageCodeVersion(codeVersion)

    audit.checks[0].setFound('no')
    audit.checks[0].setProofs('-')
    audit.checks[1].setFound('no')
    audit.checks[1].setProofs('-')
    audit.checks[2].setFound('no')
    audit.checks[2].setProofs('-')
    audit.checks[3].setFound('no')
    audit.checks[3].setProofs('-')
    audit.checks[4].setFound('no')
    audit.checks[4].setProofs('-')
    audit.checks[5].setFound('no')
    audit.checks[5].setProofs('-')
    audit.checks[6].setFound('no')
    audit.checks[6].setProofs('-')

    if '{http://schemas.android.com/apk/res/android}networkSecurityConfig' in appAttrs:
        nscEntry = grepBinary(manifestpath, config.NSCENTRY)
        nscconfigpath = folderpath + 'res/xml/network_security_config.xml'
        cleanNscConfigPath = nscconfigpath.split(config.UPLOAD_FOLDER)[1][9:]

        trustAnchors = grepBinary(nscconfigpath, config.TRUSTANCHORS)
        #print(trustAnchors)
        if trustAnchors:
            nscconfig = open(nscconfigpath, "r").read()
            audit.checks[0].setFound('yes')
            audit.checks[0].setProofs(json.dumps(nscEntry, sort_keys = True, indent = 4) + '\n' + escape(nscconfig) + ":\n" + cleanNscConfigPath)

        #https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted
        cleartextTraffic = grepBinary(nscconfigpath, config.CLEARTEXTTRAFFICPERMITTED)
        #print(cleartextTraffic)
        if cleartextTraffic:
            nscconfig = open(nscconfigpath, "r").read()
            audit.checks[1].setFound('yes')
            audit.checks[1].setProofs(json.dumps(nscEntry, sort_keys = True, indent = 4) + '\n' + escape(nscconfig) + ":\n" + cleanNscConfigPath)

    appMetaDatas = app.findall('meta-data')
    disableSafeBrowsing = False
    for appMetaData in appMetaDatas:
        if appMetaData.attrib['{http://schemas.android.com/apk/res/android}name'] == 'android.webkit.WebView.EnableSafeBrowsing':
            if appMetaData.attrib['{http://schemas.android.com/apk/res/android}value'] == 'false':
                disableSafeBrowsing = True
                break

    if disableSafeBrowsing:
        disableSafeBrowsingEntry = grepBinary(manifestpath, config.DISABLESAFEBROWSING)
        audit.checks[2].setFound('yes')
        audit.checks[2].setProofs(escape(json.dumps(disableSafeBrowsingEntry, sort_keys = True, indent = 4)))


    expComps = getExportedComponents(manifestpath)

    with open(manifestpath) as mp:
        soup = BeautifulSoup(mp, 'html.parser')

    if expComps['activity'] or expComps['activity-alias']:
        proofs = ""
        if expComps['activity']:
            for activityName in expComps['activity']:
                tag = soup.find('activity', {"android:name": activityName})
                proofs += tag.prettify() + grep(manifestpath, activityName)[activityName][0] + '\n\n'
        if expComps['activity-alias']:
            for activityAliasName in expComps['activity']:
                tag = soup.find('activity', {"android:name": activityAliasName})
                proofs += tag.prettify() + grep(manifestpath, activityAliasName)[activityAliasName][0] + '\n\n'

        audit.checks[3].setFound('yes')
        audit.checks[3].setProofs(escape(proofs))

    if expComps['receiver']:
        proofs = ""
        for receiverName in expComps['receiver']:
            tag = soup.find('receiver', {"android:name": receiverName})
            proofs += tag.prettify() + grep(manifestpath, receiverName)[receiverName][0] + '\n\n'

        audit.checks[4].setFound('yes')
        audit.checks[4].setProofs(escape(proofs))

    if expComps['service']:
        proofs = ""
        for serviceName in expComps['service']:
            tag = soup.find('service', {"android:name": serviceName})
            proofs += tag.prettify() + grep(manifestpath, serviceName)[serviceName][0] + '\n\n'

        audit.checks[5].setFound('yes')
        audit.checks[5].setProofs(escape(proofs))

    if expComps['provider']:
        proofs = ""
        for providerName in expComps['provider']:
            tag = soup.find('provider', {"android:name": providerName})
            proofs += tag.prettify() + grep(manifestpath, providerName)[providerName][0] + '\n\n'

        audit.checks[6].setFound('yes')
        audit.checks[6].setProofs(escape(proofs))
    mp.close()

def search(audit):
    folderpath = audit.folderpath
    files = findfiles(folderpath)
    filesSize = len(files)

    if audit.os is config.ANDROID:
        httpInsecureLinksCheckIndex = config.ANDROIDHTTPINSECURELINKSCHECKINDEX
        httpQaLinksCheckIndex = config.ANDROIDHTTPQALINKSCHECKINDEX

        wsInsecureLinksCheckIndex = config.ANDROIDWSINSECURELINKSCHECKINDEX
        wsQaLinksCheckIndex = config.ANDROIDWSQALINKSCHECKINDEX

        blacklistUrls = config.ANDROIDBLACKLISTURLS if config.ANDROIDBINARYSEARCHOFF else config.ANDROIDBLACKLISTURLSBINARY
        startLevel = config.ANDROIDSTARTLEVEL
        finishLevel = config.ANDROIDFINISHLEVEL

    else:
        httpInsecureLinksCheckIndex = config.IOSHTTPINSECURELINKSCHECKINDEX
        httpQaLinksCheckIndex = config.IOSHTTPQALINKSCHECKINDEX

        wsInsecureLinksCheckIndex = config.IOSWSINSECURELINKSCHECKINDEX
        wsQaLinksCheckIndex = config.IOSWSQALINKSCHECKINDEX

        blacklistUrls = config.IOSBLACKLISTURLS
        startLevel = config.IOSSTARTLEVEL
        finishLevel = config.IOSFINISHLEVEL

    httpLinks = {}
    wsLinks = {}

    for check in audit.checks[(wsQaLinksCheckIndex + 1):]:
        check.proofs = {}

    p = 0
    for file in files:
        p += 1
        if p % 1000 == 0:
            socketio.emit("progressText", "Searching: processed " + str(p*100//filesSize) + "%", namespace=config.NS)
            socketio.emit("progress", {"text": startLevel + p*(finishLevel-startLevel)//filesSize}, namespace=config.NS)
        if audit.os is config.ANDROID and config.ANDROIDBINARYSEARCHOFF:
            grepAll(file, httpLinks, wsLinks, audit, wsQaLinksCheckIndex, blacklistUrls)
        else:
            grepAllBinary(file, httpLinks, wsLinks, audit, wsQaLinksCheckIndex, blacklistUrls)

    audit.checks[httpInsecureLinksCheckIndex].setFound('no')
    audit.checks[httpInsecureLinksCheckIndex].setProofs('-')
    audit.checks[httpQaLinksCheckIndex].setFound('no')
    audit.checks[httpQaLinksCheckIndex].setProofs('-')

    audit.checks[wsInsecureLinksCheckIndex].setFound('no')
    audit.checks[wsInsecureLinksCheckIndex].setProofs('-')
    audit.checks[wsQaLinksCheckIndex].setFound('no')
    audit.checks[wsQaLinksCheckIndex].setProofs('-')

    if httpLinks:
        #print(httpLinks)
        httpInsecureLinks = {}
        httpQaLinks = {}
        for k in httpLinks:
            if "http://" in k:
                httpInsecureLinks[k] = httpLinks[k]
            #if "qa" in k or "test" in k or "dev" in k:
            if any(qastr in k for qastr in config.QALINKS):
                httpQaLinks[k] = httpLinks[k]
        if httpInsecureLinks:
            audit.checks[httpInsecureLinksCheckIndex].setFound('yes')
            audit.checks[httpInsecureLinksCheckIndex].setProofs(json.dumps(httpInsecureLinks, sort_keys = True, indent = 4))

        if httpQaLinks:
            audit.checks[httpQaLinksCheckIndex].setFound('yes')
            audit.checks[httpQaLinksCheckIndex].setProofs(json.dumps(httpQaLinks, sort_keys = True, indent = 4))

    if wsLinks:
        #print(wsLinks)
        wsInsecureLinks = {}
        wsQaLinks = {}
        for k in wsLinks:
            if "ws://" in k:
                wsInsecureLinks[k] = wsLinks[k]
            #if "qa" in k or "test" in k or "dev" in k:
            if any(qastr in k for qastr in config.QALINKS):
                wsQaLinks[k] = wsLinks[k]
        if wsInsecureLinks:
            audit.checks[wsInsecureLinksCheckIndex].setFound('yes')
            audit.checks[wsInsecureLinksCheckIndex].setProofs(json.dumps(wsInsecureLinks, sort_keys = True, indent = 4))

        if wsQaLinks:
            audit.checks[wsQaLinksCheckIndex].setFound('yes')
            audit.checks[wsQaLinksCheckIndex].setProofs(json.dumps(wsQaLinks, sort_keys = True, indent = 4))

    for check in audit.checks[(wsQaLinksCheckIndex + 1):]:
        if check.proofs:
            check.setFound('yes')
            jsonProofs = json.dumps(check.proofs, sort_keys = True, indent = 4)
            check.setProofs(jsonProofs)
        else:
            check.setFound('no')
            check.setProofs('-')

def findfiles(path):
    res = []
    for root, dirs, fnames in os.walk(path):
        for fname in fnames:
            if os.path.splitext(fname)[1] not in config.EXTSLIST:
                res.append(os.path.join(root, fname))
    return res

def grepAllBinary(filepath, httpLinks, wsLinks, audit, wsQaLinksCheckIndex, blacklistUrls):
    i = 0
    with open(filepath, 'rb') as f:
        try:
            for line in f:
                i += 1

                lineHttpLinks = re.findall(config.HTTPURLSBINARY, line)
                if lineHttpLinks:
                    for lineHttpLink in lineHttpLinks:
                        if not lineHttpLink.startswith(tuple(blacklistUrls)):
                            addFoundToDictBinary(lineHttpLink, httpLinks, filepath, i)

                lineWsLinks = re.findall(config.WSURLSBINARY, line)
                if lineWsLinks:
                    for lineWsLink in lineWsLinks:
                        addFoundToDictBinary(lineWsLink, wsLinks, filepath, i)

                for check in audit.checks[(wsQaLinksCheckIndex + 1):]:
                    founds = re.findall(check.pattern, line)
                    if founds:
                        for found in founds:
                            addFoundToDictBinary(found, check.proofs, filepath, i)

        except Exception as e:
            pass

        f.close()

def addFoundToDictBinary(found, dict, filepath, line):
    decodedFound = found.decode()
    cleanFilepath = filepath.split(config.UPLOAD_FOLDER)[1][9:]
    if decodedFound in dict:
        dict[decodedFound].append(cleanFilepath + ':' + str(line))
    else:
        dict[decodedFound] = [cleanFilepath + ':' + str(line)]

def grepBinary(filepath, regex):
    res = {}
    i = 0
    with open(filepath, 'rb') as f:
        try:
            for line in f:
                i += 1
                founds = re.findall(regex, line)
                if founds:
                    for found in founds:
                        addFoundToDictBinary(found, res, filepath, i)
        except Exception as e:
            pass
        f.close()
    return res

def grepAll(filepath, links, audit, qaLinksCheckIndex, blacklistUrls):
    i = 0
    with open(filepath) as f:
        try:
            for line in f:
                i += 1

                lineLinks = re.findall(config.HTTPURLS, line)
                if lineLinks:
                    for lineLink in lineLinks:
                        if not lineLink.startswith(tuple(blacklistUrls)):
                            addFoundToDict(lineLink, links, filepath, i)

                for check in audit.checks[(qaLinksCheckIndex + 1):]:
                    founds = re.findall(check.pattern, line)
                    if founds:
                        for found in founds:
                            addFoundToDict(found, check.proofs, filepath, i)

        except Exception as e:
            pass

    f.close()

def addFoundToDict(found, dict, filepath, line):
    cleanFilepath = filepath.split(config.UPLOAD_FOLDER)[1][9:]
    if found in dict:
        dict[found].append(cleanFilepath + ':' + str(line))
    else:
        dict[found] = [cleanFilepath + ':' + str(line)]

def grep(filepath, regex):
    res = {}
    i = 0
    with open(filepath) as f:
        try:
            for line in f:
                i += 1
                founds = re.findall(regex, line)
                if founds:
                    for found in founds:
                        addFoundToDict(found, res, filepath, i)
        except Exception as e:
            pass
    f.close()
    return res

def isNullOrEmptyString(input_string, strip_whitespaces=False):
    if input_string is None :
        return True
    if strip_whitespaces :
        if input_string.strip() == "" :
            return True
    else :
        if input_string == "" :
            return True
    return False

def getExportedComponents(manifestPath):
    res = {"activity": [], 'activity-alias': [], 'receiver': [], 'service': [], 'provider': []}

    PROTECTION_NORMAL = 0
    PROTECTION_DANGEROUS = 1
    PROTECTION_SIGNATURE = 2

    xml = minidom.parse(manifestPath)
    xml.normalize()

    PermissionName_to_ProtectionLevel = {}
    for item in xml.getElementsByTagName("permission"):
        name = item.getAttributeNS(config.NSANDROIDURI, "name")
        protectionLevel = item.getAttributeNS(config.NSANDROIDURI, "protectionLevel")
        if name is not None:
            try:
                if protectionLevel == "" :
                    PermissionName_to_ProtectionLevel[name] = 0
                else :
                    PermissionName_to_ProtectionLevel[name] = int(protectionLevel, 16)  #translate hex number to int
            except ValueError:
                PermissionName_to_ProtectionLevel[name] = 0

    list_ready_to_check = []
    find_tags = ["activity", "activity-alias", "service", "receiver"]

    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            name = item.getAttribute("android:name")
            exported = item.getAttribute("android:exported")
            permission = item.getAttribute("android:permission")
            has_any_actions_in_intent_filter = False
            if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):

                is_ready_to_check = False
                is_launcher = False
                has_any_non_google_actions = False
                isSyncAdapterService = False
                for sitem in item.getElementsByTagName("intent-filter"):
                    for ssitem in sitem.getElementsByTagName("action"):
                        has_any_actions_in_intent_filter = True

                        action_name = ssitem.getAttribute("android:name")
                        if (not action_name.startswith("android.")) and (not action_name.startswith("com.android.")):
                            has_any_non_google_actions = True

                        if (action_name == "android.content.SyncAdapter"):
                            isSyncAdapterService = True

                    for ssitem in sitem.getElementsByTagName("category"):
                        category_name = ssitem.getAttribute("android:name")
                        if category_name == "android.intent.category.LAUNCHER":
                            is_launcher = True

                # exported="true" or exported not set
                if exported == "":
                    if has_any_actions_in_intent_filter:
                        # CHECK
                        is_ready_to_check = True

                elif exported.lower() == "true":  # exported = "true"
                    # CHECK
                    is_ready_to_check = True

                if (is_ready_to_check) and (not is_launcher):
                    list_ready_to_check.append((tag, name, exported, permission, has_any_non_google_actions,
                                                has_any_actions_in_intent_filter, isSyncAdapterService))
    # ------------------------------------------------------------------------
    # CHECK procedure
    list_implicit_service_components = []

    list_alerting_exposing_components_NonGoogle = []
    list_alerting_exposing_components_Google = []
    for i in list_ready_to_check:
        component = i[0]
        permission = i[3]
        hasAnyNonGoogleActions = i[4]
        has_any_actions_in_intent_filter = i[5]
        isSyncAdapterService = i[6]
        is_dangerous = False
        if permission == "":  # permission is not set
            is_dangerous = True
        else:  # permission is set
            if permission in PermissionName_to_ProtectionLevel:
                protectionLevel = PermissionName_to_ProtectionLevel[permission]
                if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
                    is_dangerous = True
            # else: #cannot find the mapping permission
            #   is_dangerous = True

        if is_dangerous:
            if (component == "service") and (has_any_actions_in_intent_filter) and (not isSyncAdapterService):
                list_implicit_service_components.append(i[1])

            if hasAnyNonGoogleActions:
                if i not in list_alerting_exposing_components_NonGoogle:
                    list_alerting_exposing_components_NonGoogle.append(i)
            else:
                if i not in list_alerting_exposing_components_Google:
                    list_alerting_exposing_components_Google.append(i)

    if list_alerting_exposing_components_NonGoogle or list_alerting_exposing_components_Google:
        if list_alerting_exposing_components_NonGoogle:
            for i in list_alerting_exposing_components_NonGoogle:
                res[i[0]].append(i[1])

        if list_alerting_exposing_components_Google:
            for i in list_alerting_exposing_components_Google:
                res[i[0]].append(i[1])

    # ------------------------------------------------------------------------
    # "exported" checking (provider):
    # android:readPermission, android:writePermission, android:permission
    list_ready_to_check = []

    for item in xml.getElementsByTagName("provider"):
        name = item.getAttribute("android:name")
        exported = item.getAttribute("android:exported")

        if (not isNullOrEmptyString(name)) and (exported.lower() != "false"):
            # exported is only "true" or non-set
            permission = item.getAttribute("android:permission")
            readPermission = item.getAttribute("android:readPermission")
            writePermission = item.getAttribute("android:writePermission")
            has_exported = True if (exported != "") else False

            list_ready_to_check.append((name, exported, permission, readPermission, writePermission, has_exported))

    list_alerting_exposing_providers_no_exported_setting = []  # providers that Did not set exported
    list_alerting_exposing_providers = []  # provider with "true" exported
    for i in list_ready_to_check:  # only exist "exported" provider or not set
        exported = i[1]
        permission = i[2]
        readPermission = i[3]
        writePermission = i[4]
        has_exported = i[5]

        is_dangerous = False
        list_perm = []
        if permission != "":
            list_perm.append(permission)
        if readPermission != "":
            list_perm.append(readPermission)
        if writePermission != "":
            list_perm.append(writePermission)

        if list_perm:  # among "permission" or "readPermission" or "writePermission", any of the permission is set
            for self_defined_permission in list_perm:  # (1)match any (2)ignore permission that is not found
                if self_defined_permission in PermissionName_to_ProtectionLevel:
                    protectionLevel = PermissionName_to_ProtectionLevel[self_defined_permission]
                    if (protectionLevel == PROTECTION_NORMAL) or (protectionLevel == PROTECTION_DANGEROUS):
                        is_dangerous = True
                        break

        else:  # none of any permission
            if exported.lower() == "true":
                is_dangerous = True

        if is_dangerous:
            list_alerting_exposing_providers.append(i)  # exported="true" and none of the permission are set => of course dangerous

    if list_alerting_exposing_providers:
        for i in list_alerting_exposing_providers:
            res['provider'].append(i[0])

    return res