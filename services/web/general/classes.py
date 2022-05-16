from flask import json

class Audit:
    def __init__(self, id, type, custom, status, startTime, os, filename, filepath, folderpath, checks, packageId=None, packageVersion=None, packageCodeVersion=None,
                 time=None):
        self.id = id
        self.type = type
        self.custom = custom
        self.status = status
        self.startTime = startTime
        self.os = os
        self.filename = filename
        self.filepath = filepath
        self.folderpath = folderpath
        self.checks = checks
        self.packageId = packageId
        self.packageVersion = packageVersion
        self.packageCodeVersion = packageCodeVersion
        self.time = time

    def setStatus(self, value):
        self.status = value

    def setPackageId(self, value):
        self.packageId = value

    def setPackageVersion(self, value):
        self.packageVersion = value

    def setPackageCodeVersion(self, value):
        self.packageCodeVersion = value

    def setTime(self, value):
        self.time = value

class Check:
    def __init__(self, name, tag=None, severity=None, pattern=None, found=None, proofs=None, info=None):
        self.name = name
        self.tag = tag
        self.severity = severity
        self.pattern = pattern
        self.found = found
        self.proofs = proofs
        self.info = info

    def setTag(self, value):
        self.tag = value

    def setSeverity(self, value):
        self.severity = value

    def setFound(self, value):
        self.found = value

    def setProofs(self, value):
        self.proofs = value

    def setInfo(self, value):
        self.info = value

    def decodePattern(self):
        if self.pattern:
            self.pattern = self.pattern.decode()

class AuditEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Audit):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)

class CheckEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Check):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)
