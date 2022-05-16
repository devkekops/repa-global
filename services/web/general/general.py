from flask import Blueprint, render_template, request, redirect, session, flash, url_for, json, abort, current_app
from werkzeug.utils import secure_filename
import config
import os
from uuid import uuid4
from general.classes import Audit, Check
from datetime import datetime
from models import AuditDB, CheckDB
from app import socketio
from app import db
from general.helper import androidAudit, iosAudit
from general.classes import CheckEncoder
from flask_login import current_user
import redis
from rq import Queue, Connection

general_bp = Blueprint('general', __name__)

AUDITS = {}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

def make_unique(string):
    ident = uuid4().__str__()[:8]
    return f"{ident}-{string}"

@general_bp.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            originalFilename = secure_filename(file.filename)
            filename = make_unique(originalFilename)
            file.save(os.path.join(config.UPLOAD_FOLDER, filename))

            session['filename'] = filename
            AUDITS[filename] = {}
            AUDITS[filename]['originalFilename'] = originalFilename

            filepath = config.UPLOAD_FOLDER + filename
            folderpath = os.path.splitext(filepath)[0] + '/'
            checks = []

            checkDBs = []
            print(filename.rsplit('.', 1))
            if filename.rsplit('.', 1)[-1].lower() == 'apk':
                platform = config.ANDROID
                for item in config.DEFAULTANDROIDCHECKS:
                    defaultCheck = Check(name=item['name'], pattern=item.get('pattern'))
                    checks.append(defaultCheck)
                    checkDBs.append(CheckDB(name=defaultCheck.name, tag=config.CHECKSINFO[defaultCheck.name]['tag'], severity=config.CHECKSINFO[defaultCheck.name]['severity'], info=config.CHECKSINFO[defaultCheck.name]['info']))
            else:
                platform = config.IOS
                for item in config.DEFAULTIOSCHECKS:
                    defaultCheck = Check(name=item['name'], pattern=item.get('pattern'))
                    checks.append(defaultCheck)
                    checkDBs.append(CheckDB(name=defaultCheck.name, tag=config.CHECKSINFO[defaultCheck.name]['tag'], severity=config.CHECKSINFO[defaultCheck.name]['severity'], info=config.CHECKSINFO[defaultCheck.name]['info']))

            custom = False
            if 'newCheckName' in request.form and 'newCheckPattern' in request.form:
                customCheckName = request.form['newCheckName']
                customCheckPattern = request.form['newCheckPattern']
                if customCheckName is not '' and customCheckPattern is not '':
                    custom = True
                    customCheck = Check(name=customCheckName, tag='custom', severity='Info', pattern=customCheckPattern.encode(), info='Strings match: ' + customCheckPattern)
                    checks.append(customCheck)
                    checkDBs.append(CheckDB(name=customCheckName, tag='custom', severity='Info', info='Strings match: ' + customCheckPattern))

            #if 'Auto' in request.headers:
            #    print("AUTO CHECK START")
            #    type = 'auto'
            #else:
            #    type = 'manual'
            type = 'manual'
            status = 'in progress'
            dt = datetime.utcnow()

            auditDB = AuditDB(type=type, custom=custom, status=status, startTime=dt, os=platform, filename=originalFilename, checks=checkDBs, userId=current_user.get_id())
            db.session.add(auditDB)
            db.session.commit()
            auditDBId = auditDB.id

            if platform is config.ANDROID:
                audit = Audit(auditDBId, type, custom, status, dt, config.ANDROID, filename, filepath, folderpath, checks)
                socketio.start_background_task(androidAudit, audit)
            else:
                audit = Audit(auditDBId, type, custom, status, dt, config.IOS, filename, filepath, folderpath, checks)
                #socketio.start_background_task(iosAudit, audit)
                with Connection(redis.from_url(current_app.config["REDIS_URL"])):
                    q = Queue()
                    #task = q.enqueue(create_task, 6)
                    task = q.enqueue(iosAudit, audit)
                    print(task.get_id())

            if type is 'auto':
                return {"id": auditDBId}
            else:
                return redirect(url_for('.checking'))

    return render_template('general/home.html')

@general_bp.route('/сhecking')
def checking():
    if 'filename' in session and session['filename'] in AUDITS:
        filename = session['filename']

        if filename.rsplit('.', 1)[1].lower() == 'apk':
            return render_template('general/checking_android.html', name=AUDITS[filename]['originalFilename'])
        else:
            return render_template('general/checking_ios.html', name=AUDITS[filename]['originalFilename'])
    else:
        abort(404)
