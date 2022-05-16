from flask import Blueprint, request, render_template, flash, abort
from models import AuditDB
import config
from flask_login import current_user, login_required

checks_bp = Blueprint('checks', __name__, url_prefix='/checks')

@checks_bp.route('/')
def checks():
    if current_user.is_authenticated:
        page = request.args.get('page', 1, type=int)
        #audits = AuditDB.query.order_by(AuditDB.id.desc()).paginate(page, 10, True)
        audits = current_user.audits.order_by(AuditDB.id.desc()).paginate(page, 10, True)
    else:
        flash('Please Login to save and view your checks results history', 'success')
        audits = None

    return render_template('checks/checks.html', audits=audits)

@checks_bp.route('/<id>')
@login_required
def check_results(id):
    audit = AuditDB.query.get(id)
    if audit.userId == int(current_user.get_id()) or current_user.admin:
        checks = audit.checks.all()
        checkResult = {}
        sortChecks(checks, checkResult)

        if audit.os == config.ANDROID:
            return render_template('checks/check_results_android.html', checkResult=checkResult, audit=audit)
        else:
            return render_template('checks/check_results_ios.html', checkResult=checkResult, audit=audit)
    else:
        abort(403)

def sortChecks(checks, result):
    for check in checks:
        if check.tag in result:
            result[check.tag].append(check)
        else:
            result[check.tag] = [check]
