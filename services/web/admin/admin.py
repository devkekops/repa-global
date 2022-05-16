from flask import Blueprint, request, render_template, url_for, abort, redirect
from auth.auth import admin_required
from models import User, AuditDB

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/')
@admin_required
def admin():
    return redirect(url_for('admin.all_users'))

@admin_bp.route('/users')
@admin_required
def all_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.id.desc()).paginate(page, 10, True)
    return render_template('admin/all_users.html', users=users)

@admin_bp.route('/checks')
@admin_required
def all_checks():
    page = request.args.get('page', 1, type=int)
    audits = AuditDB.query.order_by(AuditDB.id.desc()).paginate(page, 10, True)
    return render_template('admin/all_checks.html', audits=audits)

@admin_bp.route('/users/<id>')
@admin_required
def checks_by_user(id):
    page = request.args.get('page', 1, type=int)
    user = User.query.get(id)
    audits = user.audits.order_by(AuditDB.id.desc()).paginate(page, 10, True)
    return render_template('checks/checks.html', audits=audits)