from flask import Blueprint, request, render_template, redirect, url_for, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, mail
from models import User
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
import config
from flask_mail import Message
from flask_login import login_user, logout_user, login_required, current_user
from app import login_manager
from functools import wraps

auth_bp = Blueprint('auth', __name__)

def admin_required(f):
    @wraps(f)
    def wrapped_view(*args, **kwargs):
        if not current_user.admin:
            return login_manager.unauthorized()
        return f(*args, **kwargs)
    return wrapped_view

@auth_bp.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('auth/login.html')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and not user.confirmed:
            flash('Email address unconfirmed yet. Please check your inbox')
            return redirect(url_for('auth.login'))

        if not user or not password == user.password:
            flash('Invalid credentials. Please verify them and try again')
            return redirect(url_for('auth.login'))
        else:
            login_user(user)
            flash("You have been logged in")
            return redirect(url_for('general.home'))

@auth_bp.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'GET':
        return render_template('auth/signup.html')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            if user.confirmed:
                flash('Email address already exists and confirmed. Please Login')
            else:
                flash('Email address already exists, but unconfirmed yet. Please check your inbox')
            return redirect(url_for('auth.signup'))

        newUser = User(email=email, password=password, signupTime=datetime.utcnow(), admin=False, confirmed=False)

        db.session.add(newUser)
        db.session.commit()

        token = generateConfirmationToken(newUser.email)
        confirmUrl = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('auth/activate.html', confirmUrl=confirmUrl)
        sendEmail(newUser.email, "Please confirm your email", html)

        return redirect(url_for('auth.unconfirmed', email=email))

@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirmToken(token)
    except:
        flash('The confirmation link is invalid or has expired', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmationTime = datetime.utcnow()
        db.session.add(user)
        db.session.commit()

        flash('You have confirmed your account. Thanks! Please Login', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/unconfirmed/<email>')
def unconfirmed(email):
    user = User.query.filter_by(email=email).first_or_404()
    if user and not user.confirmed:
        return render_template('auth/unconfirmed.html', email=email)
    else:
        abort(404)

@auth_bp.route('/resend/<mail>')
def resend(mail):
    user = User.query.filter_by(email=mail).first_or_404()
    if user and not user.confirmed:
        token = generateConfirmationToken(mail)
        confirmUrl = url_for('auth.confirm_email', token=token, _external=True)
        html = render_template('auth/activate.html', confirmUrl=confirmUrl)
        subject = "Please confirm your email"
        sendEmail(mail, subject, html)
        flash('A new confirmation email has been sent', 'success')
        return redirect(url_for('auth.unconfirmed', email = mail))
    else:
        abort(404)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('general.home'))

def generateConfirmationToken(email):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    return serializer.dumps(email)

def sendEmail(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=config.MAIL_DEFAULT_SENDER)
    mail.send(msg)

def confirmToken(token, expiration=3600):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    try:
        email = serializer.loads(token, max_age=expiration)
    except:
        return False

    return email