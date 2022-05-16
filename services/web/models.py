from app import db
from flask_login import UserMixin

class AuditDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(6), index=True)
    custom = db.Column(db.Boolean, nullable=False, default=False, index=True)
    status = db.Column(db.String(11), index=True)
    startTime = db.Column(db.DateTime, index=True)
    os = db.Column(db.String(7), index=True)
    filename = db.Column(db.String(50), index=True)
    packageId = db.Column(db.String(50), index=True)
    packageVersion = db.Column(db.String(15))
    packageCodeVersion = db.Column(db.String(15))
    time = db.Column(db.String(8), index=True)
    userId = db.Column(db.Integer, db.ForeignKey('users.id'))
    checks = db.relationship('CheckDB', backref='auditDB', lazy='dynamic')

    def __repr__(self):
        return 'AuditDB ' + str(self.id) + ' ' + self.filename

class CheckDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(20))
    name = db.Column(db.String(50))
    severity = db.Column(db.String(8))
    found = db.Column(db.String(3))
    proofs = db.Column(db.String)
    info = db.Column(db.String(400))
    auditDBId = db.Column(db.Integer, db.ForeignKey('auditDB.id'))

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    signupTime = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmationTime = db.Column(db.DateTime, nullable=True)
    audits = db.relationship('AuditDB', backref='user', lazy='dynamic')
