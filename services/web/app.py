from flask import Flask
import config
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from jinja2 import Markup
from flask_mail import Mail
from flask_login import LoginManager

class momentjs(object):
    def __init__(self, timestamp):
        self.timestamp = timestamp

    def render(self, format):
        return Markup("<script>\ndocument.write(moment(\"%s\").%s);\n</script>" % (self.timestamp.strftime("%Y-%m-%dT%H:%M:%S Z"), format))

    def format(self, fmt):
        return self.render("format(\"%s\")" % fmt)

app = Flask(__name__)
app.config.from_object("config.Config")
app.secret_key = config.SECRET_KEY
app.jinja_env.globals['momentjs'] = momentjs

login_manager = LoginManager()
login_manager.init_app(app)
socketio = SocketIO(app, message_queue=app.config["REDIS_URL"])
mail = Mail(app)
db = SQLAlchemy(app)

#if __name__ == '__main__':
#    socketio.run(app)

from info.info import info_bp
from general.general import general_bp
from checks.checks import checks_bp
from auth.auth import auth_bp
from admin.admin import admin_bp

app.register_blueprint(info_bp, url_prefix='/info')
app.register_blueprint(general_bp)
app.register_blueprint(checks_bp, url_prefix='/checks')
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix='/admin')


from models import User
@login_manager.user_loader
def load_user(userId):
    return User.query.filter(User.id == int(userId)).first()