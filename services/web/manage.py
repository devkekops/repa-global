from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from app import app
from datetime import datetime
from app import db
from models import User
from flask.cli import FlaskGroup
import os
import redis
from rq import Connection, Worker

migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)

cli = FlaskGroup(app)

@cli.command("create_db")
def create_db():
    db.drop_all()
    db.create_all()
    db.session.commit()

@cli.command("drop_db")
def drop_db():
    db.drop_all()

@cli.command("create_admin")
def create_admin():
    db.session.add(User(
        email="ad@min.com",
        password="admin",
        signupTime=datetime.utcnow(),
        admin=True,
        confirmed=True,
        confirmationTime=datetime.utcnow())
    )
    db.session.commit()

@cli.command("create_upload_folder")
def create_upload_folder():
    os.mkdir("repaUploadFiles")

@cli.command("run_worker")
def run_worker():
    redis_url = app.config["REDIS_URL"]
    redis_connection = redis.from_url(redis_url)
    with Connection(redis_connection):
        worker = Worker(app.config["QUEUES"])
        worker.work()

if __name__ == '__main__':
    cli()