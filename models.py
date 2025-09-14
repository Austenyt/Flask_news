from datetime import datetime

from peewee import *

db = SqliteDatabase('news.db')


class Base(Model):
    class Meta:
        database = db


class User(Base):
    email = CharField(unique=True)
    password_hash = CharField()


class News(Base):
    topic = CharField()
    text = CharField()
    created_on = DateTimeField(default=datetime.now)


db.connect()
db.create_tables((User, News))
