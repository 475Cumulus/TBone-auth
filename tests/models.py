#!/usr/bin/env python
# encoding: utf-8

from tbone.data.fields import *
from tbone.data.fields.mongo import ObjectIdField, DBRefField
from tbone.data.models import *
from tbone.db.models import MongoCollectionMixin
from tbone_auth.models import User


class TodoItem(Model, MongoCollectionMixin):
    _id = ObjectIdField(primary_key=True)
    user = DBRefField(User, required=True)
    state = IntegerField(default=0, choices=[0, 1, 2, 3, 4, 5])
    priority = IntegerField(default=0, choices=[0, 1, 2])
    text = StringField(required=True)
    due = DateTimeField()

