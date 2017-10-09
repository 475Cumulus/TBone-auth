#!/usr/bin/env python
# encoding: utf-8

import hashlib
import binascii
import datetime
import random
from pymongo import ASCENDING
from tbone.data.models import Model
from tbone.data.fields import *
from tbone.data.fields.mongo import ObjectIdField, DBRefField
from tbone.db.models import MongoCollectionMixin



class Group(Model, MongoCollectionMixin):
    _id = ObjectIdField(projection=None)
    name = StringField(primary_key=True)
    permissions = ListField(StringField)

    class Meta:
        namespace = 'account'
        name = 'groups'
        indices = [
            {
                'name': '_name',
                'fields': [('name', ASCENDING)],
                'unique': True
            }
        ]