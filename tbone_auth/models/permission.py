#!/usr/bin/env python
# encoding: utf-8


from pymongo import ASCENDING
from tbone.data.models import Model
from tbone.data.fields import *
from tbone.data.fields.mongo import ObjectIdField
from tbone.db.models import MongoCollectionMixin


class Permission(Model, MongoCollectionMixin):
    _id = ObjectIdField(projection=None)
    slug = StringField(primary_key=True)
    description = StringField()

    class Meta:
        namespace = 'account'
        name = 'permissions'
        indices = [
            {
                'name': '_slug',
                'fields': [('slug', ASCENDING)],
                'unique': True
            }
        ]
