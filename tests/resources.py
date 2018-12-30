#!/usr/bin/env python
# encoding: utf-8

from bson import ObjectId
from tbone.resources.mongo import *
from tbone_auth.resources import JWTAuthentication
from .models import TodoItem


class TodoItemResource(MongoResource):
    class Meta:
        object_class = TodoItem
        authentication = JWTAuthentication()

    async def list(self, **kwargs):
        kwargs['user'] = self.request.user
        return await super(TodoItemResource, self).list(**kwargs)
