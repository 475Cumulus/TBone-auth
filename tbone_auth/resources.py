#!/usr/bin/env python
# encoding: utf-8

import logging
from tbone.resources import ModelResource, Resource
from tbone.resources.http import *
from .models import User


logger = logging.getLogger(__file__)


class CreateUserResource(ModelResource):
    class Meta:
        object_class = User
        incoming_list = ['post']
        incoming_detail = []

    async def create(self, **kwargs):
        '''
        Corresponds to POST request without a resource identifier, inserting a document into the database
        '''
        try:
            # deserialize data from request params
            self.data.update(kwargs)
            # create model
            user = self._meta.object_class()
            await user.deserialize(self.data)
            # create document in DB
            await user.insert(db=self.db)
            # serialize userect for response
            return await user.serialize()
        except Exception as ex:
            logger.exception(ex)
            raise BadRequest(ex)



class SessionResource(Resource):
    class Meta:
        incoming_list = ['post']
        incoming_detail = ['delete']

    async def create(self, **kwargs):
        # authenticate user with provided credentials
        user = await authenticate(db=self.db, **self.data)
        if user is None:
            raise NotFound('No user was found with your credentials')
