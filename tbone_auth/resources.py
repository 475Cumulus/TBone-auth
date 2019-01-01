#!/usr/bin/env python
# encoding: utf-8

import logging
import asyncio
from tbone.resources import Resource, ModelResource
from tbone.resources.verbs import *
from tbone.resources.authentication import NoAuthentication
from .models import User, Session


logger = logging.getLogger(__file__)

BEARER = 'token'
AUTHORIZATION_KEY = 'Authorization'


class TokenAuthentication(NoAuthentication):
    '''
    Authentication for resources, based on JWT tokens
    '''

    def extract_credentials(self, request):
        if request.headers.get(AUTHORIZATION_KEY) and request.headers[AUTHORIZATION_KEY].lower().startswith('{} '.format(BEARER)):
            (auth_type, data) = request.headers[AUTHORIZATION_KEY].split()
            if auth_type.lower() != BEARER:
                raise ValueError('Incorrect authorization header')
            return data
        return None

    async def is_authenticated(self, request):
        token = self.extract_credentials(request)
        if token:
            try:
                user = await request.app.auth.get_user_from_token(token)
                if user:
                    request['user'] = user
                    return True
            except Exception as ex:
                raise BadRequest(ex)

        return False


class CreateUserResource(ModelResource):
    class Meta:
        object_class = User
        incoming_list = ['post']
        incoming_detail = []

    async def create(self, **kwargs):
        try:
            # deserialize data from request params
            self.data.update(kwargs)
            # create model
            user = self._meta.object_class()
            await user.deserialize(self.data)
            # create document in DB
            await user.insert(db=self.db)
            # serialize user for response
            return await user.serialize()
        except Exception as ex:
            logger.exception(ex)
            raise BadRequest(ex)


class DatabaseSessionResource(ModelResource):
    class Meta:
        object_class = Session
        incoming_list = ['post']
        incoming_detail = ['get', 'delete']
        add_resource_uri = False

    async def create(self, **kwargs):
        # authenticate user with provided credentials
        try:
            user = await self.request.app.auth.authenticate(**self.data)
        except Exception as ex:
            raise BadRequest(str(ex))
        token = await Session.get_or_create(self.db, user)
        if token:
            data = await token.serialize()
            data['user'] = await user.serialize()
            return data
        raise HttpError('Failed to create token')

    async def delete(self, **kwargs):
        pk = self.pk_type(kwargs['pk'])
        result = await self._meta.object_class.delete_entries(self.db, {self.pk: pk})
        if result.acknowledged:
            if result.deleted_count == 0:
                raise NotFound()
        else:
            raise BadRequest('Failed to delete object')

    # async def detail(self, **kwargs):

    #     pk = self.pk_type(kwargs.get('pk'))
    #     obj = await self._meta.object_class.find_one(self.db, {self.pk: pk})
    #     if obj:
    #         # this is a temporary hack until we figure out how to use dereference efficiently
    #         obj_data = await obj.serialize()
    #         user = await User.find_one(self.db, {'_id': obj.user.id})
    #         obj_data['user'] = await user.serialize()
    #         return obj_data
    #     raise NotFound('Session was not found'.format(self.pk, str(pk)))


class JWTSessionResource(Resource):
    class Meta:
        incoming_list = ['post']
        add_resource_uri = False

    async def create(self, **kwargs):
        # authenticate user with provided credentials
        try:
            user = await self.request.app.auth.authenticate(**self.data)
        except Exception as ex:
            raise BadRequest(str(ex))
        # create user token
        jwt_data = self.request.app.auth.create_user_token(user)
        # update user object with the new jti - used to revoke token if needed
        asyncio.ensure_future(User.modify(self.db, key=user.pk, data={'jti': jwt_data['jti']}))

        return {
            'token': jwt_data['token'],
            'user': await user.serialize()
        }



