#!/usr/bin/env python
# encoding: utf-8

import logging
import datetime
import uuid
import jwt
import asyncio
from tbone.resources import ModelResource
from tbone.resources.http import *
from tbone.resources.authentication import NoAuthentication
from .auth import authenticate
from .models import User, Session


logger = logging.getLogger(__file__)

JWT_SECRET = '45j63lkjhg3492f3kjh25ps7'
TOKEN_EXPIRY_DAYS = 10
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
                payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                userid = payload['userid']
                request.user = await User.find_one(request.app.db, {User.primary_key: userid})
                return True
            except jwt.ExpiredSignatureError:
                return False

        return False


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


class SessionResource(ModelResource):
    class Meta:
        object_class = Session
        incoming_list = ['post']
        incoming_detail = ['get', 'delete']
        add_resource_uri = False

    async def create_old(self, **kwargs):
        # authenticate user with provided credentials
        user = await authenticate(db=self.db, **self.data)
        if user is None:
            raise NotFound('No user was found with your credentials')
        token = await Session.get_or_create(self.db, user)
        if token:
            data = await token.serialize()
            data['user'] = await user.serialize()
            return data
        raise HttpError('Failed to create token')

    async def create(self, **kwargs):
        # authenticate user with provided credentials
        user = await authenticate(db=self.db, **self.data)
        if user is None:
            raise NotFound('No user was found with your credentials')
        # create JWT token
        jti = uuid.uuid4().hex
        headers = {
            'alg': 'HS256',
            'typ': 'JWT'
        }
        payload = {
            'nbf': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_EXPIRY_DAYS),
            'jti': jti,
            'userid': user.pk,

        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256', headers=headers)
        # update user object with the new jti - used to revoke token
        asyncio.ensure_future(User.modify(self.db, key=user.pk, data={'jti': jti}))
        return {
            'token': token.decode('utf-8')
        }

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

    # async def delete(self, **kwargs):
    #     pk = self.pk_type(kwargs['pk'])
    #     result = await self._meta.object_class.delete_entries(self.db, {self.pk: pk})
    #     if result.acknowledged:
    #         if result.deleted_count == 0:
    #             raise NotFound()
    #     else:
    #         raise BadRequest('Failed to delete object')



