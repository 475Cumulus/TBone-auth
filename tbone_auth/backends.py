#!/usr/bin/env python
# encoding: utf-8

import asyncio
import datetime


class AuthenticationBackend(object):
    '''
    Base class for authentication backends. Derived classes must implement:
    ``async def authenticate(self, **credentials)``
    '''
    @classmethod
    async def authenticate(cls, app, **credentials):
        raise NotImplementedError()

    @classmethod
    async def login_user(cls, app, user, token=None):
        raise NotImplementedError()


class DatabaseAuthenticationBackend(AuthenticationBackend):
    '''
    Authentication backend that uses MongoDB as the backend to store user credentials and authenticate against
    '''
    @classmethod
    async def authenticate(cls, app, **credentials):
        # get the primary identifying field - listed in the user model
        user_model = app.auth.user_model
        if 'userid' not in credentials:
            raise ValueError('User id not provided')
        user_id = credentials['userid']
        if user_id is None or user_id == '':
            raise ValueError('User id not provided')
        user = await user_model.find_one(app.db, {
            '$or': [{'username': user_id}, {'email': user_id}],
            'active': True
        })
        if user:
            if user.check_password(credentials.get('password', None)) is False:
                raise RuntimeError('Incorrect password')
        else:
            raise RuntimeError('User not found')
        return user

    @classmethod
    async def login_user(cls, db, user, jti=None):
        # update user last login timestamp to now
        user.last_login = datetime.datetime.utcnow()
        if jti:
            user.jti = jti
        asyncio.ensure_future(user.update(db))


