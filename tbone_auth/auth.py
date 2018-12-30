#!/usr/bin/env python
# encoding: utf-8

import asyncio
import datetime
from .models import User


class AuthenticationBackend(object):
    '''
    Base class for authentication backends. Derived classes must implement:
    ``async def authenticate(self, **credentials)``
    '''
    def authenticate(**credentials):
        raise NotImplementedError()


class DatabaseAuthenticationBackend(AuthenticationBackend):
    '''
    Authentication backend that uses MongoDB as the backend to store user credentials and authenticate against
    '''
    @classmethod
    async def authenticate(cls, **credentials):
        if 'db' not in credentials:
            raise ValueError('Failed to authenticate user. missing database handle')
        db = credentials.pop('db')
        # get the primary identifying field - can be username, email or phone number
        user_id = credentials[User.primary_key]
        # user = await User.find_one(db, {User.primary_key: user_id, 'active': True})
        user = await User.find_one(db, {'$or': [{'username': user_id}, {'email': user_id}], 'active': True})
        if user:
            if user.check_password(credentials.get('password', None)):
                # authentication was established, update last login timestamp
                user.last_login = datetime.datetime.utcnow()
                asyncio.ensure_future(user.update(db))
                return user
        return None


async def authenticate(**credentials):
    '''
    Global authentication method.
    Authenticate user with credentials using a given backend
    '''
    return await DatabaseAuthenticationBackend.authenticate(**credentials)
