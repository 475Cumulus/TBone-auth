#!/usr/bin/env python
# encoding: utf-8

import asyncio
from datetime import datetime
from collections import defaultdict
# from base.authentication import Authentication
from .models import User, Token


class AuthenticationBackend(object):
    '''
    Base class for authentication backends. Derived classes must implement:
    ``async def authenticate(self, **credentials)``
    '''
    def authenticate(**credentials):
        raise NotImplementedError()



class DatabaseAuthenticationBackend(AuthenticationBackend):
    ''' Authentication backend that uses MongoDB as the backend to store user credentials and authenticate against '''
    async def authenticate(self, **credentials):
        if 'db' not in credentials:
            raise ValueError('Failed to authenticate user. missing database handle')
        db = credentials.pop('db')
        username = credentials[User.primary_key]
        user = await User.find_one(db, {User.primary_key: username, 'active': True})
        if user:
            if user.check_password(credentials.get('password', None)):
                user.last_login = datetime.utcnow()
                asyncio.ensure_future(user.save(db))
                return user
        return None



async def authenticate(**credentials):
    '''
    Global authentication method.
    Authenticate user with credentials using a given backend
    '''
    backend = DatabaseAuthenticationBackend()
    return await backend.authenticate(**credentials)