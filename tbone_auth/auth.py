#!/usr/bin/env python
# encoding: utf-8

import datetime
import uuid
import jwt
import logging
from functools import wraps
from .models import User
from .backends import DatabaseAuthenticationBackend


logger = logging.getLogger(__file__)


SESSION_NAME = 'milkstrip-admin-session'
JWT_SECRET = '45j63lkjhg3492f3kjh25ps7'
TOKEN_EXPIRY_DAYS = 10


class Auth(object):
    '''
    Global Authentication Manager.
    An instance of this should be assigned to the globall App object of the project
    '''

    def __init__(self, app=None, user_model=None, auth_backend=None, no_auth_handler=None):
        self.app = None
        if app is not None:
            self.setup(app, user_model, auth_backend, no_auth_handler)

    def setup(self, app, user_model, auth_backend, no_auth_handler):
        ''' Setup with application's configuration. '''

        if self.app:
            raise RuntimeError('already initialized with an application')

        # assign the auth manager to the app
        setattr(app, 'auth', self)
        self.app = app
        self.user_model = user_model or User
        self.auth_backend = auth_backend or DatabaseAuthenticationBackend
        self.no_auth_handler = no_auth_handler or None

    async def authenticate(self, **credentials):
        '''
        Global authentication method.
        Authenticate user with credentials using a given backend
        '''
        if self.app is None:
            raise RuntimeError('Authentication manager not initialized')

        return await self.auth_backend.authenticate(self.app, **credentials)

    async def login_user(self, user, token=None):
        if self.app is None:
            raise RuntimeError('Authentication manager not initialized')

        return await self.auth_backend.login_user(self.app.db, user)

    def _create_jwt_token(self, user):
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
            'userid': str(user.pk),
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256', headers=headers)
        return {
            'jti': jti,
            'token': token.decode('utf-8')
        }

    def _get_user_from_jwt_token(self, token):
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            if 'userid' not in payload:
                raise RuntimeError('Invalid Token')
            return payload['userid']
        except (jwt.ExpiredSignatureError, jwt.DecodeError, RuntimeError):
            raise RuntimeError('Invalid Token')

    def create_user_token(self, user):
        return self._create_jwt_token(user)

    async def get_user_from_token(self, token):
        userid = self._get_user_from_jwt_token(token)
        return await self.user_model.find_one(self.app.db, {
            self.user_model.primary_key: User.primary_key_type(userid)
        })

    @classmethod
    def login_required(cls, no_auth_handler):
        ''' decorator for request handlers which require authentication '''
        def inner(handler):
            @wraps(handler)
            async def wrapped(request, *args, **kwargs):
                session = request.get(SESSION_NAME)
                if session:
                    try:
                        user = await request.app.auth.get_user_from_token(session)
                        if user is None:
                            raise Exception('No user was derived fron token')
                        request['user'] = user
                        return await handler(request, *args, **kwargs)
                    except Exception as ex:
                        logger.exception(ex)

                return await no_auth_handler(request)

            return wrapped
        return inner
