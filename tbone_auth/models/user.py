#!/usr/bin/env python
# encoding: utf-8

import hashlib
import binascii
import datetime
import random
import uuid
from pymongo import ASCENDING
from pymongo.results import UpdateResult
from tbone.data.models import Model
from tbone.data.fields import *
from tbone.data.fields.mongo import ObjectIdField, DBRefField
from tbone.db.models import MongoCollectionMixin


SALT = 'rIxeK641CtwD2JgWYOm5fFpD0LW9m1'
TOKEN_EXPIRY = 604800  # one week


class Password(Model):
    '''
    Maintains password information.

    :param password:
        A string contained a hashed version of the password

    :param set_date:
        DateTime of the last password set

    :param old_passwords:
        A list of old passwords that were previously used.
        for cases when periodic password changing needs to be enforced
        and password repeats are not allowed
    '''
    password = StringField()
    set_date = DateTimeField()
    old_passwords = ListField(StringField, limit=5)


class User(Model, MongoCollectionMixin):
    '''
    Base class for user model.
    Implements a user model as a MongoDB collection
    Subclass this to extend your app's user model with additional data.
    '''
    _id = ObjectIdField(primary_key=True)
    username = StringField()
    email = EmailField(export_if_none=False)
    password = ModelField(Password, export_if_none=False, projection=None)  # this field is never serialized
    first_name = StringField()
    middle_name = StringField()
    last_name = StringField()
    last_login = DateTimeField(readonly=True)
    active = BooleanField(default=False, readonly=True)
    superuser = BooleanField(default=False, readonly=True)
    jti = StringField(readonly=True, projection=None)

    class Meta:
        namespace = 'account'
        name = 'users'
        indices = [
            {
                'name': '_username',
                'fields': [('username', ASCENDING)],
                'unique': True,
                'partialFilterExpression': {'username': {'$type': 'string'}}
            }, {
                'name': '_email',
                'fields': [('email', ASCENDING)],
                'unique': True,
                'partialFilterExpression': {'email': {'$type': 'string'}}
            }
        ]

    @serialize
    async def created(self):
        return self._id.generation_time.isoformat()

    def set_password(self, password):
        self.password = Password()
        self.password.password = self._hash(password)
        self.password.set_date = datetime.datetime.utcnow()

    def check_password(self, password):
        return self.password.password == self._hash(password)

    def _hash(self, s):
        return binascii.hexlify(hashlib.pbkdf2_hmac('sha256', str.encode(s), str.encode(SALT), 10000)).decode('utf-8')

    async def activate_user(self, db):
        ''' Activates the user by setting the active field to True and updating the storage '''
        db = db or self.db
        # use model's pk as query
        query = {self.primary_key: self.pk}
        # push review
        result = await db[self.get_collection_name()].update_one(
            filter=query,
            update={'$set': {'active': True}},
        )
        if isinstance(result, UpdateResult) and result.modified_count == 1:
            self.active = True
        return result

    async def set_superuser(self, db, status):
        ''' Sets the superuser status of a user in the database '''
        db = db or self.db
        # use model's pk as query
        query = {self.primary_key: self.pk}
        # push review
        result = await db[self.get_collection_name()].update_one(
            filter=query,
            update={'$set': {'superuser': status}},
        )
        if isinstance(result, UpdateResult) and result.modified_count == 1:
            self.active = True
        return result


    async def deserialize(self, data: dict):
        password = data.pop('password', None)
        await super(User, self).deserialize(data)

        if password:
            self.set_password(password)


class Session(Model, MongoCollectionMixin):
    _id = ObjectIdField(projection=None)
    created = DateTimeField(default=datetime.datetime.utcnow())
    token = StringField(primary_key=True)
    user = DBRefField(User, required=True)

    class Meta:
        namespace = 'account'
        name = 'sessions'
        indices = [
            {
                'name': '_token',
                'fields': [('token', ASCENDING)],
            }, {
                'name': '_user',
                'fields': [('user', ASCENDING)],
                'unique': True
            }, {
                'name': '_created',
                'fields': [('created', ASCENDING)],
                'expireAfterSeconds': TOKEN_EXPIRY
            }
        ]

    @classmethod
    async def get_or_create(cls, db, user: User):
        '''
        Find or create a token for given user.
        Do not use ``insert`` or ``create`` directly but rather this method.
        Token automatically expires after TOKEN_EXPIRE
        '''
        user_ref = DBRefField(User).to_python(user)
        token_data = await db[cls.get_collection_name()].find_one_and_update(
            filter={'user': user_ref},
            update={
                '$set': {'user': user_ref},
                '$setOnInsert': {
                    'token': uuid.uuid4().hex,
                    'created': datetime.datetime.utcnow()
                }
            },
            upsert=True,
            return_document=True
        )
        if token_data:
            return cls.create_model(token_data)
        return None


class UserAction(Model, MongoCollectionMixin):
    USER_ACTION_CHOICES = (
        (0, 'Unknown'),
        (1, 'Activate'),
        (2, 'Reset Password'),
        (2, 'Reset Passcode'),
        (4, 'Change Email Address'),
    )

    USER_ACTION_STATE_CHOICES = (
        (0, 'Active'),
        (1, 'Completed'),
        (1, 'Expired'),
    )

    _id = ObjectIdField(projection=None)
    key = StringField(primary_key=True)
    user = DBRefField(User, required=True)
    action = IntegerField(choices=[x for x, _ in USER_ACTION_CHOICES])
    state = IntegerField(default=0, choices=[x for x, _ in USER_ACTION_STATE_CHOICES])

    class Meta:
        name = 'user_actions'
        namespace = 'account'
        indices = [
            {
                'name': '_user_and_action',
                'fields': [('user', ASCENDING), ('action', ASCENDING)],
                'unique': True,
                # 'partialFilterExpression': {'action': {'$ne': 0}}  # unique if action is active
            }
        ]

    @classmethod
    def create_apikey(cls, username):
        salt = hashlib.sha1(str(random.random()).encode('utf-8')).hexdigest()[:5]
        return hashlib.sha1((salt + username).encode('utf-8')).hexdigest()
