#!/usr/bin/env python
# encoding: utf-8

import asyncio
import pytest
import datetime
from tbone.resources import Resource, http
from tbone.testing.resources import DummyResource
from tbone.testing.fixtures import *
from tbone.testing.clients import *
from tbone_auth.auth import authenticate
from tbone_auth.models import *
from tbone_auth.resources import (
    CreateUserResource as CreateUserResourceBase,
    SessionResource as SessionResourceBase,
    TokenAuthentication
)
from .base import *

USERNAME = 'rburg'
PASSWORD = 'channel4i$gr8'


class CreateUserResource(DummyResource, CreateUserResourceBase):
    # subclasssed from tbone-auth to add a webserver mixin
    pass


class SessionResource(DummyResource, SessionResourceBase):
    # subclasssed from tbone-auth to add a webserver mixin
    pass


async def create_user_and_activate(app):
    # create client
    url = '/api/{}/'.format(CreateUserResource.__name__)
    client = ResourceTestClient(app, CreateUserResource)
    # create user
    new_user = {
        'username': 'rburg',
        'first_name': 'Ron',
        'last_name': 'Burgundy',
        'password': 'channel4i$gr8'
    }
    response = await client.post(url, body=new_user)
    assert response.status == http.CREATED
    data = client.parse_response_data(response)
    assert 'username' in data
    assert 'first_name' in data
    assert 'last_name' in data
    # activate user
    user_obj = User({'username': 'rburg'})
    await user_obj.activate_user(app.db)


async def get_user_token(app):
    # create client
    url = '/api/{}/'.format(SessionResource.__name__)
    client = ResourceTestClient(app, SessionResource)
    # create session
    response = await client.post(url, body={'username': USERNAME, 'password': PASSWORD})
    assert response.status == http.CREATED
    data = client.parse_response_data(response)
    assert 'token' in data
    return data['token']


@pytest.mark.asyncio
async def test_create_new_user_and_authenticate(create_app, patch_datetime_utcnow):
    app = create_app
    # create user
    await create_user_and_activate(app)
    # authenticate user
    user = await authenticate(db=app.db, username='rburg', password='channel4i$gr8')
    assert isinstance(user, User)
    # Wait to allow the task spawned by authentiate to update the last login timestamp
    await asyncio.sleep(.2)
    same_user = await User.find_one(app.db, {'username': 'rburg'})
    assert same_user.last_login == datetime.datetime(1950, 1, 1, 0, 0, 0)


@pytest.mark.asyncio
async def test_user_login(create_app):
    app = create_app
    # create user
    await create_user_and_activate(app)
    # create client
    url = '/api/{}/'.format(SessionResource.__name__)
    client = ResourceTestClient(app, SessionResource)
    # fail to create session with wrong password
    response = await client.post(url, body={'username': USERNAME, 'password': PASSWORD + '4'})
    assert response.status == http.NOT_FOUND
    # create session
    response = await client.post(url, body={'username': USERNAME, 'password': PASSWORD})
    assert response.status == http.CREATED
    data = client.parse_response_data(response)
    assert 'token' in data


@pytest.mark.asyncio
async def test_resource_crud_with_authentication(create_app):

    class SomeResource(DummyResource, Resource):
        class Meta:
            authentication = TokenAuthentication()

    app = create_app
    # create user
    await create_user_and_activate(app)
    # create client
    url = '/api/{}/'.format(SomeResource.__name__)
    client = ResourceTestClient(app, SomeResource)
    # fail to make a request without token
    response = await client.get(url)
    assert response.status == http.UNAUTHORIZED
    # get user token
    token = await get_user_token(app)
    response = await client.get(url, headers={'Authorization': 'token {}'.format(token)})
    # expert not implemented
    assert response.status == http.METHOD_NOT_IMPLEMENTED
    response = await client.post(url, body={}, headers={'Authorization': 'token {}'.format(token)})
    # expert not implemented
    assert response.status == http.METHOD_NOT_IMPLEMENTED







