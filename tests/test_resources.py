#!/usr/bin/env python
# encoding: utf-8

import asyncio
import pytest
import datetime
from tbone.resources import verbs
from tbone.db.models import create_collection
from tbone.testing.fixtures import *
from tbone.testing.clients import *
from tbone_auth import Auth
from tbone_auth.models import *
from tbone_auth.resources import (
    CreateUserResource, DatabaseSessionResource, JWTSessionResource
)
from .base import *
from .models import TodoItem
from .resources import TodoItemResource

USERNAME = 'rburg'
PASSWORD = 'channel4i$gr8'
USER_COUNT = 2
TODO_COUNT = 4


async def create_user_and_activate(app):
    # create client
    url = '/api/{}/'.format(CreateUserResource.__name__)
    client = ResourceTestClient(app, CreateUserResource)
    # create user
    user_data = {
        'username': 'rburg',
        'first_name': 'Ron',
        'last_name': 'Burgundy',
        'password': 'channel4i$gr8'
    }
    response = await client.post(url, body=user_data)
    assert response.status == verbs.CREATED
    data = client.parse_response_data(response)
    assert 'username' in data
    assert 'first_name' in data
    assert 'last_name' in data
    # activate user
    user = await User.find_one(db=app.db, query={'username': 'rburg'})
    assert isinstance(user, User)
    await user.activate_user(app.db)
    assert user.active is True


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
@pytest.fixture(scope='function')
async def create_todo_items(db):
    app = App(db=db)  # create collection in db and optional indices
    Auth(app)
    await create_collection(db, TodoItem)
    # create some users
    for i in range(USER_COUNT):
        user = User({'username': 'user%d' % i})
        user.set_password(PASSWORD)
        await user.save(db)
        assert user._id
        await user.activate_user(db)
        assert user.active is True
        # insert todo items for this user
        futures = []
        for j in range(TODO_COUNT):
            todo = TodoItem({'user': user, 'text': 'todo item %d' % j})
            futures.append(todo.save(db))
        await asyncio.gather(*futures)
    return app


@pytest.mark.asyncio
async def test_create_new_user_and_authenticate(create_app, patch_datetime_utcnow):
    app = create_app
    # create user
    await create_user_and_activate(app)
    # authenticate user
    user = await app.auth.authenticate(userid='rburg', password='channel4i$gr8')
    assert isinstance(user, User)
    # log user in - this updates the last login timestamp
    await app.auth.login_user(user)
    # Wait to allow the task spawned by authentiate to update the last login timestamp
    await asyncio.sleep(.2)
    same_user = await User.find_one(app.db, query={'username': 'rburg'})
    # the last login datetime was patched and mocked to set as 1/1/1950
    assert same_user.last_login == datetime.datetime(1950, 1, 1, 0, 0, 0)


@pytest.mark.asyncio
async def test_user_login_with_database_session(create_app):
    app = create_app
    # create user
    await create_user_and_activate(app)

    # create client
    url = '/api/{}/'.format(DatabaseSessionResource.__name__)
    client = ResourceTestClient(app, DatabaseSessionResource)

    # fail to create session with wrong password
    response = await client.post(url, body={'userid': USERNAME, 'password': PASSWORD + '4'})
    assert response.status == verbs.BAD_REQUEST

    # create session
    response = await client.post(url, body={'userid': USERNAME, 'password': PASSWORD})
    assert response.status == verbs.CREATED
    data = client.parse_response_data(response)
    assert 'token' in data
    assert 'user' in data


@pytest.mark.asyncio
async def test_user_login_with_jwt_session(create_app):
    app = create_app
    # create user
    await create_user_and_activate(app)

    # create client
    url = '/api/{}/'.format(JWTSessionResource.__name__)
    client = ResourceTestClient(app, JWTSessionResource)

    # fail to create session with wrong password
    response = await client.post(url, body={'userid': USERNAME, 'password': PASSWORD + '4'})
    assert response.status == verbs.BAD_REQUEST

    # create session
    response = await client.post(url, body={'userid': USERNAME, 'password': PASSWORD})
    assert response.status == verbs.CREATED
    data = client.parse_response_data(response)
    assert 'token' in data
    assert 'user' in data


@pytest.mark.asyncio
async def test_resource_crud_with_authentication(create_todo_items):
    app = create_todo_items

    # create client
    url = '/api/{}/'.format(JWTSessionResource.__name__)
    client = ResourceTestClient(app, JWTSessionResource)

    # create session
    response = await client.post(url, body={'userid': 'user1', 'password': PASSWORD})
    assert response.status == verbs.CREATED
    data = client.parse_response_data(response)
    assert 'token' in data
    assert 'user' in data
    user_token = data['token']

    url = '/api/{}/'.format(TodoItemResource.__name__)
    client = ResourceTestClient(app, TodoItemResource)

    # fail to make API calls without authorization header
    response = await client.get(url)
    assert response.status == verbs.UNAUTHORIZED

    # fail to make API calls with invalid token
    response = await client.get(url, headers={'Authorization': 'token {}'.format('bad-token')})
    assert response.status == verbs.BAD_REQUEST

    # get all user todo items
    response = await client.get(url, headers={'Authorization': 'token {}'.format(user_token)})
    assert response.status == verbs.OK
    data = client.parse_response_data(response)
    # the total count of todo items per user should be TODO_COUNT
    assert data['meta']['total_count'] == TODO_COUNT

    # class SomeResource(DummyResource, Resource):
    #     class Meta:
    #         authentication = TokenAuthentication()

    # app = create_app
    # # create user
    # await create_user_and_activate(app)
    # # create client
    # url = '/api/{}/'.format(SomeResource.__name__)
    # client = ResourceTestClient(app, SomeResource)
    # # fail to make a request without token
    # response = await client.get(url)
    # assert response.status == http.UNAUTHORIZED
    # # get user token
    # token = await get_user_token(app)
    # response = await client.get(url, headers={'Authorization': 'token {}'.format(token)})
    # # expert not implemented
    # assert response.status == http.METHOD_NOT_IMPLEMENTED
    # response = await client.post(url, body={}, headers={'Authorization': 'token {}'.format(token)})
    # # expert not implemented
    # assert response.status == http.METHOD_NOT_IMPLEMENTED
