#!/usr/bin/env python
# encoding: utf-8

import asyncio
import pytest
from tbone.db.models import create_collection
from tbone.resources import http
from tbone.testing.resources import DummyResource
from tbone.testing.fixtures import *
from tbone.testing.clients import *
from tbone_auth.auth import authenticate
from tbone_auth.models import *
from tbone_auth.resources import CreateUserResource as CreateUserResourceBase


class CreateUserResource(DummyResource, CreateUserResourceBase):
    pass


@pytest.mark.asyncio
@pytest.fixture(scope='function')
async def create_app(db):
    ''' Helper fixture for loading the accounts.json fixture into the database '''
    app = App(db=db)

    # create collections and db indices
    futures = []
    futures.append(create_collection(db, User))
    futures.append(create_collection(db, Token))

    await asyncio.gather(*futures)

    return app


@pytest.mark.asyncio
async def test_create_new_user_and_authenticate(create_app):
    app = create_app
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
    # authenticate user
    user = await authenticate(db=app.db, username='rburg', password='channel4i$gr8')
    assert isinstance(user, User)
