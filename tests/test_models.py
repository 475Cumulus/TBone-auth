#!/usr/bin/env python
# encoding: utf-8


import asyncio
import pytest
from pymongo.errors import DuplicateKeyError
from tbone.db.models import create_collection
from tbone.testing.fixtures import *
from tbone_auth.models import *
from tbone_auth.auth import authenticate
from .base import create_app


USERNAME = 'rburg'
PASSWORD = 'channel4i$gr8'

@pytest.mark.asyncio
async def test_create_user_with_unique_username_and_email(create_app):
    app = create_app
    user_data = {
        'username': USERNAME,
        'first_name': 'Ron',
        'last_name': 'Burgundy',
        'email': 'rburg@channel4.com'
    }
    user = User(user_data)
    user.set_password(PASSWORD)
    await user.save(app.db)
    assert user._id
    # fail to create a new user with same username
    with pytest.raises(DuplicateKeyError):
        user2 = User(user_data)
        user2.set_password(PASSWORD)
        await user2.save(app.db)

    # fail to create a new user with same email address
    with pytest.raises(DuplicateKeyError):
        n2 = dict()
        n2.update(user_data)
        n2['username'] = USERNAME + '2'
        user3 = User(n2)
        user3.set_password(PASSWORD)
        await user3.save(app.db)


@pytest.mark.asyncio
async def test_create_multiple_users_without_email_address(create_app):
    app = create_app

    COUNT = 10
    futures = []
    for i in range(0, COUNT):
        user = User({'username': 'user{}'.format(i + 1)})
        futures.append(user.save(app.db))

    await asyncio.gather(*futures)

    cursor = User.get_cursor(app.db)
    users = await User.find(cursor)
    # verify all users were created and are unique
    usernames = set()  # set maintains uniqueness
    for u in users:
        assert isinstance(u, User)
        usernames.add(u.username)
    assert len(usernames) == COUNT
    assert len(users) == COUNT


@pytest.mark.asyncio
async def test_authenticate_user(create_app):
    app = create_app
    user_data = {
        'username': USERNAME,
        'first_name': 'Ron',
        'last_name': 'Burgundy',
        'email': 'rburg@channel4.com'
    }
    user = User(user_data)
    user.set_password(PASSWORD)
    await user.save(app.db)
    assert user._id

    # authentication should fail because user is not active
    u = await authenticate(db=app.db, username=USERNAME, password=PASSWORD)
    assert u is None

    # activate user
    await user.activate_user(app.db)
    # successful authentication
    u = await authenticate(db=app.db, username=USERNAME, password=PASSWORD)
    assert isinstance(u, User)


@pytest.mark.asyncio
async def test_create_user_with_email_as_username(db):
    class EmailUser(User):
        username = StringField()
        email = EmailField(primary_key=True)

    await create_collection(db, EmailUser)
    assert EmailUser.primary_key == 'email'
    # create new user based on email address as unique key
    user_data = {
        'first_name': 'Ron',
        'last_name': 'Burgundy',
        'email': 'rburg@channel4.com'
    }
    user = EmailUser(user_data)
    user.set_password(PASSWORD)
    await user.insert(db)
    same_user = await EmailUser.find_one(db, {'email': 'rburg@channel4.com'})
    assert isinstance(same_user, User)
    assert same_user._id


@pytest.mark.asyncio
async def test_create_token_for_user(create_app):
    app = create_app
    # create user
    user_data = {
        'username': USERNAME,
        'first_name': 'Ron',
        'last_name': 'Burgundy',
        'email': 'rburg@channel4.com'
    }
    user = User(user_data)
    user.set_password(PASSWORD)
    await user.save(app.db)
    assert user._id
    # get or create token for user
    session = await Session.get_or_create(app.db, user)
    assert isinstance(session, Session)
    # get or create session for user
    session2 = await Session.get_or_create(app.db, user)
    assert isinstance(session2, Session)
    assert session.token == session.token
    # make sure there is only one session
    cursor = User.get_cursor(app.db)
    sessions = await Session.find(cursor)
    assert len(sessions) == 1






