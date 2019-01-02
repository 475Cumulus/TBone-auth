#!/usr/bin/env python
# encoding: utf-8


import asyncio
import pytest
from pymongo.errors import DuplicateKeyError
from tbone.db.models import create_collection
from tbone.testing.fixtures import *
from tbone_auth.backends import AuthenticationBackend
from tbone_auth.models import *
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
async def test_create_multiple_users_with_email_address(create_app):
    app = create_app

    COUNT = 10
    futures = []
    for i in range(0, COUNT):
        user = User({'email': 'user{}@example.com'.format(i + 1)})
        user.set_password('pa$$word')
        futures.append(user.save(app.db))

    await asyncio.gather(*futures)

    cursor = User.get_cursor(app.db)
    users = await User.find(cursor)
    # verify all users were created and are unique
    usernames = set()  # set maintains uniqueness
    for u in users:
        assert isinstance(u, User)
        usernames.add(u.email)
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
    assert user.active is False
    with pytest.raises(RuntimeError):
        await app.auth.authenticate(userid=USERNAME, password=PASSWORD)

    # activate user
    await user.activate_user(app.db)
    assert user.active is True

    # successful authentication
    u = await app.auth.authenticate(userid=USERNAME, password=PASSWORD)
    assert isinstance(u, User)

    # fail to authenticate with wrong password
    with pytest.raises(RuntimeError) as ex:
        await app.auth.authenticate(userid=USERNAME, password='wrong_password')
    assert str(ex.value) == 'Incorrect password'


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

    # activate user
    await user.activate_user(app.db)
    assert user.active is True

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


@pytest.mark.asyncio
async def test_custom_user_model(create_app):
    # create a custom user class where the username is the primary key
    class CustomUser(User):
        _id = ObjectIdField(projection=False)
        username = StringField(primary_key=True)

    app = create_app
    app.auth.user_model = CustomUser

    user_data = {
        'username': USERNAME,
        'first_name': 'Ron',
        'last_name': 'Burgundy',
    }
    user = CustomUser(user_data)
    user.set_password(PASSWORD)
    await user.save(app.db)
    assert user._id
    assert user.pk == USERNAME

    # authentication should fail because user is not active
    assert user.active is False
    with pytest.raises(RuntimeError) as ex:
        await app.auth.authenticate(userid=USERNAME, password=PASSWORD)
    assert str(ex.value) == 'User not found'
    # activate user
    await user.activate_user(app.db)
    assert user.active is True

    # successful authentication
    u = await app.auth.authenticate(userid=USERNAME, password=PASSWORD)
    assert isinstance(u, CustomUser)

    # fail to authenticate with wrong password
    with pytest.raises(RuntimeError) as ex:
        await app.auth.authenticate(userid=USERNAME, password='wrong_password')
    assert str(ex.value) == 'Incorrect password'


@pytest.mark.asyncio
async def test_custom_authentication_backend(create_app):
    class FakeAuthenticationBackend(AuthenticationBackend):
        @classmethod
        async def authenticate(cls, app, **credentials):
            user_data = {
                'username': USERNAME,
                'first_name': 'Ron',
                'last_name': 'Burgundy',
            }
            user = User(user_data)
            user.set_password(PASSWORD)
            return user

    app = create_app
    app.auth.auth_backend = FakeAuthenticationBackend

    u = await app.auth.authenticate(userid=USERNAME, password=PASSWORD)
    assert isinstance(u, User)


@pytest.mark.asyncio
async def test_authenticate_user_with_additional_conditions(create_app):
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
    assert user.active is False
    with pytest.raises(RuntimeError):
        await app.auth.authenticate(userid=USERNAME, password=PASSWORD)

    # activate user
    await user.activate_user(app.db)
    assert user.active is True

    # successful authentication
    u = await app.auth.authenticate(userid=USERNAME, password=PASSWORD)
    assert isinstance(u, User)

    # fail to authenticate when we require superuser account
    with pytest.raises(RuntimeError):
        await app.auth.authenticate(userid=USERNAME, password=PASSWORD, superuser=True)

    await user.set_superuser(app.db, True)

    u = await app.auth.authenticate(userid=USERNAME, password=PASSWORD)
    assert isinstance(u, User)



