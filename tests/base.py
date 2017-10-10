#!/usr/bin/env python
# encoding: utf-8


import asyncio
import pytest
from tbone.db.models import create_collection
from tbone.testing.clients import App
from tbone_auth.models import *


@pytest.mark.asyncio
@pytest.fixture(scope='function')
async def create_app(db):
    ''' Helper fixture for loading the accounts.json fixture into the database '''
    app = App(db=db)

    # create collections and db indices
    futures = []
    for model in [User, UserAction, Session]:
        futures.append(create_collection(db, model))

    await asyncio.gather(*futures)
    return app


@pytest.fixture
def patch_datetime_utcnow(monkeypatch):
    ''' Fixture for monkeypatching the ``datetime.utcnow`` method to fake a different datetime '''
    class mockdatetime(datetime.datetime):
        @classmethod
        def utcnow(cls):
            return datetime.datetime(1950, 1, 1, 0, 0, 0)

    monkeypatch.setattr(datetime, 'datetime', mockdatetime)
