#!/usr/bin/env python
# encoding: utf-8

from .auth import Auth

VERSION = (0, 1, 0, 0)

__short_version__ = '.'.join(map(str, VERSION[0:2]))
__version__ = ''.join(['.'.join(map(str, VERSION[0:4])), ''.join(VERSION[4:])])



