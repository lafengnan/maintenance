#!/usr/bin/env python
# coding=utf-8

import os
import errno
import hashlib
import sqlite3
import functools
from time import time
from datetime import datetime

import logging
from tempfile import mkstemp


class DBConnectionError(sqlite3.DatabaseError):
    def __init__(self, path, msg, timeout=0):
        self.path = path
        self.msg = msg 
        self.timeout = timeout

    def __str__(self):
        return 'DB Connection Error (%s %s):\n%s' % (self.path,
                self.timeout, self.msg)

class DBAlreadyExists(sqlite3.DatabaseError):
    def __init__(self, path):
        self.path = path

    def __str__(self):
        return 'DB %s already exists' % self.path

def mkdirs(path):
    if not os.path.isdir(path):
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno != errno.EEXIST or not os.path.isdir(path):
                raise

def get_db_connection(path, timeout=30):
    """
    Return a Sqlite3 database connection
    @path: path to DB
    @timeout: timeout for connection
    @returns: DB connection object
    """
    try:
        connect_time = time()
        conn = sqlite3.connect(path, check_same_thread=False, timeout=timeout)
        if path != ':memory:':
            stat = os.stat(path)
            if stat.st_size == 0 and stat.st_ctime >= connect_time:
                os.ulink(path)
                raise DBConnectionError(path, 'is Invalid DB file') 

        conn.row_factory = sqlite3.Row
        conn.text_factory = str
        return conn
    except sqlite3.DatabaseError:
        import traceback
        raise DBConnectionError(path, traceback.format_exc(), 
                               timeout=timeout)


class Cache(object):
    """
    Cache is a deco class for simple cache usage
    """
    def __init__(self):
        super(Cache, self).__init__()
        self.cache = dict()

    def __call__(self, f):
        @functools.wraps(f)
        def wrapper(inst, user, passwd):
            if user not in self.cache:
                self.cache[user] = f(inst, user, passwd)
            return self.cache.get(user)
        return wrapper

    def ishit(self, user, token):
        return token == self.cache.get(user)

class DBBroker(object):
    """
    DBBroker is broker class of sqlite3 connection
    @db the db to connect, should be defined in devops settings
    """
    def __init__(self, db_file, timeout=30, logger=None):
        super(DBBroker, self).__init__()
        self.conn = None
        self.db_file = db_file
        self.db_dir = os.path.dirname(db_file)
        self.logger = logger or logging.getLogger(__name__)
        self.timeout = timeout

    def __str__(self):
        return self.db_file

    def __enter__(self):
        try:
            self.initialize()
        except DBAlreadyExists:
            pass
        return self

    def __exit__(self, exc_t, exc_v, tb):
        self.conn.close()

    def execute_sql(self, query):
        return self.conn.cursor().execute(query)

    def commit(self):
        self.conn.commit()

    def initialize(self):
        """
        Create the database
        """
        mkdirs(self.db_dir) 
        fd, tmp_db_file = mkstemp(suffix='.tmp', dir=self.db_dir)
        os.close(fd)
        conn = sqlite3.connect(tmp_db_file, 
                               check_same_thread=False,
                               timeout=0)
        sql = '''
        CREATE TABLE auth
        (id INTEGER primary key AUTOINCREMENT,
        user varchar UNIQUE,
        token text,
        expires INTEGER)
        '''
        conn.cursor().execute(sql)
        conn.commit()
        if tmp_db_file:
            conn.close()
            with open(tmp_db_file, 'r+b') as f:
                os.fsync(f.fileno())
            if not os.path.exists(self.db_file):
                os.rename(tmp_db_file, self.db_file)
            else:
                os.remove(tmp_db_file)
            self.conn = get_db_connection(self.db_file, self.timeout)
        else:
            self.conn = conn

    def is_table_exist(self, table):
        if table and len(table) > 0:
            query = '''
            SELECT name FROM sqlite_master WHERE type='table' AND name = '%s'
            ''' % table
            return True if self.execute_sql(query).fetchone() else False
        else:
            raise Exception("table None or table name is null")

class MaintenanceSecheduler(DBBroker):
    """
    MaintenanceSecheduler is used for maintenance notfication event table
    manifections. It is derived from Sqlite3Conn to reuse the lowlevle
    functions
    """
    def __init__(self, service_list, when, duaration):
        create_table = '''
        CREATE TABLE maintenance_scheduler
        (id INTEGER PRIMARY KEY AUTOINCREMENT, service text, when Date, duration INTEGER)
        '''
        self.execute_sql(create_table)
        self.commit()

    def create_event(self, services, when, duration):
        pass

    def get_event(self, id):
        pass

class SimpleAuth(object):
    """
    Token is respect for simple access token.The generation is determined
    by Hash alogorithm. Currently we would like to use MD5 alogorithm to
    generate the access token. It could be configured if needed in future.
    @algorithm the hash algorithm to use, default algorithm is md5
    @expires life of a token, default value is 86400 seconds(equals to 24h)
    """
    def __init__(self, algorithm='md5', expires=86400):
        super(SimpleAuth, self).__init__()
        self.db_file = '/Users/lafengnan/codes/Github/maintenance/nf.db' # for test, will get from settings
        self.table = 'auth'
        self.token_life = expires
        self.db = DBBroker(self.db_file)
        self.db.initialize()
        self.hash = getattr(hashlib, algorithm.lower(), hashlib.md5)

    def get_token(self, user, passwd):
        def _validate_user_and_passwd():
            pass
        _validate_user_and_passwd()

        m = self.hash()
        m.update(user + passwd + \
                 datetime.now().strftime('%d/%m/%y: %H:%M:%S'))
        token  = m.hexdigest()
        expires = long(time() + self.token_life)

        def _write_to_db(token, expires):
            update = '''
            (SELECT id from %s WHERE user = '%s')
            ''' % (self.table, user)
            sql = '''
            INSERT or REPLACE INTO %s VALUES(%s, '%s', '%s', %d)
            ''' % (self.table, update, user, token, expires)
            self.db.execute_sql(sql)
            self.db.commit()

        _write_to_db(token, expires)

        return token

    def validate_token(self, token):
        def _get_token_info_from_db(token):
            q = '''
            SELECT token, expires from %s WHERE token = '%s'
            ''' % (self.table, token)
            r = self.db.execute_sql(q).fetchone()
            if r:
                return r
            raise Exception("token: %s is invalid" % token)
        try:
            _, e = _get_token_info_from_db(token)
            return e - long(time()) > 0
        except Exception:
            raise
