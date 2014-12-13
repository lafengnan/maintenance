#!/usr/bin/env python
# coding=utf-8

import os
import errno
import hashlib
import sqlite3
import functools
from time import time
from datetime import datetime
from contextlib import contextmanager

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

class AuthError(Exception):
    def __init__(self, token):
        self.token = token

class InvalidTokenError(AuthError):
    def __str__(self):
        return "Invalid Token: %s" % self.token 

class ExpiredTokenError(AuthError):
    def __str__(self):
        return "Expired Token: %s" % self.token

class Cache(object):
    """
    Cache is a deco class for token cache usage
    """
    cache = {}
    def __init__(self):
        super(Cache, self).__init__()

    def __call__(self, f):
        @functools.wraps(f)
        def wrapper(inst, user, passwd):
            if user not in Cache.cache:
                Cache.cache[user] = f(inst, user, passwd)
                self.dump()
            return Cache.cache.get(user)
        return wrapper

    def ishit(self, user, token):
        return token == self.cache.get(user)

    def dump(self):
        #TODO
        for k, v in Cache.cache.items():
            print k, ": ", v

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
        raise DBConnectionError(path, 
                                traceback.format_exc(), 
                                timeout=timeout)

class DBBroker(object):
    """
    DBBroker is top broker class of sqlite3 connection, it should not 
    be used directly. Any new table to create, please inherit it for usage.
    @db_file: the db file to connect, should be defined in devops settings.
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
        if not self.conn:
            self.initialize()
        return self

    def __exit__(self, exc_t, exc_v, tb):
        self.conn.close()

    def execute_sql(self, query):
        return self.conn.cursor().execute(query)

    def commit(self):
        self.conn.commit()
    
    def is_table_existing(self, table):
        query = '''
        SELECT name FROM sqlite_master WHERE type='table' AND name = '%s'
        ''' % table
        return True if self.execute_sql(query).fetchone() else False

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
        self._initialize(conn)
        conn.commit()
        if tmp_db_file: 
            conn.close()
            if not os.path.exists(self.db_file):
                with open(tmp_db_file, 'r+b') as f:
                    os.fsync(f.fileno())
                os.rename(tmp_db_file, self.db_file)
            else:
                os.remove(tmp_db_file)
            self.conn = get_db_connection(self.db_file, self.timeout)
        else:
            self.conn = conn

    @property
    @contextmanager
    def broker(self):
        """
        Enable 'with...as' statement
        """
        if not self.conn:
            if self.db_file != ':memory:' and os.path.exists(self.db_file):
                try:
                    self.conn = get_db_connection(self.db_file, self.timeout)
                except (sqlite3.DatabaseError, DBConnectionError):
                    raise
            else:
                raise DBConnectionError(self.db_file, "DB does not exist!")
        try:
            yield self
        finally:
            self.conn.close()

    def backup(self, dst_path):
        pass #TODO

    def restore(self, src_path):
        pass #TODO

class AuthBroker(DBBroker):
    """
    AuthBroker is used for authentication table. Derived from DBBroker.
    AuthBroker will only be responsible for auth table to store tokens.
    """
    db_type = 'auth'

    def _initialize(self, conn):
        self.create_auth_table(conn)
    
    def create_auth_table(self, conn):
        """
        Create the auth table for authentication
        @conn: DB connection object
        """
        sql = '''
        CREATE TABLE auth
        (id INTEGER primary key AUTOINCREMENT,
        user varchar UNIQUE,
        token text,
        expires INTEGER)
        '''
        conn.cursor().execute(sql)

class MaintenanceEventBroker(DBBroker):
    """
    MaintenanceEventBroker is used for maintenance notfication event table
    manifections. It is derived from DBBroker to reuse low levle functions.
    """
    db_type = 'maintenance_event'

    def _initialize(self, conn):
        self.create_maintenance_event_table(conn)

    def create_maintenance_event_table(self, conn):
        sql = '''
        CREATE TABLE maintenance_event
        (id INTEGER PRIMARY KEY AUTOINCREMENT, 
        service text, 
        when Date, 
        duration INTEGER)
        '''
        conn.cursor().execute(sql)

    def create_event(self, services, when, duration):
        pass #TODO

    def get_event(self, id):
        pass #TODO

class SimpleAuth(object):
    """
    Token is respect for simple access token.The generation is determined
    by Hash alogorithm. Currently we would like to use MD5 alogorithm to
    generate the access token. It could be configured if needed in future.
    @algorithm: the hash algorithm to use, default algorithm is md5
    @expires: life of a token, default value is 86400 seconds(equals to 24h)
    """
    def __init__(self, algorithm='md5', expires=86400):
        super(SimpleAuth, self).__init__()
        self.db_file = '/Users/lafengnan/codes/Github/maintenance/nf.db' # for test, will get from settings
        self.token_life = expires
        self._get_broker = lambda : AuthBroker(self.db_file)
        self.hash = getattr(hashlib, algorithm.lower(), hashlib.md5)

    @Cache()
    def get_token(self, user, passwd):
        def _validate_user_and_passwd():
            pass #TODO
        
        try:
            _validate_user_and_passwd()
        except Exception:
            raise

        m = self.hash()
        m.update(user + passwd + \
                 datetime.now().strftime('%d/%m/%y: %H:%M:%S'))
        token  = m.hexdigest()
        expires = long(time() + self.token_life)
        broker = self._get_broker()
        def _write_to_db():
            update = '''
            (SELECT id FROM auth WHERE user = '%s')
            ''' % user
            sql = '''
            INSERT or REPLACE INTO auth VALUES(%s, '%s', '%s', %d)
            ''' % (update, user, token, expires)
            broker.execute_sql(sql)
            broker.commit()

        try:
            with broker.broker as broker:
                _write_to_db()
        except DBConnectionError: # DB does not exist
            broker.initialize()
            _write_to_db()

        return token

    def validate_token(self, token):
        def _get_token_info_from_db():
            q = '''
            SELECT token, expires FROM auth WHERE token = '%s'
            ''' % token
            # If token is valid, return(token, expires)
            # If token is invalid, return None
            return broker.execute_sql(q).fetchone()

        broker = self._get_broker()
        try:
            with broker.broker as broker:
                info = _get_token_info_from_db()
                if not info:
                    raise InvalidTokenError(token)
                elif info['expires'] - long(time()) <= 0:
                    # Remove it from cache if it has been cached
                    for u in Cache.cache:
                        if Cache.cache[u] == info['token']:
                            del Cache.cache[u]
                            break
                    raise ExpiredTokenError(token)
                else:
                    return "valid"
        except DBConnectionError:
            raise
