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
import ConfigParser
from tempfile import mkstemp

LOGGING_FORMAT = '%(asctime)s %(levelname)s user_id:%(user_id)s %(message)s'
SYSLOG_LOGGING_FORMAT = '%(levelname)s user_id:%(user_id)s %(message)s'
CONF_PATH = '/etc/polaris/maintenance.cfg'

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

class InvalidIDError(Exception):
            def __init__(self, e_id):
                self.id = e_id

            def __str__(self):
                return "Invalid id: %d" % self.id

class AuthError(Exception):
    def __init__(self, user, token):
        self.user = user
        self.token = token

class InvalidTokenError(AuthError):
    def __str__(self):
        return "invalid token: %s" % self.token

class ExpiredTokenError(AuthError):
    def __str__(self):
        return "user: %s --- expired token: %s" % (self.user, self.token)

class Cache(object):
    """
    Cache is a deco class for token cache usage
    """
    cache = dict()
    def __init__(self):
        super(Cache, self).__init__()

    def __call__(self, f):
        @functools.wraps(f)
        def wrapper(inst, user, passwd):
            if user not in Cache.cache:
                Cache.cache[user] = f(inst, user, passwd)
            return Cache.cache.get(user)
        return wrapper

    @classmethod
    def remove_token(cls, token):
        if token in cls.invert_cache():
            del cls.cache[token]
        # After deletion, restore to original cache
        cls.invert_cache()

    @classmethod
    def invert_cache(cls):
        """
        The items of cache should be unique for each user.
        So it can be inverted for searching via token value.
        """
        cls.cache = {v: k for k, v in cls.cache.items()}
        return cls.cache

    @classmethod
    def ishit(cls, user, token):
        return token == cls.cache.get(user)

    @classmethod
    def dump(cls):
        #TODO
        for k, v in cls.cache.items():
            print k, ": ", v

class Config(object):
    """
    To store the configuration set by DevOps.
    The configuration is defined by groups.
    One example below:
        [devops]
        user = devops
        passwd = passwd

        [security]
        algorithm = md5
        expires = 86400

        [database]
        auth = /var/polaris/auth.db
        event = /var/polaris/maintenance.db

    """
    def __init__(self, conf_file='/etc/polaris/maintenance.cfg'):
        self.conf_file = conf_file
        self.config = ConfigParser.RawConfigParser(allow_no_value=True)
        self.config.read(conf_file)

    @staticmethod
    def get_config():
        return Config(CONF_PATH)

    @property
    def user(self):
        return self.config.get('devops', 'user')

    @property
    def passwd(self):
        return self.config.get('devops', 'passwd')

    @property
    def algorithm(self):
        return self.config.get('security', 'algorithm')

    @property
    def expires(self):
        return self.config.getint('security', 'expires')

    @property
    def auth_db(self):
        return self.config.get('database', 'auth')

    @property
    def maintenance_event_db(self):
        return self.config.get('database', 'event')

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
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
        user varchar UNIQUE,
        token TEXT,
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
        service TEXT,
        timestamp TEXT,
        duration INTEGER)
        '''
        conn.cursor().execute(sql)

    def add_record(self, service_lst, when, duration):
        """
        SQLite does not have a storage class set aside for storing dates
        and/or times. Instead, the built-in Date And Time Functions of
        SQLite are capable of storing dates and times as TEXT, REAL, or
        INTEGER values:
            * TEXT as ISO8601 strings ("YYYY-MM-DD HH:MM:SS.SSS").
            * REAL as Julian day numbers, the number of days since noon
              in Greenwich on November 24, 4714 B.C. according to the proleptic
              Gregorian calendar.
            * INTEGER as Unix Time, the number of seconds since 1970-01-01
              00:00:00 UTC.
        In Polaris-* services, the date format is ISO8601, so we would like to
        use TEXT as the date type.
        """

        sql = '''
        INSERT INTO maintenance_event VALUES
        (NULL, '%s', '%s', %d)
        ''' % (service_lst, when, duration)
        self.execute_sql(sql)
        self.commit()

    def get_record(self, e_id):
        query = '''
        SELECT * FROM maintenance_event WHERE id = %d
        ''' % e_id if e_id >= 0 else '''
        SELECT * FROM maintenance_event ORDER BY id DESC LIMIT 1
        '''
        return self.execute_sql(query).fetchone()

    def get_max_id(self):
        query = '''
        SELECT MAX(id) as id FROM maintenance_event
        '''
        r = self.execute_sql(query).fetchone()
        return r['id'] if r else None

    def update_record(self, e_id, service_lst, when, duration):
        update = '''
        (SELECT * FROM maintenance_event WHERE id = %d)
        ''' % e_id
        sql = '''
        INSERT OR REPLACE INTO maintenance_event VALUES
        (%s, '%s', '%s', %d)
        ''' % (update, service_lst, when, duration)
        try:
            self.execute_sql(sql)
            self.commit()
        except (sqlite3.DataError, sqlite3.DatabaseError):
            raise


class MaintenanceScheduler(object):
    def __init__(self):
        super(MaintenanceScheduler, self).__init__()
        db_file = Config.get_config().maintenance_event_db
        self._get_broker = lambda : MaintenanceEventBroker(db_file)

    @staticmethod
    def get_scheduler():
        return MaintenanceScheduler()

    def create_event(self, services, when, duration):
        broker = self._get_broker()
        broker.initialize()
        try:
            broker.add_record(services, when, duration)
        except DBConnectionError:
            broker.add_record(services, when, duration)
        finally:
            return broker.get_max_id()

    def get_event(self, e_id):
        broker = self._get_broker()
        try:
            with broker.broker as broker:
                r = broker.get_record(e_id)
                if r:
                    return r
                else:
                    raise InvalidIDError(e_id)
        except DBConnectionError:
            raise

    def update_event(self, e_id, service_lst, when, duration):
        broker = self._get_broker()
        try:
            broker.update_record(e_id, service_lst, when, duration)
            return e_id
        except Exception:
            raise

    def delete_event(self, e_id):
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
        self.token_life = expires
        db_file = Config.get_config().auth_db
        self._get_broker = lambda : AuthBroker(db_file)
        self.hash = getattr(hashlib, algorithm.lower(), hashlib.md5)

    @staticmethod
    def get_simple_auth():
        algorithm = Config.get_config().algorithm or 'md5'
        expires = Config.get_config().expires or 86400
        return SimpleAuth(algorithm, expires)

    @Cache()
    def get_token(self, user, passwd):
        def _validate_user_and_passwd():
            u = Config.get_config().user
            p = Config.get_config().passwd
            if u != user or p != passwd:
                raise Exception("Invalid (user: %s, passwd: %s)" % (user, passwd))
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
            INSERT OR REPLACE INTO auth VALUES(%s, '%s', '%s', %d)
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
            SELECT user, token, expires FROM auth WHERE token = '%s'
            ''' % token
            # If token is valid, return(token, expires)
            # If token is invalid, return None
            return broker.execute_sql(q).fetchone()

        broker = self._get_broker()
        try:
            with broker.broker as broker:
                info = _get_token_info_from_db()
                if not info:
                    raise InvalidTokenError(None, token)
                elif info['expires'] - long(time()) <= 0:
                    # Remove it from cache if it has been cached
                    Cache.remove_token(token)
                    raise ExpiredTokenError(info['user'], token)
                else:
                    return "valid"
        except DBConnectionError:
            raise
