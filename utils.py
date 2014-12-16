# coding=utf-8

import os
import errno
import hashlib
import sqlite3
import functools
from time import time
from datetime import datetime
from contextlib import contextmanager

import shutil
import logging
import ConfigParser
from tempfile import mkstemp

from simplecrypt import encrypt, decrypt

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

class InvalidUserError(Exception):
    def __init__(self, user):
        self.user = user

    def __str__(self):
        return "Invalid user: %s" % self.user

class InvalidPasswdError(Exception):
    def __init__(self, passwd):
        self.passwd = passwd

    def __str__(self):
        return "Wrong password: %s" % self.passwd

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
        import csv
        with open("/tmp/token_cache.csv", 'w') as f:
            w = csv.writer(f)
            for k, v in cls.cache.items():
                w.writerow([k, v])

class Config(object):
    """
    To store the configuration set by DevOps.
    The configuration is defined by groups.
    One example below:
        [devops]
        user = devops
        passwd = passwd
        encrypt_flag = False

        [security]
        algorithm = md5
        expires = 86400

        [database]
        auth_db = /var/polaris/auth.db
        event_db = /var/polaris/maintenance.db

    The option 'encrypt_flag' should be pre-defined as False for encryption
    invoking later.

    """
    def __init__(self, conf_file='/etc/polaris/maintenance.cfg'):
        self.conf_file = conf_file
        self.config = ConfigParser.RawConfigParser(allow_no_value=True)
        self.config.read(conf_file)
        if not self.config.getboolean('devops', 'encrypt_flag'):
            self._encrypt_password()

    @staticmethod
    def get_config():
        return Config(CONF_PATH)

    def _encrypt_password(self):
        cipher_passwd = encrypt('devops', self.config.get('devops', 'passwd'))
        self.config.set('devops', 'passwd', cipher_passwd)
        self.config.set('devops', 'encrypt_flag', True)
        self.config.write(open(self.conf_file, 'w'))

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
        return self.config.get('database', 'auth_db')

    @property
    def maintenance_event_db(self):
        return self.config.get('database', 'event_db')

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
    @timeout: the timeout value to connect a db file
    @logger: the logger for logging
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

    def rollback(self):
        self.conn.rollback()

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

    def backup(self, backup_dir):
        if not os.path.exists(backup_dir):
            raise Exception("Backup dir does not exist!" % backup_dir)
        backup_db_file = os.path.join(
            backup_dir,
            os.path.basename(self.db_file)
            + datetime.now().strftime(".%Y%m%d-%H:%M:%S"))
        self.execute_sql('BEGIN IMMEDIATE')
        shutil.copyfile(self.db_file, backup_db_file)
        self.rollback()

    def restore(self, src_db_file):
        raise NotImplementedError

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

    def add_token(self, user, token, expires):
        update = '''
        (SELECT id FROM auth WHERE user = '%s')
        ''' % user
        sql = '''
        INSERT OR REPLACE INTO auth VALUES(%s, '%s', '%s', %d)
        ''' % (update, user, token, expires)
        self.execute_sql(sql)
        self.commit()

    def get_token_info(self, token):
        q = '''
        SELECT user, token, expires FROM auth WHERE token = '%s'
        ''' % token
        # If token is valid, return(token, expires)
        # If token is invalid, return None
        return self.execute_sql(q).fetchone()


class MaintenanceEventBroker(DBBroker):
    """
    MaintenanceEventBroker is used for maintenance notfication event table
    manifections. It is derived from DBBroker to reuse low level functions.
    @conn: the connection to db file
    """
    db_type = 'maintenance_event'

    def _initialize(self, conn):
        self.create_maintenance_event_table(conn)

    def create_maintenance_event_table(self, conn):
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
        CREATE TABLE maintenance_event
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT,
        timestamp TEXT,
        duration INTEGER)
        '''
        conn.cursor().execute(sql)

    def add_record(self, service_lst, when, duration):
        sql = '''
        INSERT INTO maintenance_event VALUES
        (NULL, '%s', '%s', %d)
        ''' % (service_lst, when, duration)
        self.execute_sql(sql)
        self.commit()

    def get_record(self, e_id):
        """
        In order to retrieve the latest event, we plan to use negative value to
        get the latest event record. Hence the query has relationship with e_id.
        """
        query = '''
        SELECT * FROM maintenance_event WHERE id = %d
        ''' % e_id if e_id >= 0 else '''
        SELECT * FROM maintenance_event ORDER BY timestamp DESC LIMIT 1
        '''
        return self.execute_sql(query).fetchone()

    @property
    def all_records(self):
        query = '''
        SELECT * FROM maintenance_event
        '''
        return self.execute_sql(query).fetchall()

    @property
    def max_id(self):
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

    def delete_record(self, e_id):
        query = '''
        DELETE FROM maintenance_event WHERE id = %d
        ''' % e_id if isinstance(e_id, int) else '''
        DELETE FROM maintenance_event
        '''
        try:
            self.execute_sql(query)
            self.commit()
        except (sqlite3.DataError, sqlite3.DatabaseError):
            raise


class MaintenanceScheduler(object):
    """
    MaintenanceScheduler is the delegate for maintenance event operations.
    The actual operations are performed by MaintenanceEventBroker.
    """
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
            return broker.max_id

    def get_event(self, e_id=-1):
        broker = self._get_broker()
        if isinstance(e_id, int):
            try:
                with broker.broker as broker:
                    r = broker.get_record(e_id)
                    if r:
                        return r
                    else:
                        raise InvalidIDError(e_id)
            except DBConnectionError:
                raise
        elif isinstance(e_id, str) and e_id.lower() == 'all':
            try:
                with broker.broker as broker:
                    return broker.all_records
            except DBConnectionError:
                raise
        else:
            raise InvalidIDError(e_id)

    def update_event(self, e_id, service_lst, when, duration):
        broker = self._get_broker()
        try:
            broker.update_record(e_id, service_lst, when, duration)
            return e_id
        except Exception:
            raise

    def delete_event(self, e_id):
        if isinstance(e_id, str) and e_id != 'all':
            raise InvalidIDError(e_id)
        broker = self._get_broker()
        try:
            with broker.broker as broker:
                broker.delete_record(e_id)
        except DBConnectionError:
            raise

    def backup_db(self, backup_dir):
        with self._get_broker().broker as broker:
            try:
                broker.backup(backup_dir)
            except Exception:
                raise

    def restore(self, src_db_file):
        raise NotImplementedError

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
            if user != u:
                raise InvalidUserError(user)
            elif passwd != decrypt('devops', p):
                raise InvalidPasswdError(passwd)
        try:
            _validate_user_and_passwd()
        except (InvalidUserError, InvalidPasswdError):
            raise

        m = self.hash()
        m.update(user + passwd + \
                 datetime.now().strftime('%d/%m/%y: %H:%M:%S'))
        token  = m.hexdigest()
        expires = long(time() + self.token_life)
        broker = self._get_broker()
        try:
            with broker.broker as broker:
                broker.add_token(user, token, expires)
        except DBConnectionError: # DB does not exist
            broker.initialize()
            broker.add_token(user, token, expires)

        return token

    def validate_token(self, token):
        broker = self._get_broker()
        try:
            with broker.broker as broker:
                info = broker.get_token_info(token)
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

    def backup_db(self, backup_dir):
        with self._get_broker().broker as broker:
            try:
                broker.backup(backup_dir)
            except Exception:
                raise

    def restore(self, src_db_file):
        raise NotImplementedError
