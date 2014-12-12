#!/usr/bin/env python
# coding=utf-8

import hashlib
import sqlite3
from time import time
from datetime import datetime


class Cache(object):
    """
    Cache is a deco class for simple cache usage
    """
    def __init__(self):
        super(Cache, self).__init__()

    def __call__(self, f):
        self.cache = dict()
        def wrapper(inst, user, passwd):
            if user not in self.cache:
                self.cache[user] = f(inst, user, passwd)
            return self.cache.get(user)
        return wrapper

    def ishit(self, user, token):
        return token == self.cache.get(user)

class Sqlite3Conn(object):
    """
    Sqlite3Conn is the wrapper class of sqlite3 connection
    @db the db to connect, should be defined in devops settings
    """
    def __init__(self, db='nf.db'):
        super(Sqlite3Conn, self).__init__()
        self.conn = sqlite3.connect(db)
        self.conn.row_factory = sqlite3.Row

    def __enter__(self):
        return self

    def __exit__(self, exc_t, exc_v, tb):
        self.conn.close()

    def execute_sql(self, query):
        return self.conn.cursor().execute(query)

    def commit(self):
        self.conn.commit()

    def is_table_exist(self, table):
        if table and len(table) > 0:
            query = '''
            SELECT name FROM sqlite_master WHERE type='table' AND name = '%s'
            ''' % table
            return True if self.execute_sql(query).fetchone() else False
        else:
            raise Exception("table None or table name is null")

class MaintenanceSecheduler(Sqlite3Conn):
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
        self.db = 'nf.db' # for test, will get from settings
        self.table = 'auth'
        self.token_life = expires
        self.hash = getattr(hashlib, algorithm.lower(), hashlib.md5)

    def get_token(self, user, passwd):
        def _validate_user_and_passwd():
            pass
        _validate_user_and_passwd()

        now = datetime.now()
        m = self.hash()
        m.update(user + passwd + \
                 now.strftime('%d/%m/%y: %H:%M:%S'))
        token  = m.hexdigest()
        expires = long(time() + self.token_life)

        def _write_to_db(token, expires):
            with Sqlite3Conn(self.db) as db:
                if not db.is_table_exist(self.table):
                    sql = '''
                    CREATE TABLE %s
                    (id INTEGER primary key AUTOINCREMENT, user varchar UNIQUE, \
                        token text, expires INTEGER)
                    ''' % self.table
                    db.execute_sql(sql)
                    db.conn.commit()
                update = '''
                (SELECT id from %s WHERE user = '%s')
                    ''' % (self.table, user)
                sql = '''
                INSERT or REPLACE INTO %s VALUES(%s, '%s', '%s', %d)
                ''' % (self.table, update, user, token, expires)
                db.execute_sql(sql)
                db.commit()

        _write_to_db(token, expires)

        return token

    def validate_token(self, token):
        def _get_expires_from_db(token):
            with Sqlite3Conn(self.db) as db:
                q = '''
                SELECT expires from %s WHERE token = '%s'
                ''' % (self.table, token)
                return db.execute_sql(q).fetchone()['expires']
        return _get_expires_from_db(token) - long(time()) > 0
