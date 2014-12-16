#!/usr/bin/env python
# coding=utf-8

import sys
import utils
from time import sleep

def main():
    db_file = "/Users/lafengnan/codes/Github/maintenance/nf.db"
    with utils.AuthBroker(db_file) as sq:
        try:
            sq.execute_sql("""
                      CREATE TABLE event
                      (id int, services text)
                      """)
            sq.commit()
        except utils.sqlite3.OperationalError as e:
            sq.execute_sql('''
                      DROP TABLE event
                      ''')
            sq.execute_sql('''
                      CREATE TABLE event
                      (id int, services text)
                      ''')

            sq.commit()
        v = [(1, 'storage'),
             (2, 'metadata')
             ]
        sq.conn.cursor().executemany('''
                  INSERT INTO event VALUES(?,?)
                  ''', v)
        sq.commit()
        table = 'event'
        query = '''SELECT * from %s''' % table
        print sq.execute_sql(query)
        ids = sq.execute_sql('''
                 SELECT * from event
                 ''')
        for r in ids:
            print r
        sq.conn.row_factory = utils.sqlite3.Row
        r = sq.execute_sql(query).fetchone()
        print r['id']


def get_token(auth, u, p, algorithm='md5'):
    return auth.get_token(u, p)

if __name__ == '__main__':
    #main()
    auth = utils.SimpleAuth.get_simple_auth()
    try:
        t1 = get_token(auth, 'devops', 'Passw0rd')
        t2= get_token(auth, 'devops', 'Passw0rd')
        t3 = get_token(auth, 'devops', 'Passw0rd')
        t4 = get_token(auth, 'devops', 'Passw0rd')
        t5 = get_token(auth, 'devops', 'Passw0rd')
        t6 = get_token(auth, 'devops', 'Passw0rd')
        for t in (t1, t2, t3, t4, t5, t6):
            print t
            try:
                print auth.validate_token(t)
            except utils.InvalidTokenError as e:
                print e
            except utils.ExpiredTokenError as e:
                print e
                try:
                    print auth.validate_token('123')
                except utils.InvalidTokenError as e:
                    pass
                except utils.ExpiredTokenError as e:
                    pass
                finally:
                    print e
    except Exception as e:
        print e
        sys.exit(1)

    utils.Cache.dump()
    sch = utils.MaintenanceScheduler.get_scheduler()
    id1 = sch.create_event("storage, metadata", "2014-12-31 12:00:00.000", 120)
    id5 = sch.create_event("storage, redis", "2014-12-31 12:00:00.000", 120)
    id2 = sch.create_event("storage, ES", "2014-12-31 12:01:00.000", 120)
    id3 = sch.create_event("storage, ES", "2014-12-31 12:01:00.001", 120)
    id4 = sch.create_event("storage, Cassandra", "2014-12-30 12:00:00.000", 120)
    print id1, id2, id3, id4, id5
    sch.delete_event(id2)
    sch.delete_event(id3)
    print sch.get_event('all')
    print sch.get_event(-1)
    #sch.delete_event('all')
    print "--------------"
    print sch.get_event('all')
    sch.backup_db('/home/chris')
    auth.backup_db('/home/chris')
