#!/usr/bin/env python
# coding=utf-8

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
    main()
    auth = utils.SimpleAuth()
    print get_token(auth, 'devops', 'Passw0rd')
    print get_token(auth, 'devops2', 'Passw0rd')
    t = get_token(auth, 'devops', 'Passw0rd')
    sleep(2)
    print t
    print auth.validate_token(t)
