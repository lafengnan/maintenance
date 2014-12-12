#!/usr/bin/env python
# coding=utf-8

import utils
from time import sleep

def main():
    with utils.DBBroker("nf.db") as sq:
        sq.intialize()
        c = sq.conn.cursor()
        try:
            c.execute("""
                      CREATE TABLE event
                      (id int, services text)
                      """)
        except utils.sqlite3.OperationalError as e:
            c.execute('''
                      DROP TABLE event
                      ''')
            c.execute('''
                      CREATE TABLE event
                      (id int, services text)
                      ''')
        v = [(1, 'storage'),
             (2, 'metadata')
             ]
        c.executemany('''
                  INSERT INTO event VALUES(?,?)
                  ''', v)
        table = 'event'
        query = '''SELECT * from %s''' % table
        print sq.execute_sql(query)
        ids = c.execute('''
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
    auth = utils.SimpleAuth()
    print get_token(auth, 'devops', 'Passw0rd')
    print get_token(auth, 'devops2', 'Passw0rd')
    t = get_token(auth, 'devops', 'Passw0rd')
    sleep(2)
    print t
    print auth.validate_token(t)
