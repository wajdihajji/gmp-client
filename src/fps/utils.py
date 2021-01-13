"""
Utils functions to:
    - Manipulate `hosts` SQLite table.
    - Generate random IP addresses for testing.
    - Dictionary-related operations.
"""
import configparser
import csv
import itertools
import logging
import random
import sqlite3
from datetime import datetime

import psycopg2

config = configparser.ConfigParser()
config.read('config.ini')

secrets = configparser.ConfigParser()
secrets.read('secrets.ini')


def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='|', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=printEnd)
    # Print New Line on Complete
    if iteration == total:
        print()


def generate_random_ips(range_length):
    """Generates random IP addresses from the numbers in [1, range_length + 1]."""
    return [f'{subset[0]}.{subset[1]}.{subset[2]}.{subset[3]}'
            for subset in itertools.permutations(range(1, range_length + 1), 4)]


def get_key_by_value(dictionary, searched_value):
    """Returns key by value in a dictionary."""
    for key, value in dictionary.items():
        if value == searched_value:
            return key

    return None


def create_pg_conn(
        host=config['PG']['host'], database=config['PG']['database'], port=config['PG']['port'],
        user=secrets['PG']['user'], password=secrets['PG']['password']):
    """Creates a Postgres connection."""
    conn = None
    try:
        conn = psycopg2.connect(
            host=host, database=database, user=database, password=password, port=port)
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)

    return conn


def create_sqlite_conn(db_file=config['SQLITE']['sqlite_file']):
    """
    Creates an SQLite database connection to the DB file `db_file`.

    :param db_file: database file.
    :return: Connection object or `None`.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as error:
        logging.error(error)

    return conn


def create_hosts_table(conn):
    """Creates `hosts` table."""
    try:
        cur = conn.cursor()
        cur.execute('''create table if not exists hosts
                    (scan_day integer, ip_address text primary key, netmask text,
                    selected_for_discovery integer default 0, seen_up integer default 0,
                    selected_for_scan integer default 0, scanned integer default 0,
                    scan_priority integer default 3)''')
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)


def populate_hosts_table(conn, scan_day=datetime.today().isoweekday(), hosts_file='hosts.csv', permutation_elts=None):
    """Initiliase hosts table with hosts in `hosts_file` or generated random IP addresses."""
    if permutation_elts is not None:
        hosts_ips = generate_random_ips(permutation_elts)
        hosts = [(scan_day, ip, '', 0, 0, 0, 0, random.randint(1, 3)) for ip in hosts_ips]
    else:
        hosts_file_full_path = f"{config['SQLITE']['hosts_files_dir']}/{hosts_file}"
        hosts = []
        try:
            with open(hosts_file_full_path, 'r') as file_input:
                csv_reader = csv.reader(file_input, delimiter=',')
                next(csv_reader)
                for row in csv_reader:
                    hosts.append((row[0], row[1], '', 0, 0, 0, 0, row[2]))
        except FileNotFoundError:
            logging.error('File %s does not exist', hosts_file_full_path)

    with conn:
        logging.info('Creating %s entries in table hosts to be scanned on day %s...', len(hosts), scan_day)
        for host in hosts:
            insert_host(conn, host)


def insert_report(conn, report):
    """Inserts a new report."""
    try:
        sql = """INSERT INTO
        reports (
            ipaddr,
            port,
            portdesc,
            nid,
            risk,
            severity,
            synopsis,
            report,
            date_create,
            date_update)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        cur = conn.cursor()
        cur.execute(sql, report)
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)

    return cur.lastrowid


def insert_host(conn, host):
    """Creates a new host.
    Host is the tuple: (scan_day, ip_address, netmask, selected_for_discovery, \
                        seen_up, selected_for_scan, scanned, scan_priority)"""
    try:
        sql = '''insert or ignore into hosts(
                 scan_day, ip_address, netmask, selected_for_discovery,
                 seen_up, selected_for_scan, scanned, scan_priority)
                 VALUES(?, ?, ?, ?, ?, ?, ?, ?)'''
        cur = conn.cursor()
        cur.execute(sql, host)
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)

    return cur.lastrowid


def update_host_attribute(conn, attribute, value, ip_address, scan_day=datetime.today().isoweekday()):
    """Set host's `attribute` to `value`."""
    try:
        sql = f'update hosts set {attribute} = ? where ip_address = ? and scan_day = ?'
        cur = conn.cursor()
        cur.execute(sql, (value, ip_address, scan_day))
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)

    return cur.lastrowid


def initialise_host_attribute(conn, attribute, value, scan_day=datetime.today().isoweekday()):
    """Initialises `attribute` to `value`."""
    try:
        sql = f'update hosts set {attribute} = ? where scan_day = ?'
        cur = conn.cursor()
        cur.execute(sql, (value, scan_day))
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)

    return cur.lastrowid


def import_hosts(pg_conn, sqlite_conn, day_id=datetime.today().isoweekday()):
    """Imports hosts from the probing database."""
    regular_scan_cursor = None
    try:
        sql = (f'select I.ipaddr as ipaddr from '
               f'(select ipaddr from ipaddr_inst except select ipaddr from ipaddr_blacklist) as I, '
               f'(select day, netblock from probing_schedule) as S '
               f'where I.ipaddr << S.netblock and S.day = {day_id}')
        regular_scan_cursor = pg_conn.cursor()
        regular_scan_cursor.execute(sql)
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)

    user_scan_cursor = None
    try:
        sql = 'select ipaddr from ipaddr_rescan'
        user_scan_cursor = pg_conn.cursor()
        user_scan_cursor.execute(sql)
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)

    if regular_scan_cursor is not None:
        hosts = regular_scan_cursor.fetchall()
        if len(hosts) > 0:
            printProgressBar(0, len(hosts), prefix='Importing FPS scans:', suffix='Complete', length=50)
            i = 0
            for item in hosts:
                insert_host(sqlite_conn, (day_id, item[0], '', 0, 0, 0, 0, 2))
                printProgressBar(i + 1, len(hosts), prefix='Importing FPS scans:', suffix='Complete', length=50)
                i += 1

    if user_scan_cursor is not None:
        hosts = user_scan_cursor.fetchall()
        if len(hosts) > 0:
            printProgressBar(0, len(hosts), prefix='Importing USER scans:', suffix='Complete', length=50)
            i = 0
            for item in hosts:
                insert_host(sqlite_conn, (day_id, item[0], '', 0, 0, 0, 0, 1))
                printProgressBar(i + 1, len(hosts), prefix='Importing USER scans:', suffix='Complete', length=50)
                i += 1


def get_hosts(
        conn, selected_for_discovery, seen_up, selected_for_scan,
        scanned, scan_day=datetime.today().isoweekday(), num_records=None):
    """Returns the hosts where `attribute` equals `value` and having highest scan_priority."""
    try:
        sql = (f'select ip_address, scan_priority from hosts '
               f'where selected_for_discovery in ({",".join(str(val) for val in selected_for_discovery)}) '
               f'and seen_up in ({",".join(str(val) for val in seen_up)}) '
               f'and selected_for_scan in ({",".join(str(val) for val in selected_for_scan)}) '
               f'and scanned in ({",".join(str(val) for val in scanned)}) '
               f'and scan_day = "{scan_day}"'
               f'order by scan_priority'
               f'{"" if num_records is None else " limit " + str(num_records)}')
        cur = conn.cursor()
        cur.execute(sql)
    except sqlite3.Error as error:
        logging.error(error)

    rows = cur.fetchall()

    hosts_high_priority = [row[0] for row in rows if row[1] == rows[0][1]]

    log_msg = 'No hosts found for scan/discovery'

    if len(hosts_high_priority) > 0:
        log_msg = f'Returns {len(hosts_high_priority)} hosts for scan/discovery with priority {rows[0][1]}'

    logging.info(log_msg)

    return hosts_high_priority


def get_hosts_count(
        conn, selected_for_discovery, seen_up, selected_for_scan,
        scanned, scan_priority=[1, 2, 3], scan_day=datetime.today().isoweekday()):
    """Returns hosts count."""
    try:
        sql = (f'select count(*) from hosts '
               f'where selected_for_discovery in ({",".join(str(val) for val in selected_for_discovery)}) '
               f'and seen_up in ({",".join(str(val) for val in seen_up)}) '
               f'and selected_for_scan in ({",".join(str(val) for val in selected_for_scan)}) '
               f'and scanned in ({",".join(str(val) for val in scanned)}) '
               f'and scan_priority in ({",".join(str(val) for val in scan_priority)}) '
               f'and scan_day = "{scan_day}"')
        cur = conn.cursor()
        cur.execute(sql)
    except sqlite3.Error as error:
        logging.error(error)

    value = cur.fetchone()
    return value[0]


def update_discovered_hosts(conn, discovered_hosts, is_discovery=True):
    """Updates `seen_up` or `scanned` attributes of discovered hosts."""
    if is_discovery:
        for host in discovered_hosts:
            update_host_attribute(conn, 'seen_up', 1, host)
    else:
        for host in discovered_hosts:
            update_host_attribute(conn, 'scanned', 1, host)
