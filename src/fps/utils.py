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

config = configparser.ConfigParser()
config.read('config.ini')


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

        conn.commit()


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
