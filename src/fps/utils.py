"""
Utils functions to:
    - Manipulate `hosts` SQLite table.
    - Generate random IP addresses for testing.
    - Dictionary-related operations.
"""
import configparser
import itertools
import logging
import sqlite3
from datetime import date

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


def create_db_connection(db_file=config['DB']['sqlite_file']):
    """
    Creates a database connection to the SQLite database specified by `db_file`.

    :param db_file: database file.
    :return: Connection object or `None`.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as error:
        logging.error(error)

    return conn


def populate_hosts_table(conn, hosts_file=date.today(), permutation_elts=None):
    """Initiliase hosts table with hosts in `hosts_file`
       or generated random IP addresses for testing"""
    scan_date = None
    if permutation_elts is not None:
        scan_date = date.today()
        hosts_ips = generate_random_ips(permutation_elts)
        hosts = [(scan_date, ip, '', 0, 0, 0, 0) for ip in hosts_ips]
    else:
        scan_date = hosts_file
        hosts_file_full_path = f"{config['DB']['hosts_files_dir']}/{hosts_file}"
        with open(hosts_file_full_path, 'r') as reader:
            hosts_ips = reader.read().splitlines()
        hosts = [(scan_date, ip, '', 0, 0, 0, 0) for ip in hosts_ips]

    with conn:
        cur = conn.cursor()

        logging.info('Creating %s entries in table hosts to be scanned on %s...', len(hosts), scan_date)
        cur.execute('''create table if not exists hosts
                    (date text not null, ip_address text primary key, netmask text,
                    selected_for_discovery integer default 0, seen_up integer default 0,
                    selected_for_scan integer default 0, scanned integer default 0)''')

        for host in hosts:
            insert_host(conn, host)

        conn.commit()


def insert_host(conn, host):
    """Creates a new host."""
    try:
        sql = ''' INSERT INTO hosts(date, ip_address, netmask, selected_for_discovery, seen_up, selected_for_scan, scanned)
                VALUES(?, ?, ?, ?, ?, ?, ?) '''
        cur = conn.cursor()
        cur.execute(sql, host)
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)

    return cur.lastrowid


def update_host_attribute(conn, attribute, value, host_ip_address, _date=date.today()):
    """Set host's `attribute` to `value`."""
    try:
        sql = f'update hosts set {attribute} = ? where ip_address = ? and date = ?'
        cur = conn.cursor()
        cur.execute(sql, (value, host_ip_address, _date))
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)

    return cur.lastrowid


def initialise_host_attribute(conn, attribute, value, _date=date.today()):
    """Initialises `attribute` to `value`."""
    try:
        sql = f'update hosts set {attribute} = ? where date = ?'
        cur = conn.cursor()
        cur.execute(sql, (value, _date))
        conn.commit()
    except sqlite3.Error as error:
        logging.error(error)

    return cur.lastrowid


def get_hosts(conn, selected_for_discovery, seen_up, selected_for_scan, scanned, _date=date.today(), num_records=None):
    """Queries IP addresses in hosts table where `attribute` equals `value`."""
    try:
        sql = (f'select ip_address from hosts '
               f'where selected_for_discovery in ({",".join(str(val) for val in selected_for_discovery)}) '
               f'and seen_up in ({",".join(str(val) for val in seen_up)}) '
               f'and selected_for_scan in ({",".join(str(val) for val in selected_for_scan)}) '
               f'and scanned in ({",".join(str(val) for val in scanned)}) '
               f'and date = "{_date}"'
               f'{"" if num_records is None else " limit " + str(num_records)}')
        cur = conn.cursor()
        cur.execute(sql)
    except sqlite3.Error as error:
        logging.error(error)

    rows = cur.fetchall()

    logging.info('get_hosts(selected_for_discovery=%s, seen_up=%s, selected_for_scan=%s, scanned=%s) returns %s rows',
                 selected_for_discovery, seen_up, selected_for_scan, scanned, len(rows))

    return [row[0] for row in rows]


def get_hosts_count(conn, selected_for_discovery, seen_up, selected_for_scan, scanned, _date=date.today()):
    """Returns hosts count."""
    try:
        sql = (f'select count(*) from hosts '
               f'where selected_for_discovery in ({",".join(str(val) for val in selected_for_discovery)}) '
               f'and seen_up in ({",".join(str(val) for val in seen_up)}) '
               f'and selected_for_scan in ({",".join(str(val) for val in selected_for_scan)}) '
               f'and scanned in ({",".join(str(val) for val in scanned)}) '
               f'and date = "{_date}"')
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
