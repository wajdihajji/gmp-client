"""
Running scheduled jobs.
"""
import configparser
import functools
import logging
import time

import schedule

from fps.client import GMPClient
from fps.tasks import (initialise_discovery, initialise_scan, run_discovery,
                       run_scan, update_host_attribute)
from fps.utils import (create_hosts_table, create_pg_conn, create_sqlite_conn,
                       del_hosts_by_day, get_hosts, import_hosts,
                       populate_hosts_table)

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

config = configparser.ConfigParser()
config.read('config.ini')


# logging decorator for schedule jobs
def with_logging(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logging.info('Started job "%s"' % func.__name__)
        result = func(*args, **kwargs)
        logging.info('Job "%s" completed' % func.__name__)
        return result
    return wrapper


@with_logging
def job_populate_hosts_table(sqlite_conn):
    """Loads the host files in `./data` into the SQLite table `hosts`."""
    populate_hosts_table(sqlite_conn)


@with_logging
def job_run_discovery(gmp_client, sqlite_conn, pg_conn):
    """Runs host discovery."""
    # Get the hosts that have not been selected for discovery or seen up,
    # not selected for scan and not yet scanned.
    sub_hosts = get_hosts(
        sqlite_conn, [0], [0], [0], [0], num_records=config.getint('DISCOVERY', 'max_num_hosts'))
    run_discovery(gmp_client, sqlite_conn, pg_conn, sub_hosts)


@with_logging
def job_import_hosts(sqlite_conn, pg_conn):
    """Import hosts to scan."""
    if config['INTERNAL-DB'].getboolean('import_hosts_from_file'):
        populate_hosts_table(sqlite_conn)
    else:
        import_hosts(sqlite_conn, pg_conn)


@with_logging
def job_run_scan(gmp_client, sqlite_conn, pg_conn):
    """Runs scan."""
    # Get the hosts that have been seen up, not selected for scan and not yet scanned.
    sub_hosts = get_hosts(
        sqlite_conn, [0, 1], [1], [0], [0], num_records=config.getint('SCAN', 'max_num_hosts'))
    for host in sub_hosts:
        update_host_attribute(sqlite_conn, 'selected_for_scan', 1, host)
    run_scan(gmp_client, sqlite_conn, pg_conn, sub_hosts)


if __name__ == '__main__':
    gmp_client = GMPClient()
    sqlite_conn = create_sqlite_conn()
    pg_conn = create_pg_conn()

    discovery_freq = config.getint('DISCOVERY', 'frequency')
    import_hosts_freq = config.getint('DISCOVERY', 'hosts_import_frequency')
    scan_freq = config.getint('SCAN', 'frequency')

    # Initialisation steps:
    # 1. create sqlite hosts table
    create_hosts_table(sqlite_conn)

    # 2. create scanners and their dependencies
    initialise_scan(gmp_client)

    # 3. create discovery scanner and its dependency
    initialise_discovery(gmp_client)

    # 4. import hosts from either csv file or pg database
    job_import_hosts(sqlite_conn, pg_conn)

    # 5. delete next day hosts in the SQL database
    # This to prepare for getting the next day hosts to scan
    del_hosts_by_day(sqlite_conn)

    # 6. start the first discovery task
    job_run_discovery(gmp_client, sqlite_conn, pg_conn)

    # Scheduled steps:
    # 1. import hosts every `import_hosts_freq` minutes
    schedule.every(import_hosts_freq).minutes.do(
        job_import_hosts, sqlite_conn=sqlite_conn, pg_conn=pg_conn)

    # 2. run job_run_discovery every `discovery_freq` minutes
    schedule.every(10).seconds.do(
        job_run_discovery, gmp_client=gmp_client, sqlite_conn=sqlite_conn, pg_conn=pg_conn)

    # 3. run job_run_scan every `scan_freq` minutes
    schedule.every(10).seconds.do(
        job_run_scan, gmp_client=gmp_client, sqlite_conn=sqlite_conn, pg_conn=pg_conn)

    # 4. delete next day hosts at 11pm
    schedule.every().day.at("23:00:00").do(
        del_hosts_by_day, sqlite_conn=sqlite_conn
    )

    while True:
        schedule.run_pending()
        time.sleep(1)
