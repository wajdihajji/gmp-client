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
from fps.utils import create_db_connection, get_hosts, populate_hosts_table

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
def job_populate_hosts_table(db_connection):
    """Loads the host files in `./data` into the SQLite table `hosts`."""
    populate_hosts_table(db_connection)


@with_logging
def job_run_discovery(gmp_client, db_connection):
    """Runs host discovery."""
    # Get the hosts that have not been selected for discovery or seen up,
    # not selected for scan and not yet scanned.
    sub_hosts = get_hosts(
        db_connection, [0], [0], [0], [0], num_records=config.getint('DISCOVERY', 'max_num_hosts'))
    run_discovery(gmp_client, db_connection, sub_hosts)


@with_logging
def job_run_scan(gmp_client, db_connection):
    """Runs scan."""
    # Get the hosts that have been seen up, not selected for scan and not yet scanned.
    sub_hosts = get_hosts(
        db_connection, [0, 1], [1], [0], [0], num_records=config.getint('SCAN', 'max_num_hosts'))
    for host in sub_hosts:
        update_host_attribute(db_connection, 'selected_for_scan', 1, host)
    run_scan(gmp_client, db_connection, sub_hosts)


if __name__ == '__main__':
    gmp_client = GMPClient()
    db_connection = create_db_connection()
    populate_hosts_table(db_connection)
    initialise_scan(gmp_client)
    initialise_discovery(gmp_client)

    # Run job_populate_hosts_table every day at 00:01
    schedule.every().day.at("00:01").do(
        job_populate_hosts_table, db_connection=db_connection)

    discovery_freq = config.getint('DISCOVERY', 'frequency')
    scan_freq = config.getint('SCAN', 'frequency')

    # Run job_run_discovery every `discovery_freq` minutes
    schedule.every(discovery_freq).minutes.do(
        job_run_discovery, gmp_client=gmp_client, db_connection=db_connection)

    # Run job_run_scan every `scan_freq` minutes
    schedule.every(scan_freq).minutes.do(
        job_run_scan, gmp_client=gmp_client, db_connection=db_connection)

    while True:
        schedule.run_pending()
        time.sleep(1)
