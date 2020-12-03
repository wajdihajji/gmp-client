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
                       run_scan)
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


def job_init(gmp_client):
    """Runs scan and discovery initialisation."""
    initialise_scan(gmp_client)
    initialise_discovery(gmp_client)


@with_logging
def job_run_discovery(gmp_client, db_connection):
    """Runs host discovery."""
    # Get the hosts that have not been selected_for discovery or seen up,
    # not selected for scan and not yet scanned.
    sub_hosts = get_hosts(db_connection, [0], [0], [0], [0], num_records=1024)
    run_discovery(gmp_client, db_connection, sub_hosts)


@with_logging
def job_run_scan(gmp_client, db_connection):
    """Runs scan."""
    # Get the hosts that have been seen up, not selected for scan and not yet scanned.
    sub_hosts = get_hosts(db_connection, [0, 1], [1], [0], [0], num_records=1024)
    run_scan(gmp_client, db_connection, sub_hosts)


if __name__ == '__main__':
    gmp_client = GMPClient()
    db_connection = create_db_connection()
    populate_hosts_table(db_connection, permutation_elts=4)

    job_init(gmp_client)

    # The following schedule simply means run job_run_discovery then job_run_scan and do that infinitely.
    schedule.every(15).seconds.do(
        job_run_discovery, gmp_client=gmp_client, db_connection=db_connection)
    schedule.every(15).seconds.do(
        job_run_scan, gmp_client=gmp_client, db_connection=db_connection)

    while True:
        schedule.run_pending()
        time.sleep(1)
