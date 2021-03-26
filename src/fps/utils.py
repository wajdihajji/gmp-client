"""
Utils functions to:
    - Updated database table `hosts`.
    - Generate random IP addresses for testing.
    - Dictionary-related operations.
"""
import configparser
import csv
import itertools
import logging
import os
import random
import re
from datetime import datetime

import psycopg2

config = configparser.ConfigParser()
config.read('config.ini')


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
        host=os.getenv('PG_HOST'), database=config['PROBING-DB']['database'],
        port=config['PROBING-DB']['port'],
        user=os.getenv('PG_USERNAME'), password=os.getenv('PG_PASSWORD')):
    """Creates a Postgres connection."""
    try:
        conn = psycopg2.connect(
            host=host, database=database, user=user, password=password, port=port)
        return conn
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def create_hosts_table(conn):
    """Creates `hosts` table."""
    try:
        cur = conn.cursor()
        cur.execute('''create table if not exists hosts
                    (scan_day integer, ip_address text, netmask text,
                    selected_for_discovery integer default 0, discovery_count integer default 0,
                    seen_up integer default 0, selected_for_scan integer default 0,
                    scanned integer default 0, scan_priority integer default 3,
                    PRIMARY KEY (scan_day, ip_address))''')
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def reset_discovery_attribute(conn):
    """
    Set selected_for_discovery attribute to 0 if all the hosts with seen_up=0
    have been checked if alive in the discovery process.
    """
    try:
        cur = conn.cursor()
        cur.execute('''update hosts
                       set selected_for_discovery = 0
                       where
                       (select count(*) from hosts where seen_up = 0 and selected_for_discovery = 0) = 0
                       ''')
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def populate_hosts_table(
        conn, scan_day=None, hosts_file='hosts.csv', permutation_elts=None):
    """Initiliase hosts table with hosts in `hosts_file` or generated random IP addresses."""
    if scan_day is None:
        scan_day = datetime.today().isoweekday()

    if permutation_elts is not None:
        hosts_ips = generate_random_ips(permutation_elts)
        hosts = [(scan_day, ip, '', 0, 0, 0, 0, random.randint(1, 3)) for ip in hosts_ips]
    else:
        hosts_file_full_path = f"{config['PROBING-DB']['hosts_file_dir']}/{hosts_file}"
        hosts = []
        try:
            with open(hosts_file_full_path, 'r') as file_input:
                csv_reader = csv.reader(file_input, delimiter=',')
                next(csv_reader)
                for row in csv_reader:
                    hosts.append((row[0], row[1].strip(), '', 0, 0, 0, 0, row[2]))
        except FileNotFoundError:
            logging.error('File %s does not exist', hosts_file_full_path)

    with conn:
        logging.info('Creating %s entries in table hosts', len(hosts))
        for host in hosts:
            insert_host(conn, host)


def string_to_datetime(datestring):
    """Converts a date/time string as output by OpenVAS into a Python datetime object."""
    a = list(map(int, re.sub("[^0-9]", ' ', datestring).split()))
    return datetime(a[0], a[1], a[2], a[3], a[4], a[5])


def create_portdesc_dict(service_file='/etc/services'):
    """Creates port description dict."""
    portdesc = {}
    portdesc['general-ip'] = ' '
    regex = re.compile(r'^([a-z]\S+)\s+(\d+)/([a-z]+)\s.*')
    try:
        with open(service_file, 'r') as services:
            for line in services:
                if regex.match(line):
                    m = regex.match(line)
                    name = m.group(1)
                    port = m.group(2)
                    protocol = m.group(3)
                    pd = '{}-{}'.format(port, protocol)
                    portdesc[pd] = name
    except FileNotFoundError:
        logging.error('File %s does not exist', service_file)

    return portdesc


def get_portdesc(portdesc_dict, port):
    """Returns port description of a port."""
    return ' ' if portdesc_dict.get(port) is None else portdesc_dict.get(port)


def severity_to_threat(severity):
    """Map risks to numerical values."""
    if float(severity) == 0:
        return 0
    elif float(severity) <= 3.9:
        return 1
    elif float(severity) <= 6.9:
        return 2
    elif float(severity) <= 8.9:
        return 3
    else:
        return 4


def insert_report(conn, report):
    """Inserts a new report."""
    try:
        sql = '''INSERT INTO reports (
                 ipaddr, port, portdesc, nid, risk, severity,
                 synopsis, report, date_create, date_update)
                 values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
        cur = conn.cursor()
        cur.execute(sql, report)
        conn.commit()
        return cur.lastrowid
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def update_report(conn, report):
    """Updates an existing report."""
    try:
        sql = '''update reports set
                 port = %s, portdesc = %s, risk = %s, severity = %s,
                 synopsis = %s, report = %s, date_update = %s
                 where ipaddr = %s and nid = %s and date_delete IS NULL'''
        cur = conn.cursor()
        cur.execute(
            sql,
            (report[1], report[2], report[4], report[5],
             report[6], report[7], report[8], report[0], report[3]))
        conn.commit()
        return cur.lastrowid
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def update_report_date_delete(conn, date_delete, ipaddr, nid):
    """Updates report's `date_delete`."""
    try:
        sql = 'update reports set date_delete = %s where ipaddr = %s and nid = %s'
        cur = conn.cursor()
        cur.execute(sql, (date_delete, ipaddr, nid))
        conn.commit()
        return cur.lastrowid
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def create_report(result, portdesc_dict):
    """Creates a report from a result object."""
    creation_time = result.xpath('creation_time/text()')[0]
    _port = result.xpath('port/text()')[0]  # like 19/tcp or general/tcp
    ip_address = result.xpath('host/text()')[0]
    nvt_oid = result.xpath('nvt')[0].get('oid')
    tags = result.xpath('nvt/tags/text()')[0]
    severity = result.xpath('severity/text()')[0]
    nvt_name = result.xpath('nvt/name/text()')[0]
    cvss = result.xpath('nvt/cvss_base/text()')[0]

    port = 'general-ip' if _port.split('/')[0] == 'general' else _port.replace('/', '-')

    portdesc = get_portdesc(portdesc_dict, port)

    refs = []
    for ref in result.xpath('nvt/refs/ref'):
        refs.append(ref.get('id'))

    references = '\n'.join(refs)

    summary = re.search(r'summary=([\s\S]*?)\|', tags)
    insight = re.search(r'insight=([\s\S]*?)\|', tags)
    affected = re.search(r'affected=([\s\S]*?)\|', tags)
    impact = re.search(r'impact=([\s\S]*?)\|', tags)
    solution = re.search(r'solution=([\s\S]*?)\|', tags)
    detection = re.search(r'vuldetect=([\s\S]*?)\|', tags)
    soltype = re.search(r'solution_type=([\s\S]*?)$', tags)

    cve = specresult = report = None

    report = f'''Network Vulnerability Test: {nvt_name}

    Synopsis:
    {'N/A' if summary is None else summary.group(1)}

    Impact:
    {'N/A' if impact is None else impact.group(1)}

    Description:
    {'N/A' if insight is None else insight.group(1)}

    Solution:
    {'N/A' if solution is None else solution.group(1)}

    Solution type: {'N/A' if soltype is None else soltype.group(1)}

    Risk Factor: {severity}

    CVSS Base Score: {cvss}

    CVE: {cve}

    Severity: {severity}

    Detection Method:
    {'N/A' if detection is None else detection.group(1)}

    Specific Result:
    {specresult}

    Affected Software/OS:
    {'N/A' if affected is None else affected.group(1)}

    Other References:
    {references}
    '''

    return (ip_address, port, portdesc, nvt_oid, severity_to_threat(severity),
            cvss, nvt_name, report, string_to_datetime(creation_time),
            string_to_datetime(creation_time))


def export_results(conn, results):
    """Exports results to the probing DB."""
    report_rows = []
    try:
        cur = conn.cursor()
        cur.execute('select ipaddr, nid, date_create, date_update from reports where date_delete is null')
        report_rows = cur.fetchall()
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)

    existing = {}
    ipnids = {}
    for row in report_rows:
        existing[row[0] + '-' + row[1]] = (row[2], row[3])
        if row[0] not in ipnids.keys():
            ipnids[row[0]] = set({})
        ipnids[row[0]] |= {row[1]}

    portdesc_dict = create_portdesc_dict()
    ips = set({})
    for result in results:
        nvt_oid = result.xpath('nvt')[0].get('oid')
        ip_address = result.xpath('host/text()')[0]
        if nvt_oid in ['1.3.6.1.4.1.25623.1.0.999998', '1.3.6.1.4.1.25623.1.0.108560']:
            logging.info(
                'Result of IP address %s and NVT OID %s has been ignored.', ip_address, nvt_oid)
            continue

        ips |= {ip_address}

        key = f'{ip_address}-{nvt_oid}'
        report = create_report(result, portdesc_dict)

        is_insert = True
        if key not in existing.keys():
            insert_report(conn, report)
        else:
            is_insert = False
            update_report(conn, report)

        if ip_address in ipnids.keys():
            ipnids[ip_address] -= {nvt_oid}

        logging.info(
            'Result of IP address %s and NVT OID %s has been %s',
            ip_address, nvt_oid, 'inserted' if is_insert else 'updated')

    timestamp = datetime.now()
    for ip in sorted(ips):
        if ip in ipnids.keys():
            for nid in ipnids[ip]:
                update_report_date_delete(conn, timestamp, ip, nid)


def insert_host(conn, host):
    """Creates a new host.
    Host is the tuple: (scan_day, ip_address, netmask, selected_for_discovery, \
                        seen_up, selected_for_scan, scanned, scan_priority)"""
    try:
        sql = '''insert into hosts(
                 scan_day, ip_address, netmask, selected_for_discovery,
                 seen_up, selected_for_scan, scanned, scan_priority)
                 VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
                 on conflict do nothing'''
        cur = conn.cursor()
        cur.execute(sql, host)
        conn.commit()
        return cur.lastrowid
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def update_host_attribute(conn, attribute, value, ip_address, scan_day=None):
    """Set host's `attribute` to `value`."""
    if scan_day is None:
        scan_day = datetime.today().isoweekday()

    try:
        # if selected_for_discovery -> 1, increment discovery_count
        if attribute == 'selected_for_discovery' and value == 1:
            sql = (f'update hosts set '
                   f'{attribute} = %s, '
                   f'discovery_count = discovery_count + 1 '
                   f'where ip_address = %s and scan_day = %s')
        else:
            sql = (f'update hosts set '
                   f'{attribute} = %s '
                   f'where ip_address = %s and scan_day = %s')
        cur = conn.cursor()
        cur.execute(sql, (value, ip_address, scan_day))
        conn.commit()
        return cur.lastrowid
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def del_hosts_by_day(conn, scan_day=None):
    """Delete hosts scheduled to scan on day `scan_day`."""
    if scan_day is None:
        scan_day = datetime.today().isoweekday() + 1

    try:
        sql = f'delete from hosts where scan_day = {scan_day}'
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def initialise_host_attribute(conn, attribute, value, scan_day=None):
    """Initialises `attribute` to `value`."""
    if scan_day is None:
        scan_day = datetime.today().isoweekday()

    try:
        sql = f'update hosts set {attribute} = %s where scan_day = %s'
        cur = conn.cursor()
        cur.execute(sql, (value, scan_day))
        conn.commit()
        return cur.lastrowid
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def import_hosts(pg_conn, day_id=None):
    """Imports hosts from the probing database."""
    if day_id is None:
        day_id = datetime.today().isoweekday()

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
            printProgressBar(0, len(hosts), prefix='Importing hosts:', suffix='Complete', length=50)
            i = 0
            for item in hosts:
                insert_host(pg_conn, (day_id, item[0], '', 0, 0, 0, 0, 2))
                printProgressBar(i + 1, len(hosts), prefix='Importing hosts:', suffix='Complete', length=50)
                i += 1

    if user_scan_cursor is not None:
        hosts = user_scan_cursor.fetchall()
        if len(hosts) > 0:
            printProgressBar(0, len(hosts), prefix='Importing USER hosts:', suffix='Complete', length=50)
            i = 0
            for item in hosts:
                insert_host(pg_conn, (day_id, item[0], '', 0, 0, 0, 0, 1))
                printProgressBar(i + 1, len(hosts), prefix='Importing USER hosts:', suffix='Complete', length=50)
                i += 1


def get_hosts(
        conn, selected_for_discovery, seen_up, selected_for_scan,
        scanned, scan_day=None, num_records=None):
    """Returns the hosts where `attribute` equals `value` and having highest scan_priority."""
    if scan_day is None:
        scan_day = datetime.today().isoweekday()

    rows = None

    try:
        sql = (f'select ip_address, scan_priority from hosts '
               f'where selected_for_discovery in ({",".join(str(val) for val in selected_for_discovery)}) '
               f'and seen_up in ({",".join(str(val) for val in seen_up)}) '
               f'and selected_for_scan in ({",".join(str(val) for val in selected_for_scan)}) '
               f'and scanned in ({",".join(str(val) for val in scanned)}) '
               f'and scan_day = {scan_day} '
               f'order by scan_priority'
               f'{"" if num_records is None else " limit " + str(num_records)}')
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)

    hosts_high_priority = [row[0] for row in rows if rows is not None and row[1] == rows[0][1]]

    scan_type = 'discovery' if seen_up == [0] else 'scan'

    log_msg = f'No hosts found for {scan_type}'

    if len(hosts_high_priority) > 0:
        log_msg = f'Returns {len(hosts_high_priority)} hosts for {scan_type} with priority {rows[0][1]}'

    logging.info(log_msg)

    return hosts_high_priority


def get_hosts_count(
        conn, selected_for_discovery, seen_up, selected_for_scan,
        scanned, scan_priority=[1, 2, 3], scan_day=None):
    """Returns hosts count."""
    if scan_day is None:
        scan_day = datetime.today().isoweekday()

    try:
        sql = (f'select count(*) from hosts '
               f'where selected_for_discovery in ({",".join(str(val) for val in selected_for_discovery)}) '
               f'and seen_up in ({",".join(str(val) for val in seen_up)}) '
               f'and selected_for_scan in ({",".join(str(val) for val in selected_for_scan)}) '
               f'and scanned in ({",".join(str(val) for val in scanned)}) '
               f'and scan_priority in ({",".join(str(val) for val in scan_priority)}) '
               f'and scan_day = {scan_day}')
        cur = conn.cursor()
        cur.execute(sql)
        value = cur.fetchone()
        return value[0]
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)


def update_discovered_hosts(conn, discovered_hosts, is_discovery=True):
    """Updates `seen_up` or `scanned` attributes of discovered hosts."""
    if is_discovery:
        for host in discovered_hosts:
            update_host_attribute(conn, 'seen_up', 1, host)
    else:
        for host in discovered_hosts:
            update_host_attribute(conn, 'scanned', 1, host)
