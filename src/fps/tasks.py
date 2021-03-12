"""
Tasks for managing tasks, targets and scanners in GVM.
"""
import configparser
import logging
import uuid

from fps.client import GMPClient
from fps.utils import (export_results, get_hosts, get_key_by_value,
                       reset_discovery_attribute, update_discovered_hosts,
                       update_host_attribute)

config = configparser.ConfigParser()
config.read('config.ini')


def create_comment(key, values):
    """Creates comments to be injected in `get_` functions filters."""
    return '' if values is None else ' '.join([f'comment="{key}:{value}"' for value in values])


def scan_or_discovery(task_name):
    """Determines if a task was created for discovery or scan."""
    return 'discovery' if task_name == config['DISCOVERY']['task_name'] else 'scan'


def create_tasks(
        client: GMPClient, number_of_tasks, config_name,
        target_name, scanner_name, preferences, state='initialised'):
    """
    Creates a set of tasks.

    :param client: GMP client.
    :param number_of_tasks: number of tasks to create.
    :param config_name: tasks' configuration.
    :param target_name: tasks' target.
    :param scanner_name: tasks' scanner.
    :param preferences: tasks' preferences.
    :param state: tasks' state.
    :return: list of names of created tasks.
    """
    name = uuid.uuid4().hex

    required_kwargs = {}
    required_kwargs['config_name'] = config_name
    required_kwargs['target_name'] = target_name
    required_kwargs['scanner_name'] = scanner_name
    required_kwargs['preferences'] = preferences

    tasks = []
    for idx in range(number_of_tasks):
        result = client.create_task(name=f'{name}_{idx}', state=state, **required_kwargs)
        tasks.append(f'{name}_{idx}')
        logging.info('Create task %s: %s', f'{name}_{idx}', result.get('status_text'))

    return tasks


def create_targets(
        client: GMPClient, num_items_per_target, hosts, port_list_name, state='unassigned'):
    """
    Creates a set of targets.

    :param client: GMP client.
    :param num_items_per_target: number of hosts per target.
    :param hosts: hosts in the targets.
    :param port_list_name: targets' port list.
    :param state: targets' state.
    :return: list of names of created targets.
    """
    name = uuid.uuid4().hex

    targets = []
    for idx, sub_hosts in enumerate(
            [hosts[i:i + num_items_per_target] for i in range(0, len(hosts), num_items_per_target)]):
        result = client.create_target(
            name=f'{name}_{idx}', hosts=sub_hosts, port_list_name=port_list_name,
            state=state)
        targets.append(f'{name}_{idx}')
        logging.info('Create target %s: %s', f'{name}_{idx}', result.get('status_text'))

    return targets


def delete_tasks(
        client: GMPClient, task_name=None, states=['obsolete'], ultimate=False):
    """
    Deletes a set of tasks.

    :param task_name: name of the task to delete.
    :param states: the tasks in `states` will be deleted.
    :param ultimate: move to trash or delete permanently.
    :return: list of deleted tasks.
    """
    state_filter = create_comment('state', states)

    _filter = f'rows=-1 {state_filter}' if task_name is None else f'rows=-1 name={task_name} and {state_filter}'

    deleted_tasks = []
    for task in client.get_tasks(filter=_filter):
        _task_name = task.xpath('name/text()')[0]
        result = client.delete_task(name=_task_name, ultimate=ultimate)
        logging.info('Deleted task %s: %s', _task_name, result.get('status_text'))
        deleted_tasks.append(_task_name)

    return deleted_tasks


def delete_targets(client: GMPClient, target_name=None, states=['scanned'], ultimate=True):
    """
    Deletes a set of targets.

    :param target_name: name of the target to delete.
    :param states: the targets in `states` will be deleted.
    :param ultimate: move to trash or delete permanently.
    """
    state_filter = create_comment('state', states)

    _filter = f'rows=-1 {state_filter}' if target_name is None else f'rows=-1 name={target_name} and {state_filter}'

    deleted_targets = []
    for target in client.get_targets(filter=_filter):
        _target_name = target.xpath('name/text()')[0]
        if target.xpath('in_use/text()')[0] == "0":
            result = client.delete_target(name=_target_name, ultimate=ultimate)
            logging.info('Deleted target %s: %s', _target_name, result.get('status_text'))
        else:
            logging.info('Target %s is in use', _target_name)
        deleted_targets.append(_target_name)

    return deleted_targets


def create_scanners(
        client: GMPClient, num_scanners, scanner_name_prefix,
        scanner_host_prefix, scanner_service, credential):
    """
    Creates a set of scanners.

    :param num_scanners: number of the scanners to create.
    :param scanner_name_prefix: name prefix of the scanners to create.
    :param scanner_host_prefix: scanner host prefix of the scanners to create
    :param scanner_service: scanner service name, this is particular to statfulset pods.
    :param credential: credential to be used by the scanner to connect to GVMd.
    """
    for i in range(num_scanners):
        host = f'{scanner_host_prefix}{i}' if scanner_service == '' \
                else f'{scanner_host_prefix}{i}.{scanner_service}'
        result = client.create_scanner(
            name=f'{scanner_name_prefix}{i}',
            host=host,
            credential=credential)
        logging.info('Create scanner %s: %s', f'{scanner_name_prefix}{i}', result.get('status_text'))


def delete_scanners(
        client: GMPClient, num_scanners, scanner_name_prefix, ultimate=True):
    """
    Deletes a set of scanners.

    :param num_scanners: name of scanners to delete.
    :param scanner_name_prefix: used to form the scanner name.
    :param ultimate: move to trash or delete permanently.
    """
    for i in range(num_scanners):
        result = client.delete_scanner(name=f'{scanner_name_prefix}{i}', ultimate=ultimate)
        logging.info('Delete scanner %s: %s', f'{scanner_name_prefix}{i}', result.get('status_text'))


def assign_targets(
        client: GMPClient,  target_name=None, task_name=None,
        target_states=['unassigned'], task_states=['initialised'],
        next_target_state='assigned', next_task_state='has_target'):
    """
    Assign targets to tasks.

    :param target_name: name of target to assign.
    :param task_name: name of task to accept targets.
    :param target_states: targets in `target_states` will be assigned.
    :param task_states: tasks in `task_states` can accept targets.
    :param next_target_state: Next target state.
    :param next_task_state: Next task state.
    """
    target_state_filter = create_comment('state', target_states)
    task_state_filter = create_comment('state', task_states)

    target_filter = f'rows=-1 {target_state_filter}' \
        if target_name is None else f'rows=-1 name={target_name} and {target_state_filter}'
    task_filter = f'rows=-1 {task_state_filter}' \
        if task_name is None else f'rows=-1 name={task_name} and {task_state_filter}'

    tasks = client.get_tasks(filter=task_filter)

    for target in client.get_targets(filter=target_filter):
        target_name = target.xpath('name/text()')[0]
        available_task = tasks[0] if len(tasks) > 0 else None
        if available_task is None:
            break
        client.update_task_target(
            name=available_task.xpath('name/text()')[0], target_name=target_name)
        client.update_task_state(name=available_task.xpath('name/text()')[0], state=next_task_state)
        client.update_target_state(name=target_name, state=next_target_state)
        tasks.remove(available_task)
        logging.info('Target %s assigned to task %s', target_name, available_task.xpath('name/text()')[0])


def assign_tasks(
        client: GMPClient, task_name=None, scanner_name=None,
        task_states=['has_target'], next_task_state='has_scanner'):
    """
    Assign tasks to scanners.

    Only scanners with zero active tasks will accept new tasks.

    :param task_name: name of task to assign to scanner.
    :param scanner_name: scanners with name `scanner_name` will be added to scanners' filter.
    :param task_states: tasks in `task_states` will be assigned to scanners.
    :param next_task_state: Next task state.
    :return: `None` if no scanner is available.
    """
    active_tasks_per_scanner_dict = active_tasks_per_scanner(client, scanner_name)

    state_filter = create_comment('state', task_states)
    _filter = f'rows=-1 {state_filter}' if task_name is None else f'rows=-1 name={task_name} and {state_filter}'

    for task in client.get_tasks(filter=_filter):
        task_name = task.xpath('name/text()')[0]
        scanner_name = get_key_by_value(active_tasks_per_scanner_dict, 0)
        if scanner_name is None:
            logging.info('Cannot assign the task %s as no scanner is available', task_name)
            continue
        active_tasks_per_scanner_dict[scanner_name] += 1
        logging.info('Task %s will run on the scanner %s', task_name, scanner_name)
        client.update_task_scanner(name=task_name, scanner_name=scanner_name)
        client.update_task_state(name=task_name, state=next_task_state)


def start_tasks(
        client: GMPClient, task_name=None,
        states=['has_scanner'], next_task_state='started'):
    """
    Starts a set of tasks.

    :param task_name: name of the task to start.
    :param states: the tasks in `states` will be started.
    :param next_task_state: if task is started, assign it `next_task_state`.
    """
    state_filter = create_comment('state', states)

    _filter = f'rows=-1 {state_filter}' if task_name is None else f'rows=-1 name={task_name} and {state_filter}'

    for task in client.get_tasks(filter=_filter):
        task_name = task.xpath('name/text()')[0]
        result = client.start_task(name=task_name)
        logging.info('Starting task %s: %s', task_name, result.get('status_text'))
        client.update_task_state(name=task_name, state=next_task_state)


def get_results(
        client: GMPClient, task_name=None, task_states=['finished'],
        next_task_state='obsolete', next_target_state='scanned'):
    """
    Returns results in the last reports generated for each task in a task set.

    :param task_name: name of the task from which to get the scanned hosts.
    :param task_states: get results from the tasks in state`states`.
    :param next_task_state: next state of the task.
    :param next_target_state: next state of the target.
    :return: result objects.
    """
    results = []

    state_filter = create_comment('state', task_states)
    _filter = f'rows=-1 {state_filter}' if task_name is None else f'rows=-1 name={task_name} and {state_filter}'

    for task in client.get_tasks(filter=_filter):
        task_name = task.xpath('name/text()')[0]
        task_id = client.get_task_id(name=task_name)
        task_target = task.xpath('target/name/text()')[0]
        report_id = task.xpath('last_report/report')[0].get('id')
        task_results = client.get_results(
            filter=f'rows=-1 report_id={report_id} task_id={task_id}')

        logging.info(f'{len(task_results)} results returned by task {task_name}')

        results.extend(task_results)

        client.update_task_state(name=task_name, state=next_task_state)
        client.update_target_state(name=task_target, state=next_target_state)

    return results


def active_tasks_per_scanner(
        client: GMPClient, scanner_name=None,
        scanner_name_prefix=config['SCAN']['scanner_name_prefix'],
        num_scanners=config.getint('SCAN', 'num_scanners')):
    """
    Returns a dictionary containing number of active tasks per scanner.

    `active` tasks are those in status `Requested` or `Running` or  `Stop Requested`.

    :param scanner_name: if provided only consider scanner with `scanner_name`.
    :param scanner_name_prefix: check scanners with passed prefix.
    :param num_scanners: number of scanners to check.
    :return: dictionary.
    """
    # It has turned out that get_scanners(details=True) is very time consuming.
    # So falling back into doing it the classical way.
    tasks_per_scanner_dict = {}

    # Initialise tasks_per_scanner_dict
    # Assuming scanners with `scanner_name` or `{scanner_name_prefix}{i}` exist.
    if scanner_name is None:
        for i in range(num_scanners):
            tasks_per_scanner_dict[f'{scanner_name_prefix}{i}'] = 0
    else:
        tasks_per_scanner_dict[scanner_name] = 0

    for task in client.get_tasks(filter='status="Requested" status="Running" status="Stop Requested"'):
        if task.xpath('scanner/name/text()')[0] in tasks_per_scanner_dict:
            tasks_per_scanner_dict[task.xpath('scanner/name/text()')[0]] += 1

    return tasks_per_scanner_dict


def check_task_completion(
        client: GMPClient, task_name=None, states=['started'],
        task_finished_state='finished', task_failed_state='failed', task_stopped_state='stopped'):
    """
    Checks tasks completion status.

    :param task_name: name of the task to check its status.
    :param states: check tasks with a state in states.
    :param task_finished_state: state of finished tasks.
    :param task_failed_state: state of failed tasks.
    :param task_stopped_state: state of stopped tasks.
    """
    state_filter = create_comment('state', states)

    _filter = f'rows=-1 {state_filter}' if task_name is None else f'rows=-1 name={task_name} and {state_filter}'

    for task in client.get_tasks(filter=_filter):
        task_name = task.xpath('name/text()')[0]
        task_status = task.xpath('status/text()')[0]
        task_progress = task.xpath('progress/text()')[0]
        last_report_severity = error = state = None
        if task_status == 'Done':
            last_report_severity = task.xpath('last_report/report/severity/text()')[0]
            last_report_id = task.xpath('last_report/report')[0].get('id')
            if float(last_report_severity) >= 0.0 or float(last_report_severity) in [-1, -99.0]:
                state = task_finished_state
            else:
                state = task_failed_state
                last_report = client.get_report(report_id=last_report_id, details=True)
                error = last_report[0].xpath('report/errors/error/description/text()')[0]
        elif task_status == 'Stopped':
            state = task_stopped_state

        if state is not None:
            client.update_task_state(name=task_name, state=state)

        status_msg = (
            f'Task: {task_name} | Status: {task_status} | '
            f'Progress: {task_progress} | Severity: {last_report_severity} | ERROR: "{error}"'
        )

        if state in ['d/failed', 'd/stopped', 'failed', 'stopped']:
            logging.error(status_msg)
        else:
            logging.info(status_msg)


def initialise_discovery(client: GMPClient):
    """Creates port list and `discovery` scanner."""
    port_list = config['DISCOVERY']['port_list']
    port_range = config['DISCOVERY']['port_range']
    client.create_port_list(name=port_list, port_range=port_range)

    scanner_credential = config['DISCOVERY']['scanner_credential']
    client.create_credential(name=scanner_credential)

    name = config['DISCOVERY']['scanner_name']
    host = config['DISCOVERY']['scanner_host']

    client.create_scanner(name=name, host=host, credential=scanner_credential)


def initialise_scan(client: GMPClient):
    """Creates port list and `scan` scanners."""
    port_list = config['SCAN']['port_list']
    port_range = config['SCAN']['port_range']
    client.create_port_list(name=port_list, port_range=port_range)

    default_target = config['SCAN']['default_target']
    client.create_target(name=default_target, hosts=['0.0.0.0'], port_list_name=port_list)

    default_scanner_credential = config['SCAN']['default_scanner_credential']
    client.create_credential(name=default_scanner_credential)

    default_scanner_name = config['SCAN']['default_scanner_name']
    default_scanner_host = config['SCAN']['default_scanner_host']

    client.create_scanner(
        name=default_scanner_name, host=default_scanner_host, credential=default_scanner_credential)

    num_scanners = config.getint('SCAN', 'num_scanners')

    scanner_credential = config['SCAN']['scanner_credential']
    client.create_credential(name=scanner_credential)

    scanner_name_prefix = config['SCAN']['scanner_name_prefix']
    scanner_host_prefix = config['SCAN']['scanner_host_prefix']
    scanner_service = config['SCAN']['scanner_service']

    create_scanners(
        client, num_scanners, scanner_name_prefix,
        scanner_host_prefix, scanner_service, scanner_credential)


def run_discovery(client: GMPClient, sqlite_conn):
    """Runs discovery task."""
    discovery_task = config['DISCOVERY']['task_name']
    discovery_target = config['DISCOVERY']['target_name']
    port_list = config['DISCOVERY']['port_list']
    scanner_name = config['DISCOVERY']['scanner_name']
    config_name = config['DISCOVERY']['config']
    max_checks = config['DISCOVERY']['max_checks']
    max_hosts = config['DISCOVERY']['max_hosts']

    task_config = {'config_name': config_name, 'target_name': discovery_target,
                   'scanner_name': scanner_name,
                   'preferences': {'max_checks': max_checks, 'max_hosts': max_hosts}}

    check_task_completion(
        client, task_name=discovery_task, states=['d/started'],
        task_finished_state='d/finished', task_failed_state='d/failed', task_stopped_state='d/stopped')

    results = get_results(
        client, task_name=discovery_task, task_states=['d/finished'],
        next_task_state='d/obsolete', next_target_state='d/scanned')

    discovered_hosts = list(set([result.xpath('host/text()')[0] for result in results]))

    update_discovered_hosts(sqlite_conn, discovered_hosts)

    deleted_tasks = delete_tasks(client, task_name=discovery_task, ultimate=True, states=['d/obsolete'])
    deleted_targets = delete_targets(client, target_name=discovery_target, states=['d/scanned'])

    # If discovery task completed, and all the hosts with seen_up = 0
    # have been checked if alive, and `rerun_discovery` = true,
    # then set selected_for_discovery to 0
    if config['DISCOVERY'].getboolean('rerun_discovery') and \
            discovery_task in deleted_tasks and discovery_target in deleted_targets:
        reset_discovery_attribute(sqlite_conn)

    # Get the hosts that have not been selected for discovery or seen up, and
    # not selected for scan and not yet scanned.
    sub_hosts = get_hosts(
        sqlite_conn, [0], [0], [0], [0], num_records=config.getint('DISCOVERY', 'max_num_hosts'))

    result = client.create_target(
        name=discovery_target, hosts=sub_hosts, port_list_name=port_list, state='d/assigned')

    # If target has been created successfully
    if result.get('status') == '201':
        client.create_task(name=discovery_task, state='d/has_scanner', **task_config)
        for host in sub_hosts:
            update_host_attribute(sqlite_conn, 'selected_for_discovery', 1, host)

    start_tasks(client, task_name=discovery_task, states=['d/has_scanner'], next_task_state='d/started')


def run_scan(client: GMPClient, db_conn, pg_conn):
    """Runs scan tasks."""
    scanner_name = config['SCAN']['default_scanner_name']
    default_target = config['SCAN']['default_target']
    port_list = config['SCAN']['port_list']
    config_name = config['SCAN']['config']
    max_checks = config['SCAN']['max_checks']
    max_hosts = config['SCAN']['max_hosts']
    num_hosts_per_target = config.getint('SCAN', 'num_hosts_per_target')

    default_task_config = {'config_name': config_name,
                           'target_name': default_target,
                           'scanner_name': scanner_name,
                           'preferences': {'max_checks': max_checks, 'max_hosts': max_hosts}}

    check_task_completion(client)

    results = get_results(client)
    export_results(pg_conn, results)
    scanned_hosts = list(set([result.xpath('host/text()')[0] for result in results]))

    update_discovered_hosts(db_conn, scanned_hosts, False)

    delete_tasks(client, ultimate=True)
    delete_targets(client)

    # Get the hosts that have been seen up, not selected for scan and not yet scanned.
    sub_hosts = get_hosts(
        db_conn, [0, 1], [1], [0], [0], num_records=config.getint('SCAN', 'max_num_hosts'))
    for host in sub_hosts:
        update_host_attribute(db_conn, 'selected_for_scan', 1, host)

    targets = create_targets(client, num_hosts_per_target, sub_hosts, port_list)
    create_tasks(client, len(targets), **default_task_config)

    assign_targets(client)

    assign_tasks(client)

    start_tasks(client)
