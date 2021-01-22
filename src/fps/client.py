"""
GMP client class to run operations on GVM daemon.
"""
import configparser
import logging
import os
from functools import wraps

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

config = configparser.ConfigParser()
config.read('config.ini')


def authenticate(func):
    """Decorator to authenticate against a GVM daemon."""
    @wraps(func)
    def wrapper(*argv, **kwargs):
        with Gmp(argv[0].tls_connection, transform=EtreeTransform()) as gmp:
            kwargs['gmp'] = gmp

            # Login
            gmp.authenticate(argv[0].gmp_username, argv[0].gmp_password)

            return func(*argv, **kwargs)
    return wrapper


class GMPClient(object):
    """
    GMP Client class to connect to GVM daemon and run operations on.
    """
    def __init__(self):
        self.gvm_hostname = config['GVM']['gvmd_hostname']
        self.gvm_port = config.getint('GVM', 'gvmd_port')
        self.certs_path = config['GVM']['certs_path']
        self.gmp_username = os.getenv('GMP_USERNAME')
        self.gmp_password = os.getenv('GMP_PASSWORD')
        self.tls_connection = self._create_tls_connection()

    def _create_tls_connection(self):
        """Returns a TLS connection object."""
        if self.certs_path is None:
            return TLSConnection(hostname=self.gvm_hostname)

        return TLSConnection(
            certfile=f'{self.certs_path}/cert.pem', cafile=f'{self.certs_path}/cacert.pem',
            keyfile=f'{self.certs_path}/key.pem', hostname=self.gvm_hostname, port=self.gvm_port)

    def get_version(self):
        """Returns GVMd version."""
        with Gmp(self.tls_connection, transform=EtreeTransform()) as gmp:
            version = gmp.get_version()
            logging.info('GMP version: %s', version.xpath('version/text()')[0])

            return version

    @authenticate
    def get_tasks(self, gmp, task_config=None, *argv, **kwargs):
        """Returns tasks."""
        tasks = gmp.get_tasks(*argv, **kwargs).xpath('task')

        if task_config is not None:
            return [task for task in tasks if task.xpath('config/name/text()')[0] == task_config]

        return tasks

    @authenticate
    def get_report(self, gmp, report_id, *argv, **kwargs):
        """Returns report having `report_id`."""
        return gmp.get_report(report_id=report_id, *argv, **kwargs)

    @authenticate
    def get_results(self, gmp, *argv, **kwargs):
        """Returns results."""
        return gmp.get_results(*argv, **kwargs).xpath('result')

    @authenticate
    def get_scanners(self, gmp, *argv, **kwargs):
        """Returns scanners."""
        return gmp.get_scanners(*argv, **kwargs).xpath('scanner')

    @authenticate
    def get_credentials(self, gmp, *argv, **kwargs):
        """Returns credentials."""
        return gmp.get_credentials(*argv, **kwargs).xpath('credential')

    @authenticate
    def get_port_list_id(self, gmp, name):
        """Returns ID of port list having `name`."""
        _port_lists = self.get_port_lists(filter=f'name="{name}"')
        return _port_lists[0].get('id') if len(_port_lists) > 0 else None

    @authenticate
    def get_port_lists(self, gmp, *argv, **kwargs):
        """
        Returns port lists.

        :return: `get_port_lists`'s result.
        """
        return gmp.get_port_lists(*argv, **kwargs).xpath('port_list')

    @authenticate
    def get_targets(self, gmp, *argv, **kwargs):
        """
        Returns targets.

        :return: `get_targets`'s result.
        """
        return gmp.get_targets(*argv, **kwargs).xpath('target')

    @authenticate
    def get_config_id(self, gmp, name):
        """Returns config ID."""
        _configs = self.get_configs(filter=f'name="{name}"')
        return _configs[0].get('id') if len(_configs) > 0 else None

    @authenticate
    def get_scanner_id(self, gmp, name):
        """Returns scanner ID."""
        _scanners = self.get_scanners(filter=f'name="{name}"')
        return _scanners[0].get('id') if len(_scanners) > 0 else None

    @authenticate
    def get_target_id(self, gmp, name):
        """Returns target ID."""
        _targets = self.get_targets(filter=f'name="{name}"')
        return _targets[0].get('id') if len(_targets) > 0 else None

    @authenticate
    def get_task_id(self, gmp, name):
        """Returns task ID."""
        _tasks = self.get_tasks(filter=f'name="{name}"')
        return _tasks[0].get('id') if len(_tasks) > 0 else None

    @authenticate
    def get_configs(self, gmp, *argv, **kwargs):
        """Returns scanning configurations."""
        return gmp.get_configs(*argv, **kwargs).xpath('config')

    @authenticate
    def create_credential(self, gmp, name, *args, **kwargs):
        """
        Creates a `CLIENT_CERTIFICATE` credential.

        :param name: credential name.
        :return: `True` if credential exists, otherwise, `gmp.create_credential()`'s result.
        """
        if len(self.get_credentials(filter=f'name="{name}"')) > 0:
            logging.info('Credential %s already exists', name)
            return {'status_text': 'Credential already exists'}

        with open(f'{self.certs_path}/cert.pem', 'r') as reader:
            certificate = reader.read()
            kwargs['certificate'] = certificate

        with open(f'{self.certs_path}/key.pem', 'r') as reader:
            private_key = reader.read()
            kwargs['private_key'] = private_key

        kwargs['name'] = name
        kwargs['credential_type'] = gmp.types.CredentialType.CLIENT_CERTIFICATE

        return gmp.create_credential(*args, **kwargs)

    @authenticate
    def create_scanner(
            self, gmp, name, host, credential, port=9391, **kwargs):
        """
        Creates a scanner.

        :param name: scanner name.
        :param host: scanner hostname.
        :param credential: `CLIENT_CERTIFICATE` credential.
        :return: `True` if scanner already exists, `False` if missing info, otherwise, `create_scanner`'s result.
        """
        if self.get_scanner_id(name=name) is not None:
            logging.info('Scanner %s already exists', name)
            return {'status_text': 'Scanner already exists'}

        if len(self.get_credentials(filter=f'name={credential}')) == 0:
            logging.warn('Credential %s does not exist', credential)
            return {'status_text': 'Credential does not exist'}

        credential_id = self.get_credentials(filter=f'name={credential}')[0].get('id')

        with open(f'{self.certs_path}/cacert.pem', 'r') as reader:
            ca_pub = reader.read()

        return gmp.create_scanner(
            name=name, host=host, port=port, scanner_type=gmp.types.ScannerType.OPENVAS_SCANNER_TYPE,
            credential_id=credential_id, ca_pub=ca_pub, **kwargs)

    @authenticate
    def delete_scanner(self, gmp, name, ultimate=False):
        """
        Deletes a scanner.

        :param name: scanner name.
        :param ultimate: move to trash or delete permanently.
        """
        scanner_id = self.get_scanner_id(name=name)
        if scanner_id is None:
            logging.info('Scanner %s does not exist', name)
            return {'status_text': 'Scanner does not exist'}

        return gmp.delete_scanner(scanner_id=scanner_id, ultimate=ultimate)

    @authenticate
    def create_target(self, gmp, name, hosts, port_list_name, port_range=None, state=None, **kwargs):
        """
        Creates a target.

        :param name: name.
        :param hosts: hosts.
        :param port_list_name: port list name.
        :param port_range:port range.
        :param state: state attribute in the target's comment field.
        :return: `None` if missing info, otherwise, `create_target`'s result.
        """
        target_id = self.get_target_id(name=name)
        if target_id is not None:
            logging.info('Target %s already exists', name)
            return {'status_text': 'Target already exists'}

        if len(hosts) == 0:
            logging.info('No hosts provided to create the target %s', name)
            return {'status_text': 'No hosts'}

        port_list_id = self.get_port_list_id(name=port_list_name)
        if port_list_id is None:
            logging.info('Port list %s does not exist', port_list_name)
            return {'status_text': 'Port list does not exist'}

        comment = "" if state is None else f'state:{state}'

        return gmp.create_target(
            name, hosts=hosts, port_range=port_range, port_list_id=port_list_id, comment=comment, **kwargs)

    @authenticate
    def update_target_state(self, gmp, name, state):
        """
        Updates target's state attribute in comment field.

        :param name: target name.
        :param state: new state.
        :return: `False` if target does not exist, otherwise `modify_target`s result.
        """
        target_id = self.get_target_id(name=name)
        if target_id is None:
            logging.info('Target %s does not exist', name)
            return {'status_text': 'Target does not exist'}

        return gmp.modify_target(target_id=target_id, comment=f'state:{state}')

    @authenticate
    def create_port_range(self, gmp, port_list_name, start, end, protocol='TCP'):
        """
        Creates a port range.

        :param port_list_name: port list name to add the port range to.
        :param start: port range start.
        :param end: port range end.
        :param protocol: port range protocol. Default: TCP
        :return: `False` if no port list, otherwise, `create_port_range`'s result.
        """
        port_list_id = self.get_port_list_id(name=port_list_name)
        if port_list_id is None:
            logging.info('Port list %s does not exist', port_list_name)
            return {'status_text': 'Port list does not exist'}

        port_range_type = getattr(gmp.types.PortRangeType, protocol)

        return gmp.create_port_range(
            port_list_id=port_list_id, start=start, end=end, port_range_type=port_range_type)

    @authenticate
    def create_port_list(self, gmp, name, port_range):
        """
        Creates a port list.

        :param name: port list name.
        :param port_range: port list ranges e.g. `"T: 1-1234"` for tcp port 1 - 1234
        :return: `True` if port list already exists, otherwise, `create_port_list`'s result.
        """
        port_list_id = self.get_port_list_id(name=name)
        if port_list_id is not None:
            logging.info('Port list %s already exists', name)
            return {'status_text': 'Port list already exists'}

        return gmp.create_port_list(name, port_range)

    @authenticate
    def create_task(self, gmp, name, config_name, target_name, scanner_name, preferences, state, **kwargs):
        """
        Creates a task.

        :param name: task name.
        :param config_name: task configuration.
        :param target_name: task's target.
        :param scanner_name: task's scanner.
        :param preferences: task's preferences.
        :param state: state attribute in task's comment field.
        :return: `True` if task already exists, `False` if missing info, `create_task`'s result, otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is not None:
            logging.info('Task %s already exists', name)
            return {'status_text': 'Task already exists'}

        config_id = self.get_config_id(name=config_name)
        if config_id is None:
            logging.info('Config %s does not exist', config_name)
            return {'status_text': 'Task Config does not exist'}

        target_id = self.get_target_id(name=target_name)
        if target_id is None:
            logging.info('Target %s does not exist', target_name)
            return {'status_text': 'Target does not exist'}

        scanner_id = self.get_scanner_id(name=scanner_name)
        if scanner_id is None:
            logging.info('Scanner %s does not exist', scanner_name)
            return {'status_text': 'Scanner does not exist'}

        return gmp.create_task(
            name=name, config_id=config_id, target_id=target_id, scanner_id=scanner_id,
            preferences=preferences, comment=f'state:{state}', **kwargs)

    @authenticate
    def modify_task(self, gmp, name, config_name, target_name, scanner_name, preferences):
        """
        Modifies a task.

        :param name: task name.
        :param config_name: task configuration.
        :param target_name: task's target.
        :param scanner_name: task's scanner.
        :param preferences: task's preferences.
        :param state: state attribute in task's comment field.
        :return: `False` if missing info, `modify_task`'s result, otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is None:
            logging.info('Task %s does not exist', name)
            return {'status_text': 'Task does not exist'}

        config_id = self.get_config_id(name=config_name)
        if config_id is None:
            logging.info('Config %s does not exist', config_name)
            return {'status_text': 'Task Config does not exist'}

        target_id = self.get_target_id(name=target_name)
        if target_id is None:
            logging.info('Target %s does not exist', target_name)
            return {'status_text': 'Target does not exist'}

        scanner_id = self.get_scanner_id(name=scanner_name)
        if scanner_id is None:
            logging.info('Scanner %s does not exist', scanner_name)
            return {'status_text': 'Scanner does not exist'}

        return gmp.modify_task(
            task_id=task_id, config_id=config_id,
            target_id=target_id, scanner_id=scanner_id, preferences=preferences)

    @authenticate
    def update_task_state(self, gmp, name, state):
        """
        Updates state attribute in task's comment field.

        :param name: task name.
        :param state: new task name.
        :return: `False` if task does not exist, `modify_task`'s result otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is None:
            logging.info('Task %s does not exist', name)
            return {'status_text': 'Task does not exist'}

        return gmp.modify_task(task_id=task_id, comment=f'state:{state}')

    @authenticate
    def update_task_scanner(self, gmp, name, scanner_name):
        """
        Updates task's scanner.

        :param name: task name.
        :param scanner_name: scanner name.
        :return: `False` if missing info, `modify_task`'s result otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is None:
            logging.info('Task %s does not exist', name)
            return {'status_text': 'Task does not exist'}

        scanner_id = self.get_scanner_id(name=scanner_name)
        if scanner_id is None:
            logging.info('Scanner %s does not exist', scanner_name)
            return {'status_text': 'Scanner does not exist'}

        return gmp.modify_task(task_id=task_id, scanner_id=scanner_id)

    @authenticate
    def update_task_target(self, gmp, name, target_name):
        """
        Updates task's target.

        :param name: task name.
        :param scanner_name: scanner name.
        :return: `False` if missing info, `modify_task`'s result otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is None:
            logging.info('Task %s does not exist', name)
            return {'status_text': 'Task does not exist'}

        target_id = self.get_target_id(name=target_name)
        if target_id is None:
            logging.info('Target %s does not exist', target_name)
            return {'status_text': 'Target does not exist'}

        return gmp.modify_task(task_id=task_id, target_id=target_id)

    @authenticate
    def delete_task(self, gmp, name, ultimate=False):
        """
        Deletes a task.

        :param name: task name.
        :param ultimate: Move to trash or delete permanently.
        :return: `True` if task does not exist, `delete_task`'s result otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is None:
            logging.info('Task %s does not exist', name)
            return {'status_text': 'Task does not exist'}

        return gmp.delete_task(task_id=task_id, ultimate=ultimate)

    @authenticate
    def delete_target(self, gmp, name, ultimate=False):
        """
        Deletes a target.

        :param name: target name.
        :param ultimate: Move to trash or delete permanently.
        :return: `True` if target does not exist, `delete_target`'s result otherwise.
        """
        target_id = self.get_target_id(name=name)
        if target_id is None:
            logging.info('Target %s does not exist', name)
            return {'status_text': 'Target does not exist'}

        return gmp.delete_target(target_id=target_id, ultimate=ultimate)

    @authenticate
    def start_task(self, gmp, name):
        """
        Starts a task.

        :param name: task name.
        :return: `False` if task does not exist, `start_task`'s result otherwise.
        """
        task_id = self.get_task_id(name=name)
        if task_id is None:
            logging.info('Task %s does not exist', name)
            return {'status_text': 'Task does not exist'}

        return gmp.start_task(task_id=task_id)
