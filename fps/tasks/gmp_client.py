"""
GMP client class and functions to be used by the friendly probing suite.
"""
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print


# Decorator for GVM authentication
def authenticate(func):
    def wrapper(*argv, **kwargs):
        with Gmp(argv[0].tls_connection, transform=EtreeTransform()) as gmp:
            # Login
            gmp.authenticate(argv[0].gmp_username, argv[0].gmp_password)

            kwargs['gmp'] = gmp

            return func(*argv, **kwargs)
    return wrapper


class GMPClient(object):
    """
    Creates a TLS connection to and runs tasks on a remote GVM daemon.
    """
    def __init__(self, gvm_hostname, gvm_port, gmp_username, gmp_password, certs_path=None):
        self.gvm_hostname = gvm_hostname
        self.gvm_port = gvm_port
        self.gmp_username = gmp_username
        self.gmp_password = gmp_password
        self.certs_path = certs_path
        self.tls_connection = None

    def __call__(self):
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

            # Prints the XML in beautiful form
            pretty_print(version)

    @authenticate
    def get_tasks(self, gmp):
        """Returns tasks information as an XML object."""
        return gmp.get_tasks()

    @authenticate
    def get_scanners(self, gmp, _filter=None):
        """Returns scanners information as an XML object."""
        return gmp.get_scanners(filter=_filter)

    @authenticate
    def get_credentials(self, gmp, _filter=None):
        """Returns credentials information as an XML object."""
        return gmp.get_credentials(filter=_filter)

    def create_credential(self, gmp, name, certs_path='/certs'):
        """
        Creates a `CLIENT_CERTIFICATE` credential.

        :param name: credential name.
        :param certs_path: path where to find cert.pem and key.pem files.
        """
        with open(f'{certs_path}/cert.pem', 'r') as reader:
            cert = reader.read()

        with open(f'{certs_path}/key.pem', 'r') as reader:
            private_key = reader.read()

        credential_type = gmp.types.CredentialType.CLIENT_CERTIFICATE

        return gmp.create_credential(
            name=name, credential_type=credential_type, certificate=cert, private_key=private_key)

    def create_scanner(self, gmp, name, host, credential='remote-scanner', port=9390, certs_path='/certs'):
        """
        Creates a remote OpenVAS scanner connected to GVMd through TLS connection.

        :param name: scanner's name.
        :param host: scanner's hostname.
        :param credential: CLIENT_CERTIFICATE credential to use in the TLS connection.
        :param certs_path: path where to find cacert.pem file.
        """
        get_credentials_response = self.get_credentials(gmp, _filter=f'name={credential}')
        credentials_xml = get_credentials_response.xpath('credential')

        with open(f'{certs_path}/cacert.pem', 'r') as reader:
            ca_pub = reader.read()

        scanner_type = gmp.types.ScannerType.OPENVAS_SCANNER_TYPE

        return gmp.create_scanner(
            name=name, host=host, port=port, scanner_type=scanner_type,
            credential_id=credentials_xml[0].get('id'), ca_pub=ca_pub)

    def delete_scanner(self, gmp, host, ultimate=False):
        """
        Deletes an OpenVAS scanner.

        :param host: hostname of the scanner to delete.
        :param ultimate: Move to trash of just delete.
        """
        get_scanners_response = self.get_scanners(gmp, _filter=f'host={host}')
        scanners_xml = get_scanners_response.xpath('scanner')

        if len(scanners_xml) == 0:
            print(f'Scanner not found. Host: {host}')
            return True

        return gmp.delete_scanner(scanner_id=scanners_xml[0].get('id'), ultimate=ultimate)

    def function(self):
        with Gmp(self.tls_connection, transform=EtreeTransform()) as gmp:
            # Login
            gmp.authenticate(self.gmp_username, self.gmp_password)

    def create_target(self, name, hosts, port_range, port_list_id=None):
        """
        Creates target.

        :param name: target name.
        :param hosts: hosts of the target.
        :param port_range: port range of the target.
        :param port_list_id: port list of the target.
        """
        return gmp.create_target(name, hosts=hosts, port_range=port_range, port_list_id=port_list_id)

    def create_port_list(self, name, port_range):
        """
        Creates a port list.

        :param name: port list name.
        :param port_range: Port list ranges e.g. `"T: 1-1234"` for tcp port 1 - 1234
        """
        return gmp.create_port_list(name, port_range)
