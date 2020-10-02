"""
We set here the tasks we want to run against gvmd.
"""
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print


def create_tls_connection(gvm_hostname):
    """
    Creates TLS connection to GVM.

    :param gvm_hostname: GVM hostname.
    """
    # TODO: error handling
    return TLSConnection(hostname=gvm_hostname)

def get_version(connection):
    """
    Gets GVMd version.
    """
    with Gmp(connection, transform=EtreeTransform()) as gmp:
        # Retrieve GMP version supported by the remote daemon
        version = gmp.get_version()

        # Prints the XML in beautiful form
        pretty_print(version)

def get_tasks(connection, gmp_username, gmp_password):
    """
    Get names of tasks created on GVM.

    :param gvm_hostname: gvmd hostname.
    :param gmp_username: GMP username to use to access gvmd via TLS.
    :param gmp_password: GMP password to use to access gvmd via TLS.
    """
    with Gmp(connection, transform=EtreeTransform()) as gmp:
        # Login
        gmp.authenticate(gmp_username, gmp_password)

        # Retrieve all tasks
        tasks = gmp.get_tasks()

        # Get names of tasks
        task_names = tasks.xpath('task/name/text()')
        pretty_print(task_names)
