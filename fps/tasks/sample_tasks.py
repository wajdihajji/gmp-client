"""
We set here the tasks we want to run against gvmd.
"""
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from gvm.xml import pretty_print

def get_tasks(hostname, gmp_username, gmp_password):
    """
    Get names of tasks created on GVM.

    :param hostname: gvmd hostname.
    :param gmp_username: GMP username to use to access gvmd via TLS.
    :param gmp_password: GMP password to use to access gvmd via TLS.
    """
    connection = TLSConnection(hostname=hostname)
    transform = EtreeTransform()

    with Gmp(connection, transform=transform) as gmp:
        # Login
        gmp.authenticate(gmp_username, gmp_password)

        # Retrieve all tasks
        tasks = gmp.get_tasks()

        # Get names of tasks
        task_names = tasks.xpath('task/name/text()')
        pretty_print(task_names)
