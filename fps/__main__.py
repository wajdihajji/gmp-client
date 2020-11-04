"""
Calling the main function.
"""
import configparser

from tasks import gmp_client


def main():
    """
    Test function.
    """
    config = configparser.ConfigParser()
    config.read('config.ini')

    gvm_hostname = config['DEFAULT']['gvmd_hostname']
    gmp_username = config['DEFAULT']['gmp_username']
    gmp_password = config['DEFAULT']['gmp_password']

    client = gmp_client.GMPClient(gvm_hostname, 9390, gmp_username, gmp_password, certs_path='/certs')

    # Create a connection
    client()

    # Get GVMd version
    client.get_version()

    # Get tasks created on GVMd
    get_tasks_response = client.get_tasks()
    for task in get_tasks_response.xpath('task'):
        print(task.xpath('name/text()'))

    # Get sanners.
    get_scanners_response = client.get_scanners()
    for scanner in get_scanners_response.xpath('scanner'):
        print(scanner.xpath('name/text()'))


if __name__ == '__main__':
    main()
