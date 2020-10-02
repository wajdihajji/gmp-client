"""
Invoke the fps routines.
"""
import configparser

from tasks.sample_tasks import create_tls_connection, get_version, get_tasks

def main():
    """
    Test function.
    """
    config = configparser.ConfigParser()
    config.read('config.ini')

    print("Running FPS routines...")
    connection = create_tls_connection(config['DEFAULT']['gvmd_hostname'])

    print("Get GVMd version:")
    get_version(connection)

    print("Get GVM tasks:")
    get_tasks(connection,
        config['DEFAULT']['gmp_username'], config['DEFAULT']['gmp_password'])

if __name__ == '__main__':
    main()
