"""
Invoke the fps routines.
"""
import configparser

from tasks.sample_tasks import get_tasks

def main():
    """
    Test function.
    """
    config = configparser.ConfigParser()
    config.read('config.ini')

    print("Running FPS routines")
    get_tasks(
        config['DEFAULT']['gvmd_hostname'],
        config['DEFAULT']['gmp_username'], config['DEFAULT']['gmp_password'])

if __name__ == '__main__':
    main()
