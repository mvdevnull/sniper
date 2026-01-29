import os
import yaml

def get_db_config():
    """
    Read database configuration from Metasploit's database.yml
    Returns a connection string for psycopg2
    """
    msf_config_path = '/usr/share/metasploit-framework/config/database.yml'

    try:
        with open(msf_config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Get production or development config
        db_config = config.get('production', config.get('development', {}))

        return {
            'dbname': db_config.get('database', 'msf'),
            'user': db_config.get('username', 'msf'),
            'host': db_config.get('host', 'localhost'),
            'port': db_config.get('port', 5432),
            'password': db_config.get('password', '')
        }
    except FileNotFoundError:
        # Fallback to default MSF config
        return {
            'dbname': 'msf',
            'user': 'msf',
            'host': 'localhost',
            'port': 5432,
            'password': ''
        }

def get_connection_string():
    """Get psycopg2 connection string"""
    config = get_db_config()
    return f"dbname='{config['dbname']}' user='{config['user']}' host='{config['host']}' port='{config['port']}' password='{config['password']}'"

# Flask configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sniper-web-frontend-dev-key')
    DEBUG = os.environ.get('FLASK_DEBUG', True)

# Authentication credentials
AUTH_USERNAME = 'tester'
AUTH_PASSWORD = 'tester'
