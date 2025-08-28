# config.py
import os

class Config:
    # MySQL configuration from Render environment variables
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'yamanote.proxy.rlwy.net')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'gpcMenvBLdOPPqHfbYDpXJPJiVlMXyaV')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'mess_app')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))  # default MySQL port

    # Flask secret key (set this in Render as well)
    SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey')
