# config.py
import os

class Config:
    # MySQL configuration from Render environment variables
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'mysql123')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'w_mess_app')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))  # default MySQL port

    # Flask secret key (set this in Render as well)
    SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey')
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'messsiberia@gmail.com'        # your Gmail
    MAIL_PASSWORD = 'khbb aspa fumw fdjj' # App Password you generated
    MAIL_DEFAULT_SENDER = 'messsiberia@gmail.com'
