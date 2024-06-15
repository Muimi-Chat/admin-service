import os
import psycopg2

def create_user_db_connection():
    conn = psycopg2.connect(
        dbname=os.environ.get('USER_DB_NAME', 'postgres'),
        user=os.environ.get('USER_DB_USERNAME', 'postgres'),
        password=os.environ.get('USER_DB_PASSWORD', 'postgres'),
        host='user-database',
        port='5432'
    )
    return conn