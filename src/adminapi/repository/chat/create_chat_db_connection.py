import os
import psycopg2

def create_chat_db_connection():
    conn = psycopg2.connect(
        dbname=os.environ.get('CHAT_DB_NAME', 'postgres'),
        user=os.environ.get('CHAT_DB_USERNAME', 'postgres'),
        password=os.environ.get('CHAT_DB_PASSWORD', 'postgres'),
        host='chat-db',
        port='5432'
    )
    return conn