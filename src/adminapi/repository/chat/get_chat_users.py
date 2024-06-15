from psycopg2 import sql
from .create_chat_db_connection import create_chat_db_connection

def get_chat_users():
    conn = create_chat_db_connection()
    cur = conn.cursor()

    query = sql.SQL("""
        SELECT id, token, free_token_usage
        FROM public.account
        ORDER BY id;
    """)

    cur.execute(query, [])

    column_names = [desc[0] for desc in cur.description]
    results = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    conn.close()

    return results