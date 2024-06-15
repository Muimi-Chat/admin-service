from psycopg2 import sql
from .create_user_db_connection import create_user_db_connection

def get_users():
    conn = create_user_db_connection()
    cur = conn.cursor()

    query = sql.SQL("""
        SELECT id, username, encrypted_email, created_at, authenticated, status, totp_enabled
        FROM public.userapi_account
        ORDER BY id;
    """)

    cur.execute(query, [])

    column_names = [desc[0] for desc in cur.description]
    results = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    conn.close()

    return results

