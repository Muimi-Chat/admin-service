from psycopg2 import sql

from .create_user_db_connection import create_user_db_connection

def get_user_by_id(user_id):
    conn = create_user_db_connection()
    cur = conn.cursor()

    query = sql.SQL("""
        SELECT id, username, encrypted_email, created_at, authenticated, status, totp_enabled
        FROM public.userapi_account
        WHERE id = %s;
    """)

    cur.execute(query, [user_id])

    # Fetching the first (and only) result, or None if no result
    result = cur.fetchone()

    if result:
        column_names = [desc[0] for desc in cur.description]
        user_details = dict(zip(column_names, result))
    else:
        user_details = None

    cur.close()
    conn.close()

    return user_details
