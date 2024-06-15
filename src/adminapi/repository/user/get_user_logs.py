from psycopg2 import sql
from .create_user_db_connection import create_user_db_connection

def get_user_logs():
    conn = create_user_db_connection()
    cur = conn.cursor()

    query = sql.SQL("""
        SELECT id, content, created_at, severity
        FROM public.userapi_servicelog
        ORDER BY created_at DESC;
    """)

    cur.execute(query, [])

    column_names = [desc[0] for desc in cur.description]
    results = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    conn.close()

    return results

