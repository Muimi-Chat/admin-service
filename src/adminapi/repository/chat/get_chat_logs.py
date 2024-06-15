from psycopg2 import sql
from .create_chat_db_connection import create_chat_db_connection

def get_chat_logs():
    conn = create_chat_db_connection()
    cur = conn.cursor()

    query = sql.SQL("""
        SELECT id, content, severity, at as created_at
        FROM public.log
        ORDER BY at DESC;
    """)

    cur.execute(query, [])

    column_names = [desc[0] for desc in cur.description]
    results = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    conn.close()

    return results