from psycopg2 import sql

from .create_user_db_connection import create_user_db_connection

def set_user_status(user_id, status):
    conn = create_user_db_connection()
    cur = conn.cursor()

    update_query = sql.SQL("""
        UPDATE public.userapi_account
        SET status = %s
        WHERE id = %s;
    """)

    cur.execute(update_query, [status, user_id])
    conn.commit()

    # Check if any rows were updated
    if cur.rowcount == 1:
        updated = True
    else:
        updated = False

    cur.close()
    conn.close()

    return updated