from psycopg2 import sql

from .create_user_db_connection import create_user_db_connection

def disable_user_totp(user_id):
    conn = create_user_db_connection()
    cur = conn.cursor()

    update_query = sql.SQL("""
        UPDATE public.userapi_account
        SET totp_enabled = false
        WHERE id = %s;
    """)

    cur.execute(update_query, [user_id])
    conn.commit()

    # Check if any rows were updated
    if cur.rowcount == 1:
        updated = True
    else:
        updated = False

    cur.close()
    conn.close()

    return updated