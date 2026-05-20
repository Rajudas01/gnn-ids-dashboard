import sqlite3
import bcrypt

# =====================================================
# DATABASE
# =====================================================

conn = sqlite3.connect(
    "gnn_ids.db",
    check_same_thread=False
)

cursor = conn.cursor()

# =====================================================
# USERS TABLE
# =====================================================

cursor.execute("""

CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT UNIQUE,

    password BLOB,

    role TEXT
)

""")

conn.commit()

# =====================================================
# CREATE USER
# =====================================================

def create_user(

    username,
    password,
    role="Analyst"
):

    try:

        hashed_password = bcrypt.hashpw(

            password.encode("utf-8"),

            bcrypt.gensalt()
        )

        cursor.execute(

            """

            INSERT INTO users
            (username, password, role)

            VALUES (?, ?, ?)

            """,

            (
                username,
                hashed_password,
                role
            )
        )

        conn.commit()

        return True

    except:

        return False

# =====================================================
# LOGIN USER
# =====================================================

def login_user(

    username,
    password
):

    cursor.execute(

        """

        SELECT password, role
        FROM users
        WHERE username=?

        """,

        (username,)
    )

    user = cursor.fetchone()

    if user:

        stored_password = user[0]

        role = user[1]

        if bcrypt.checkpw(

            password.encode("utf-8"),

            stored_password
        ):

            return role

    return None