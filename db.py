import sqlite3

# =====================================================
# DATABASE CONNECTION
# =====================================================

conn = sqlite3.connect(
    "gnn_ids.db",
    check_same_thread=False
)

cursor = conn.cursor()

# =====================================================
# FEEDBACK TABLE
# =====================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS feedbacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    feedback TEXT
)
""")

# =====================================================
# UPLOAD HISTORY TABLE
# =====================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    filename TEXT,
    threat_percent REAL,
    upload_time TEXT
)
""")

conn.commit()

# =====================================================
# SAVE FEEDBACK
# =====================================================

def save_feedback(username, feedback):

    cursor.execute(
        """
        INSERT INTO feedbacks
        (username, feedback)
        VALUES (?, ?)
        """,
        (
            username,
            feedback
        )
    )

    conn.commit()

# =====================================================
# SAVE UPLOAD HISTORY
# =====================================================

def save_upload_history(
    username,
    filename,
    threat_percent,
    upload_time
):

    cursor.execute(
        """
        INSERT INTO uploads
        (
            username,
            filename,
            threat_percent,
            upload_time
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            filename,
            threat_percent,
            upload_time
        )
    )

    conn.commit()

# =====================================================
# GET UPLOAD HISTORY
# =====================================================

def get_upload_history():

    cursor.execute(
        """
        SELECT
            username,
            filename,
            threat_percent,
            upload_time
        FROM uploads
        ORDER BY id DESC
        """
    )

    return cursor.fetchall()