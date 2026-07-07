import sqlite3
import os

# ==========================================================
# DATABASE CONFIGURATION
# ==========================================================

DATABASE_PATH = "database/passwords.db"
COMMON_PASSWORDS_FILE = "database/common_passwords.txt"

# ==========================================================
# CREATE DATABASE DIRECTORY
# ==========================================================

os.makedirs("database", exist_ok=True)

# ==========================================================
# CONNECT DATABASE
# ==========================================================

connection = sqlite3.connect(DATABASE_PATH)
cursor = connection.cursor()

# ==========================================================
# COMMON PASSWORDS TABLE
# ==========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS common_passwords (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    password TEXT UNIQUE NOT NULL

)
""")

# ==========================================================
# AUDIT LOGS TABLE
# ==========================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL,

    password_hash TEXT NOT NULL,

    password_length INTEGER NOT NULL,

    has_uppercase INTEGER NOT NULL,

    has_lowercase INTEGER NOT NULL,

    has_digit INTEGER NOT NULL,

    has_special INTEGER NOT NULL,

    is_common INTEGER NOT NULL,

    compliance_score INTEGER NOT NULL,

    result TEXT NOT NULL,

    remarks TEXT,

    audit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

)
""")

# ==========================================================
# IMPORT COMMON PASSWORDS
# ==========================================================

if os.path.exists(COMMON_PASSWORDS_FILE):

    with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as file:

        passwords = [(line.strip(),) for line in file if line.strip()]

    cursor.executemany(
        """
        INSERT OR IGNORE INTO common_passwords(password)
        VALUES (?)
        """,
        passwords
    )

# ==========================================================
# COMMIT & CLOSE
# ==========================================================

connection.commit()
connection.close()

print("=" * 55)
print(" Password Policy Compliance Auditor")
print("=" * 55)
print("Database initialized successfully.")
print("Database :", DATABASE_PATH)
print("Common passwords imported successfully.")
print("Audit Logs table ready.")
print("=" * 55)
