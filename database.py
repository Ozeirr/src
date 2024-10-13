import sqlite3
from datetime import datetime
from encrypt_decrypt import encrypt_data, decrypt_data
from utils import hash_password
import logging
from sqlite3 import Error

def create_connection(db_file):
    """
    Create a database connection to the SQLite database specified by db_file.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"SQLite connection is successful: {sqlite3.version}")
    except Error as e:
        print(e)
    return conn


def create_tables(conn):
    """
    Create the necessary tables in the SQLite database.
    """
    try:
        sql_create_users_table = """CREATE TABLE IF NOT EXISTS users (
                                        id INTEGER PRIMARY KEY,
                                        username TEXT NOT NULL UNIQUE,  -- Add UNIQUE constraint
                                        password TEXT NOT NULL,
                                        role TEXT NOT NULL,
                                        first_name TEXT NOT NULL,
                                        last_name TEXT NOT NULL,
                                        registration_date TEXT NOT NULL
                                    );"""

        sql_create_members_table = """CREATE TABLE IF NOT EXISTS members (
                                        id INTEGER PRIMARY KEY,
                                        first_name TEXT NOT NULL,
                                        last_name TEXT NOT NULL,
                                        age INTEGER,
                                        gender TEXT,
                                        weight REAL,
                                        address TEXT,
                                        email TEXT,
                                        phone TEXT,
                                        registration_date TEXT NOT NULL,
                                        membership_id TEXT NOT NULL
                                    );"""

        sql_create_logs_table = """CREATE TABLE IF NOT EXISTS logs (
                                       id INTEGER PRIMARY KEY,
                                       date TEXT NOT NULL,
                                       time TEXT NOT NULL,
                                       username TEXT,
                                       description TEXT NOT NULL,
                                       additional_info TEXT,
                                       suspicious TEXT NOT NULL
                                   );"""

        cursor = conn.cursor()
        cursor.execute(sql_create_users_table)
        cursor.execute(sql_create_members_table)
        cursor.execute(sql_create_logs_table)
        print("Tables created successfully.")
    except Error as e:
        logging.error(f"Error creating tables: {e}")


def add_super_admin(conn):
    """
    Voeg de super admin gebruiker toe aan de database als deze nog niet bestaat.
    Alle gegevens behalve het wachtwoord worden versleuteld.
    Het wachtwoord wordt gehasht voor veilige opslag.
    """
    try:
        # Definieer het super admin wachtwoord
        super_admin_password = "Admin_123?"  # Zorg ervoor dat dit een veilig wachtwoord is
        
        # Hash het wachtwoord
        hashed_password = hash_password(super_admin_password)

        # Controleer of een super admin al bestaat op basis van de gebruikersnaam
        cur = conn.cursor()
        cur.execute("SELECT username FROM users")
        rows = cur.fetchall()

        for row in rows:
            decrypted_username = decrypt_data(row[0])
            if decrypted_username == "super_admin":
                print("Super admin bestaat al.")
                return

        # Versleutel de gebruikersnaam, voornaam, achternaam, rol en registratie datum
        encrypted_username = encrypt_data("super_admin")
        encrypted_first_name = encrypt_data("Super")
        encrypted_last_name = encrypt_data("Admin")
        encrypted_role = encrypt_data("super_admin")
        encrypted_registration_date = encrypt_data(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        # Voeg de super admin toe aan de database
        sql = """
            INSERT INTO users (username, password, role, first_name, last_name, registration_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        cur.execute(sql, (
            encrypted_username,
            hashed_password,
            encrypted_role,
            encrypted_first_name,
            encrypted_last_name,
            encrypted_registration_date
        ))
        conn.commit()
        print("Super admin succesvol toegevoegd.")
    except Error as e:
        logging.error(f"Fout bij het toevoegen van super admin: {e}")
        print("Er is een fout opgetreden bij het toevoegen van de super admin.")
    except Exception as e:
        logging.error(f"Onverwachte fout: {e}")
        print("Er is een onverwachte fout opgetreden.")