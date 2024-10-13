import os
import logging
from sqlite3 import connect
from datetime import datetime
from user import (
    validate_login, add_user_prompt,
    update_password, list_users, update_user_prompt, delete_user_prompt,
    reset_user_password, delete_admin_prompt, update_admin_prompt, reset_admin_password_prompt
)
from member import (
    add_member_prompt, search_member_prompt, update_member_prompt, delete_member_prompt
)
from log import (
    log_activity, log_suspicious_activity, get_suspicious_logs, decrypt_log_file, display_logs
)
from database import create_connection, create_tables, add_super_admin
from backup import backup_database_and_logs, restore_database_from_backup
from encrypt_decrypt import (
    generate_keys, 
    load_private_key, 
    load_public_key
)

# Configure logging
logging.basicConfig(
    filename='data/system.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main_menu(role):
    """
    Display the main menu options based on the user's role.
    """
    border = "=" * 40
    header = f"{'Welcome to Unique Meal Management System':^40}"
    footer = "=" * 40

    print(f"\n{border}")
    print(f"{header}")
    print(f"{footer}")
    
    options = []

    if role == 'super_admin':
        options += [
            ("Add system admin", "A/a", "1"),
            ("Add consultant", "C/c", "2"),
            ("Update system admin", "M/m", "3"),
            ("Delete system admin", "X/x", "4"),
            ("Reset system admin password", "Z/z", "5")
        ]
    
    if role in ['super_admin', 'system_admin']:
        options += [
            ("View users and roles", "V/v", "6"),
            ("Update consultant account", "U/u", "7"),
            ("Delete consultant account", "E/e", "8"),
            ("Reset consultant password", "R/r", "9"),
            ("Create backup", "B/b", "10"),
            ("Restore backup", "H/h", "11"),
            ("View logs", "L/l", "12"),
            ("Register new member", "N/n", "13"),
            ("Search member", "S/s", "14"),
            ("Update member", "P/p", "15"),
            ("Delete member", "D/d", "16")
        ]
    
    if role == 'consultant':
        options += [
            ("Register new member", "N/n", "13"),
            ("Search member", "S/s", "14"),
            ("Update member", "P/p", "15"),
            ("Delete member", "D/d", "16")
        ]
    
    if role == 'member':
        options.append(("Profile management (if allowed)", "", ""))
    
    # Voeg de "Update password" optie alleen toe als de gebruiker geen super_admin is
    if role != 'super_admin':
        options.append(("Update password", "W/w", "17"))
    
    # "Exit" optie altijd toevoegen
    options.append(("Exit", "Q/q", "18"))

    for desc, key, num in options:
        key_desc = f"({key})".ljust(10)
        num_desc = f"{num}".rjust(2)
        print(f"{num_desc}. {desc} {key_desc}")
    
    print(f"{footer}")
    
    choice = input("Enter your choice: ").strip().lower()
    return choice


def login_prompt(conn, max_attempts=3):
    """
    Prompt the user to log in with a username and password.
    """
    attempts = 0
    while attempts < max_attempts:
        username = input("Username: ")
        password = input("Password: ")
        
        result = validate_login(conn, username, password)
        
        if result:
            user_id, role = result
            log_activity(username, "Logged in")
            logging.info("Login successful.")
            return user_id, role
        else:
            log_suspicious_activity(username, "Failed login attempt", f"Attempt {attempts + 1}")
            logging.info(f"Failed login attempt {attempts + 1} for username: {username}")
            print("Invalid login credentials. Try again or exit.")
            retry = input("Do you want to try again? (y/n): ").lower()
            if retry == 'n':
                log_activity(username, "User chose to exit after failed login attempts")
                print("Exiting...")
                exit()
        
        attempts += 1
        if attempts >= max_attempts:
            log_suspicious_activity(username, "Too many failed login attempts", f"Total attempts: {max_attempts}")
            print("Too many failed login attempts. Exiting...")
            exit()


def main():
    """
    Main entry point of the application. Initializes the database, handles user login,
    and displays the main menu based on the user's role.
    """
    database = "data/unique_meal.db"
    conn = create_connection(database)
    if conn is not None:
        create_tables(conn)
        add_super_admin(conn)

    user_id, role = login_prompt(conn)
    if user_id is None:
        return

    if role in ['super_admin', 'system_admin']:
        suspicious_logs = get_suspicious_logs()
        if suspicious_logs:
            print("There are unread suspicious activities!")
            for log_entry in suspicious_logs:
                print(f"{log_entry[0]} - {log_entry[1]} {log_entry[2]} - {log_entry[3]}: {log_entry[4]} - {log_entry[5]}")

    while True:
        choice = main_menu(role)
        if choice in ['a', '1'] and role == 'super_admin':
            add_user_prompt(conn, default_role='system_admin')
        elif choice in ['c', '2'] and role == 'super_admin':
            add_user_prompt(conn, default_role='consultant')
        elif choice in ['m', '3'] and role == 'super_admin':
            update_admin_prompt(conn)
        elif choice in ['x', '4'] and role == 'super_admin':
            delete_admin_prompt(conn)
        elif choice in ['z', '5'] and role == 'super_admin':
            reset_admin_password_prompt(conn)
        elif choice in ['v', '6'] and role in ['super_admin', 'system_admin']:
            list_users(conn)
        elif choice in ['u', '7'] and role in ['super_admin', 'system_admin']:
            update_user_prompt(conn)
        elif choice in ['e', '8'] and role in ['super_admin', 'system_admin']:
            delete_user_prompt(conn)
        elif choice in ['r', '9'] and role in ['super_admin', 'system_admin']:
            reset_user_password(conn)
        elif choice in ['b', '10'] and role in ['super_admin', 'system_admin']:
            backup_database_and_logs(database)
        elif choice in ['h', '11'] and role in ['super_admin', 'system_admin']:
            restore_database_from_backup(database)
        elif choice in ['l', '12'] and role in ['super_admin', 'system_admin']:
            logs = decrypt_log_file()
            display_logs(logs)
        elif choice in ['n', '13'] and role in ['super_admin', 'system_admin', 'consultant']:
            add_member_prompt(conn)
        elif choice in ['s', '14'] and role in ['super_admin', 'system_admin', 'consultant']:
            search_member_prompt(conn)
        elif choice in ['p', '15'] and role in ['super_admin', 'system_admin', 'consultant']:
            member_id = input("Enter membership number: ")
            update_member_prompt(conn, member_id)
        elif choice in ['d', '16'] and role in ['super_admin', 'system_admin']:
            delete_member_prompt(conn)
        elif choice in ['w', '17']:
            if role != 'super_admin':
                update_password(conn, user_id)
            else:
                print("Super administrators kunnen hun wachtwoord niet wijzigen.")
        elif choice in ['q', '18']:
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.")

    conn.close()

if __name__ == "__main__":
    # Controleer of de 'data' directory bestaat
    if not os.path.exists("data"):
        os.makedirs("data")

    # Genereer sleutels als ze nog niet bestaan
    try:
        load_private_key()
        load_public_key()
    except Exception as e:
        print(e)
        generate_keys()
        print("RSA-sleutels zijn gegenereerd en opgeslagen in de map 'data'.")

    main()  # Start de hoofdapplicatie