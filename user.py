import logging
import sqlite3
from datetime import datetime
import re
from encrypt_decrypt import encrypt_data, decrypt_data
from log import log_activity, log_suspicious_activity
from utils import hash_password
from sqlite3 import Error

# Validation functions
def is_valid_username(username):
    """
    Controleer of de gebruikersnaam voldoet aan de vereiste regels met een whitelisting-benadering.
    """
    # Definieer de whitelist van toegestane tekens
    allowed_characters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'")

    # Controleer de lengte van de gebruikersnaam
    if 8 <= len(username) <= 10:
        pass  # Lengte is geldig
    else:
        print("De gebruikersnaam moet tussen de 8 en 10 tekens lang zijn.")
        return False

    # Controleer of de gebruikersnaam begint met een letter of underscore (_)
    first_char = username[0]
    if first_char.isalpha() or first_char == '_':
        pass  # Eerste karakter is geldig
    else:
        print("De gebruikersnaam moet beginnen met een letter of underscore (_).")
        return False

    # Controleer of alle tekens in de gebruikersnaam zijn toegestaan
    for char in username:
        if char in allowed_characters:
            pass  # Karakter is toegestaan
        else:
            print(f"Ontoegestaan teken gevonden: '{char}'")
            return False

    # Als alle controles slagen
    return True


def is_valid_password(password):
    """
    Controleer of het wachtwoord voldoet aan de vereiste regels met een whitelisting-benadering.
    """
    # Definieer de whitelist van toegestane tekens
    allowed_characters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%&_-+=`|(){}[]:;'<>,.?/")

    # Controleer de lengte van het wachtwoord
    if 12 <= len(password) <= 30:
        pass  # Lengte is geldig
    else:
        print("Het wachtwoord moet tussen de 12 en 30 tekens lang zijn.")
        return False

    # Controleer of alle tekens in het wachtwoord zijn toegestaan
    for char in password:
        if char in allowed_characters:
            pass  # Karakter is toegestaan
        else:
            print(f"Ontoegestaan teken gevonden: '{char}'")
            return False

    # Controleer op ten minste één kleine letter
    lowercase_match = re.search(r"[a-z]", password)
    if lowercase_match is not None:
        pass  # Bevat ten minste één kleine letter
    else:
        print("Het wachtwoord moet ten minste één kleine letter bevatten.")
        return False

    # Controleer op ten minste één hoofdletter
    uppercase_match = re.search(r"[A-Z]", password)
    if uppercase_match is not None:
        pass  # Bevat ten minste één hoofdletter
    else:
        print("Het wachtwoord moet ten minste één hoofdletter bevatten.")
        return False

    # Controleer op ten minste één cijfer
    digit_match = re.search(r"\d", password)
    if digit_match is not None:
        pass  # Bevat ten minste één cijfer
    else:
        print("Het wachtwoord moet ten minste één cijfer bevatten.")
        return False

    # Controleer op ten minste één speciaal teken
    special_char_match = re.search(r"[~!@#$%&_\-+=`|\(){}[\]:;'<>,.?/]", password)
    if special_char_match is not None:
        pass  # Bevat ten minste één speciaal teken
    else:
        print("Het wachtwoord moet ten minste één speciaal teken bevatten.")
        return False

    # Als alle controles slagen
    return True


def validate_login(conn, username, password):
    """
    Valideer de gebruikersnaam en het wachtwoord tegen de opgeslagen referenties.
    """
    try:
        cursor = conn.cursor()
        
        # Haal alle gebruikers op uit de database
        cursor.execute("SELECT id, username, password, role FROM users")
        users = cursor.fetchall()
        
        for user in users:
            # Ontsleutel de gebruikersnaam
            decrypted_username = decrypt_data(user[1])  # Veronderstel dat username versleuteld is
            
            if decrypted_username == username:
                # Hash het ingevoerde wachtwoord
                hashed_password = hash_password(password)
                
                # Controleer of het gehashte wachtwoord overeenkomt
                if user[2] == hashed_password:
                    # Ontsleutel de rol voordat deze wordt geretourneerd
                    decrypted_role = decrypt_data(user[3])  # Ontsleutel de rol
                    return user[0], decrypted_role  # Retourneer user_id en ontsleutelde rol
        
        return None  # Retourneer None als de inloggegevens ongeldig zijn
    except Exception as e:
        logging.error(f"Error tijdens login: {e}")
        return None

def username_exists(conn, username):
    """
    Check if a given username already exists in the database.
    """
    lowerCaseUsername = username.lower()
    try:
        sql = "SELECT username FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        for row in rows:
            decrypted_username = decrypt_data(row[0]).lower()
            if decrypted_username == lowerCaseUsername:
                return True
        return False
    except Error as e:
        logging.error(f"Error checking for existing username: {e}")
        return False


def add_user_prompt(conn, default_role=None):
    """
    Prompt de gebruiker om een nieuwe gebruiker toe te voegen.
    Alle gegevens behalve het wachtwoord worden versleuteld.
    Het wachtwoord wordt gehasht voor veilige opslag.
    """
    while True:
        username = input("Username: ")
        if is_valid_username(username):
            if username_exists(conn, username):
                print("Deze gebruikersnaam bestaat al. Kies een andere gebruikersnaam.")
                continue
            break
        else:
            print("Ongeldige gebruikersnaam. Zorg ervoor dat de gebruikersnaam aan de vereisten voldoet.")

    while True:
        password = input("Password: ")
        if is_valid_password(password):
            break
        else:
            print("Ongeldig wachtwoord. Zorg ervoor dat het wachtwoord aan de vereisten voldoet.")

    first_name = input("First Name: ")
    last_name = input("Last Name: ")

    role = default_role if default_role else input("Role: ")

    # Encryptie van gebruikersgegevens
    encrypted_username = encrypt_data(username)
    hashed_password = hash_password(password)
    encrypted_first_name = encrypt_data(first_name)
    encrypted_last_name = encrypt_data(last_name)
    encrypted_role = encrypt_data(role)  # Encrypt de rol
    encrypted_registration_date = encrypt_data(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))  # Encrypt de registratie datum

    try:
        sql = """INSERT INTO users (username, password, role, first_name, last_name, registration_date)
                 VALUES (?, ?, ?, ?, ?, ?)"""
        cur = conn.cursor()
        cur.execute(sql, (
            encrypted_username,
            hashed_password,
            encrypted_role,
            encrypted_first_name,
            encrypted_last_name,
            encrypted_registration_date
        ))
        conn.commit()
        log_activity(username, "User added via prompt", f"Role: {role}, Name: {first_name} {last_name}")
        print(f"User {username} succesvol toegevoegd.")
    except Error as e:
        logging.error(f"Error bij het toevoegen van gebruiker: {e}")
        log_suspicious_activity(username, "Failed to add user via prompt", f"Role: {role}, Name: {first_name} {last_name}")
        print("Er is een fout opgetreden bij het toevoegen van de gebruiker.")
    except Exception as e:
        logging.error(f"Onverwachte fout: {e}")
        print("Er is een onverwachte fout opgetreden.")

def update_password(conn, user_id):
    """
    Update the password for the specified user.
    """
    while True:
        new_password = input("Enter your new password: ")
        if is_valid_password(new_password):
            break

    hashed_password = hash_password(new_password)

    try:
        sql_get_username = "SELECT username FROM users WHERE id=?"
        cur = conn.cursor()
        cur.execute(sql_get_username, (user_id,))
        row = cur.fetchone()

        if row:
            username = decrypt_data(row[0])

            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "Password updated", "User updated their password")
            print(f"Password for user {username} successfully updated.")
        else:
            print("User not found.")
            logging.error("Failed to find user for password update.")
    except Error as e:
        logging.error(f"Error updating password: {e}")
        log_suspicious_activity("system", "Failed to update password", f"Attempted to update password for user ID {user_id} with error: {e}")


def list_users(conn):
    """
    Lijst alle gebruikers en hun rollen met ontsleutelde gegevens.
    """
    try:
        sql = "SELECT username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        if not rows:
            print("Geen gebruikers gevonden.")
            return

        # Header voor de tabel
        print(f"{'Username':<40} {'Role':<40}")
        print("-" * 80)
        
        for row in rows:
            encrypted_username, encrypted_role = row
            try:
                decrypted_username = decrypt_data(encrypted_username)
                decrypted_role = decrypt_data(encrypted_role)
                print(f"{decrypted_username:<40} {decrypted_role:<40}")
            except Exception as e:
                logging.error(f"Fout bij het ontsleutelen van gegevens voor gebruiker: {encrypted_username}. Fout: {e}")
                print(f"Username: [onleesbaar], Role: [onleesbaar]")
    except Error as e:
        logging.error(f"Fout bij het opvragen van gebruikers: {e}")
        print("Er is een fout opgetreden bij het opvragen van de gebruikers.")
        logging.error(f"Error listing users: {e}")


def update_user_prompt(conn):
    """
    Prompt the user to update an existing user's details.
    """
    while True:
        username = input("Enter the current username of the user you want to update: ")
        if is_valid_username(username):
            break

    while True:
        new_username = input("New Username: ")
        if not is_valid_username(new_username):
            print("Invalid new username. Ensure the username meets the requirements.")
            continue
        if username_exists(conn, new_username):
            print("This new username already exists. Choose a different username.")
            continue
        break

    first_name = input("New First Name: ")
    last_name = input("New Last Name: ")

    try:
        sql_fetch_all = "SELECT id, username FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        encrypted_new_username = encrypt_data(new_username)

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                break

        if user_id:
            sql_update = "UPDATE users SET username=?, first_name=?, last_name=? WHERE id=?"
            cur.execute(sql_update, (encrypted_new_username, first_name, last_name, user_id))
            conn.commit()

            log_activity(username, "User updated", f"Username changed to {new_username}, Name updated to {first_name} {last_name}")
            print(f"User {username} successfully updated to {new_username}.")
        else:
            print(f"User {username} not found.")
            log_suspicious_activity(username, "Failed to update user", f"Attempted to update non-existent user {username}")
    except Error as e:
        logging.error(f"Error updating user: {e}")
        log_suspicious_activity(username, "Failed to update user", f"Attempted to update {username} with error: {e}")


def delete_user_prompt(conn):
    """
    Prompt the user to delete an existing user.
    """
    while True:
        username = input("Enter the username of the user you want to delete: ")
        if is_valid_username(username):
            break
    encrypted_username = None

    try:
        sql = "SELECT username FROM users"
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()

        for row in rows:
            decrypted_username = decrypt_data(row[0])
            if decrypted_username == username:
                encrypted_username = row[0]
                break

        if encrypted_username:
            sql_delete = "DELETE FROM users WHERE username=?"
            cur.execute(sql_delete, (encrypted_username,))
            conn.commit()
            log_activity(username, "User deleted", f"User {username} was deleted")
            print(f"User {username} successfully deleted.")
        else:
            print(f"User {username} not found.")
    except Error as e:
        logging.error(f"Error deleting user: {e}")
        log_suspicious_activity(username, "Failed to delete user", f"Attempted to delete {username}")


def reset_user_password(conn):
    """
    Reset the password for an existing user.
    """
    while True:
        username = input("Enter the username of the user whose password you want to reset: ")
        if is_valid_username(username):
            break

    while True:
        new_password = input("Enter the new password: ")
        if is_valid_password(new_password):
            break
    
    hashed_password = hash_password(new_password)

    try:
        sql_fetch_all = "SELECT id, username FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                break

        if user_id:
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()
            log_activity(username, "Password reset", f"Password for {username} was reset")
            print(f"Password for user {username} successfully reset.")
        else:
            print(f"User {username} not found.")
            log_suspicious_activity(username, "Failed to reset password", f"Attempted to reset password for non-existent user {username}")
    except Error as e:
        logging.error(f"Error resetting password: {e}")
        log_suspicious_activity(username, "Failed to reset password", f"Attempted to reset password for {username} with error: {e}")


def update_admin_prompt(conn):
    """
    Prompt de gebruiker om de gegevens van een systeembeheerder bij te werken.
    Alle gegevens behalve het wachtwoord worden versleuteld.
    """
    try:
        # Vraag de huidige gebruikersnaam van de systeembeheerder
        while True:
            username = input("Enter the current username of the system admin you want to update: ")
            if is_valid_username(username):
                break
            else:
                print("Ongeldige gebruikersnaam. Zorg ervoor dat de gebruikersnaam aan de vereisten voldoet.")

        # Vraag de nieuwe gegevens
        first_name = input("New First Name: ")
        last_name = input("New Last Name: ")

        while True:
            new_username = input("New Username: ")
            if is_valid_username(new_username):
                if username_exists(conn, new_username):
                    print("This new username already exists. Choose a different username.")
                    continue
                break
            else:
                print("Invalid new username. Ensure the username meets the requirements.")

        # Versleutel de nieuwe gebruikersnaam
        encrypted_new_username = encrypt_data(new_username)

        # Zoek de gebruiker in de database
        sql_fetch = "SELECT id, username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch)
        rows = cur.fetchall()

        user_id = None
        decrypted_role = None

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                user_id = row[0]
                try:
                    decrypted_role = decrypt_data(row[2])
                except Exception as e:
                    logging.error(f"Error decrypting role for user ID {user_id}: {e}")
                    print("Error decrypting role for the user. Cannot proceed.")
                    return
                break

        if user_id:
            if decrypted_role != 'system_admin':
                print("Deze functie is alleen beschikbaar voor systeembeheerder accounts.")
                return

            # Versleutel de nieuwe voornaam en achternaam
            encrypted_first_name = encrypt_data(first_name)
            encrypted_last_name = encrypt_data(last_name)

            # Update de gebruiker in de database
            sql_update = "UPDATE users SET username=?, first_name=?, last_name=? WHERE id=?"
            cur.execute(sql_update, (
                encrypted_new_username,
                encrypted_first_name,
                encrypted_last_name,
                user_id
            ))
            conn.commit()

            log_activity(username, "System Admin updated", f"Username changed to {new_username}, Name updated to {first_name} {last_name}")
            print(f"System admin {username} succesvol bijgewerkt naar {new_username}.")
            
            return  # Zorg ervoor dat de functie hier eindigt
        else:
            print(f"System admin {username} niet gevonden.")
            log_suspicious_activity(username, "Failed to update system admin", f"Attempted to update non-existent system admin {username}")
    except Error as e:
        logging.error(f"Error updating system admin: {e}")
        log_suspicious_activity(username, "Failed to update system admin", f"Attempted to update system admin {username} with error: {e}")
        print("Er is een fout opgetreden bij het bijwerken van de systeembeheerder.")
    except Exception as e:
        logging.error(f"Onverwachte fout: {e}")
        print("Er is een onverwachte fout opgetreden.")

def delete_admin_prompt(conn):
    """
    Prompt de gebruiker om een systeembeheerder account te verwijderen.
    Alle gegevens behalve het wachtwoord worden versleuteld.
    """
    try:
        # Vraag de gebruikersnaam van de systeembeheerder die verwijderd moet worden
        while True:
            username = input("Enter the username of the system admin you want to delete: ")
            if is_valid_username(username):
                break
            else:
                print("Ongeldige gebruikersnaam. Zorg ervoor dat de gebruikersnaam aan de vereisten voldoet.")
        
        # Zoek de gebruiker in de database
        sql_fetch_all = "SELECT id, username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        decrypted_role = None

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                try:
                    decrypted_role = decrypt_data(row[2])
                except Exception as e:
                    logging.error(f"Error decrypting role for user ID {row[0]}: {e}")
                    print("Error decrypting role for the user. Cannot proceed.")
                    return  # Stop de functie als de rol niet ontsleuteld kan worden
                if decrypted_role != 'system_admin':
                    print("This function is only available for system admin accounts.")
                    return  # Stop de functie als de gebruiker geen system_admin is
                user_id = row[0]
                break

        if user_id:
            # Bevestig de verwijdering
            confirm = input(f"Are you sure you want to delete the system admin '{username}'? (y/n): ").strip().lower()
            if confirm != 'y':
                print("Deletion canceled.")
                return

            # Verwijder de gebruiker uit de database
            sql_delete = "DELETE FROM users WHERE id=?"
            cur.execute(sql_delete, (user_id,))
            conn.commit()

            log_activity(username, "System Admin deleted", f"System Admin {username} was deleted")
            print(f"System admin '{username}' successfully deleted.")
        else:
            print(f"System admin '{username}' not found.")
            log_suspicious_activity(username, "Failed to delete system admin", f"Attempted to delete non-existent system admin '{username}'")
    except Error as e:
        logging.error(f"Error deleting system admin: {e}")
        log_suspicious_activity(username, "Failed to delete system admin", f"Attempted to delete '{username}' with error: {e}")
        print("Er is een fout opgetreden bij het verwijderen van de systeembeheerder.")
    except Exception as e:
        logging.error(f"Onverwachte fout: {e}")
        print("Er is een onverwachte fout opgetreden.")


def reset_admin_password_prompt(conn):
    """
    Prompt de super admin om het wachtwoord van een systeembeheerder te resetten.
    """
    try:
        # Vraag de gebruikersnaam van de systeembeheerder wiens wachtwoord gereset moet worden
        while True:
            username = input("Enter the username of the system admin whose password you want to reset: ")
            if is_valid_username(username):
                break
            else:
                print("Ongeldige gebruikersnaam. Zorg ervoor dat de gebruikersnaam aan de vereisten voldoet.")

        # Zoek de gebruiker in de database
        sql_fetch_all = "SELECT id, username, role FROM users"
        cur = conn.cursor()
        cur.execute(sql_fetch_all)
        rows = cur.fetchall()

        user_id = None
        decrypted_role = None

        for row in rows:
            decrypted_username = decrypt_data(row[1])
            if decrypted_username == username:
                try:
                    decrypted_role = decrypt_data(row[2])
                except Exception as e:
                    logging.error(f"Error decrypting role for user ID {row[0]}: {e}")
                    print("Error decrypting role for the user. Cannot proceed.")
                    return  # Stop de functie als de rol niet ontsleuteld kan worden
                if decrypted_role != 'system_admin':
                    print("This function is only available for system admin accounts.")
                    return  # Stop de functie als de gebruiker geen system_admin is
                user_id = row[0]
                break

        if user_id:
            # Vraag om het nieuwe wachtwoord
            while True:
                new_password = input("Enter the new password: ")
                if is_valid_password(new_password):
                    break
                else:
                    print("Invalid password. Ensure the password meets the requirements.")

            # Hash het nieuwe wachtwoord
            hashed_password = hash_password(new_password)

            # Update het wachtwoord in de database
            sql_update = "UPDATE users SET password=? WHERE id=?"
            cur.execute(sql_update, (hashed_password, user_id))
            conn.commit()

            log_activity(username, "System Admin password reset", f"Password for system admin {username} was reset")
            print(f"Password for system admin {username} successfully reset.")
            
            return  # Zorg ervoor dat de functie hier eindigt
        else:
            print(f"System admin {username} not found.")
            log_suspicious_activity(username, "Failed to reset password for system admin", f"Attempted to reset password for non-existent system admin {username}")
    except Error as e:
        logging.error(f"Error resetting password for system admin: {e}")
        log_suspicious_activity(username, "Failed to reset password for system admin", f"Attempted to reset password for {username} with error: {e}")
        print("Er is een fout opgetreden bij het resetten van het wachtwoord voor de systeembeheerder.")
    except Exception as e:
        logging.error(f"Onverwachte fout: {e}")
        print("Er is een onverwachte fout opgetreden.")