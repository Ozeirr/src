import os
import csv
from datetime import datetime
from encrypt_decrypt import encrypt_data, decrypt_data

# Definieer constanten voor bestandslocaties
LOG_FILE = 'data/logs.csv'

def ensure_data_directory_exists():
    """
    Zorg ervoor dat de 'data' directory bestaat.
    """
    if not os.path.exists('data'):
        os.makedirs('data')

# Zorg ervoor dat de data directory bestaat
ensure_data_directory_exists()

def get_next_log_number() -> int:
    """
    Bepaal het volgende lognummer op basis van de huidige logvermeldingen.
    """
    if not os.path.exists(LOG_FILE):
        return 1
    with open(LOG_FILE, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        log_entries = list(reader)
        return len(log_entries) + 1

def log_activity(username: str, description: str, additional_info: str = '', suspicious: str = 'No'):
    """
    Log een activiteit met de opgegeven details.
    """
    date = datetime.now().strftime('%d-%m-%Y')
    time = datetime.now().strftime('%H:%M:%S')
    log_number = get_next_log_number()
    
    # Versleutel de logdetails
    encrypted_username = encrypt_data(username)
    encrypted_description = encrypt_data(description)
    encrypted_additional_info = encrypt_data(additional_info)
    encrypted_suspicious = encrypt_data(suspicious)
    
    log_entry = [log_number, date, time, encrypted_username, encrypted_description, encrypted_additional_info, encrypted_suspicious]
    
    # Voeg de logvermelding toe aan het CSV-bestand
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(log_entry)

def decrypt_log_row(row: list) -> list:
    """
    Ontsleutel een enkele logrij.
    """
    if len(row) != 7:
        print(f"Onverwachte rijlengte: {len(row)}. Rij: {row}")
        return row  # Of handel het anders af
    decrypted_row = [
        row[0],  # lognummer
        row[1],  # datum
        row[2],  # tijd
        decrypt_data(row[3]),  # gebruikersnaam
        decrypt_data(row[4]),  # beschrijving van activiteit
        decrypt_data(row[5]),  # aanvullende informatie
        decrypt_data(row[6])   # verdacht
    ]
    return decrypted_row

def decrypt_log_file() -> list:
    """
    Lees en ontsleutel alle logvermeldingen uit het logbestand.
    """
    if not os.path.exists(LOG_FILE):
        return []
    
    logs = []
    with open(LOG_FILE, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            decrypted_row = decrypt_log_row(row)
            logs.append(decrypted_row)
    return logs

def display_logs(logs: list):
    """
    Toon logs in een tabelvorm met kopteksten.
    """
    headers = ["No.", "Date", "Time", "Username", "Description of Activity", "Additional Information", "Suspicious"]

    # Bepaal de breedte van elke kolom op basis van het langste item
    column_widths = [len(header) for header in headers]
    for log in logs:
        for i, field in enumerate(log):
            column_widths[i] = max(column_widths[i], len(str(field)))
    
    # Print de kopteksten
    header_row = " | ".join(header.ljust(column_widths[i]) for i, header in enumerate(headers))
    print(header_row)
    print("-" * len(header_row))  # Divider
    
    # Print elke logvermelding
    for log in logs:
        log_row = " | ".join(str(log[i]).ljust(column_widths[i]) for i in range(len(headers)))
        print(log_row)

def get_suspicious_logs() -> list:
    """
    Haal logs op die als verdacht zijn gemarkeerd.
    """
    logs = decrypt_log_file()
    suspicious_logs = [log for log in logs if log[6].lower() == 'yes']
    return suspicious_logs

def log_suspicious_activity(username: str, description: str, additional_info: str = ''):
    """
    Log een activiteit als verdacht.
    """
    log_activity(username, description, additional_info, suspicious='Yes')