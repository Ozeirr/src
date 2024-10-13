import shutil
import os
from datetime import datetime
import zipfile
import time
import sys

def backup_database_and_logs(database_path):
    """
    Create a backup of the database and log files.
    """
    backup_dir = "backups"
    os.makedirs(backup_dir, exist_ok=True)

    # Create a unique filename for the backup based on the current timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"{os.path.basename(database_path)}_{timestamp}.zip"
    backup_path = os.path.join(backup_dir, backup_filename)

    with zipfile.ZipFile(backup_path, 'w') as backup_zip:
        # Add the database to the zip file
        backup_zip.write(database_path, os.path.basename(database_path))
        
        # List of log files to include in the backup
        log_files = ["data/logs.csv", "data/encrypted_logs.csv", "data/system.log"]

        for log_file in log_files:
            if os.path.exists(log_file):
                backup_zip.write(log_file, os.path.basename(log_file))
            else:
                print(f"Log file {log_file} not found, skipping.")

    print(f"Backup successfully created: {backup_path}")


def restore_database_from_backup(database_path):
    """
    Restore the database and log files from a backup.
    """
    backup_dir = "backups"
    backup_file = input("Enter the name of the backup file (in the 'backups' directory): ")
    backup_path = os.path.join(backup_dir, backup_file)
    
    if os.path.exists(backup_path):
        with zipfile.ZipFile(backup_path, 'r') as backup_zip:
            # Extract all files to their respective locations
            backup_zip.extractall("data")

            # Normalize paths to avoid SameFileError
            extracted_db_path = os.path.abspath(os.path.join("data", os.path.basename(database_path)))
            database_path = os.path.abspath(database_path)

            # Check if the extracted database path is different from the target database path
            if extracted_db_path != database_path:
                for _ in range(3):  # Retry up to 3 times
                    try:
                        if os.path.exists(extracted_db_path):
                            shutil.move(extracted_db_path, database_path)
                        break
                    except PermissionError as e:
                        print(f"PermissionError: {e}, retrying...")
                        time.sleep(1)
                else:
                    print("Failed to move database file due to persistent PermissionError.")
            else:
                print("Source and destination are the same, no move operation needed.")

            # Move the extracted log files to their respective locations
            for file_name in ["logs.csv", "encrypted_logs.csv", "system.log"]:
                extracted_file_path = os.path.abspath(os.path.join("data", file_name))
                if os.path.exists(extracted_file_path):
                    # Check if the source and destination are the same
                    if extracted_file_path != extracted_file_path:
                        for _ in range(3):  # Retry up to 3 times
                            try:
                                shutil.move(extracted_file_path, extracted_file_path)
                                break
                            except PermissionError as e:
                                print(f"PermissionError: {e}, retrying...")
                                time.sleep(1)
                        else:
                            print(f"Failed to move {file_name} due to persistent PermissionError.")
                    else:
                        print(f"Source and destination are the same for {file_name}, no move operation needed.")
        
        print("Backup successfully restored.")

        # Restart the program to apply changes
        print("Restarting the terminal to apply changes...")
        time.sleep(2)  # Optional: Add a small delay before restarting
        os.execv(sys.executable, ['python'] + sys.argv)  # Restart the program
        
    else:
        print("Backup file not found.")


if __name__ == "__main__":
    database = "data/unique_meal.db"
    restore_database_from_backup(database)