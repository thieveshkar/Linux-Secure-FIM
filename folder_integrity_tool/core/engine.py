# Developed by: thieveshkar_cb013248
#
# Core Engine for the File Integrity Monitor.
# Handles directory scanning, baseline generation, and structural verification.

# Import the 'os' module to interact with the operating system (e.g., read file paths, move through directories)
import os
# Import the 'stat' module to interpret file permissions and other file status information
import stat
# Import the 'json' module to read and write data in JSON format, which is how we store our baseline
import json
# Import the 'hashlib' module to calculate cryptographic hashes, giving each file a unique fingerprint
import hashlib
# Import our custom system paths (VAULT_DIR and BASELINE_PATH) from the utils module
from core.utils import VAULT_DIR, BASELINE_PATH

# Define the IntegrityEngine class, which acts as the brain for scanning and checking files
class IntegrityEngine:
    """
    The core engine responsible for scanning directories, computing baselines,
    and verifying the active system state against stored baselines.
    """
    # Initialization method called when creating an IntegrityEngine object
    def __init__(self):
        # Create an empty dictionary to hold our 'baseline' (a record of what files look like when safe)
        self.baseline = {}
    
    # Internal method to calculate the SHA-256 hash (fingerprint) of a file
    def _calculate_sha256(self, filepath):
        """
        Calculates the SHA-256 cryptographic hash of a given file.
        """
        # Create a new, empty SHA-256 hash object
        sha256_hash = hashlib.sha256()
        try:
            # Open the file in 'read binary' mode ("rb") so we can read raw data regardless of file type
            with open(filepath, "rb") as f:
                # Loop to read the file in chunks of 4096 bytes (4KB) at a time, until the file is empty (b"")
                for byte_block in iter(lambda: f.read(4096), b""):
                    # Update the hash object with each chunk of data
                    sha256_hash.update(byte_block)
            # Return the final calculated hash as a continuous string of hexadecimal characters (e.g., '1a2b3c...')
            return sha256_hash.hexdigest()
        # If any error occurs (like being unable to read the file), catch it
        except Exception:
            # Return None to indicate that we failed to calculate the hash
            return None

    # Internal method to get important metadata (stats) about a file
    def _get_file_stats(self, filepath):
        """
        Extracts absolute path, file size, last modified timestamp, and Posix permissions.
        """
        try:
            # Get the raw status of the file from the operating system
            file_stat = os.stat(filepath)
            # Extract the file size in bytes
            size = file_stat.st_size
            # Extract the last modified time as a timestamp (seconds since the epoch)
            mtime = file_stat.st_mtime
            # Extract the file permissions (e.g., read/write/execute), convert to octal, and format the string
            permissions = oct(stat.S_IMODE(file_stat.st_mode)).replace("o", "")
            # If the permission string is 3 characters long (like '644'), add a '0' in front to make it standard ('0644')
            if len(permissions) == 3:
                permissions = "0" + permissions
            # Return a dictionary containing the size, modified time, and permissions
            return {
                "size": size,
                "mtime": mtime,
                "permissions": permissions
            }
        # If an error occurs (like the file being deleted right before we check it), catch it
        except Exception:
            # Return None to indicate failure
            return None

    # Method to scan through a list of folders/files and collect their info
    def scan_directories(self, paths):
        """
        Recursively scans all provided paths and generates an integrity dictionary.
        """
        # Create an empty dictionary to store the current state of all scanned files
        current_state = {}
        # Loop over every path provided in the list
        for path in paths:
            # If the path doesn't exist on the system, skip it and continue to the next one
            if not os.path.exists(path):
                continue
            # Check if the path is a single file rather than a directory
            if os.path.isfile(path):
                # Get the metadata (size, time, permissions) for the file
                stats = self._get_file_stats(path)
                # Calculate the SHA-256 fingerprint of the file
                file_hash = self._calculate_sha256(path)
                # If both stats and hash were successfully obtained
                if stats and file_hash:
                    # Save them in the dictionary, using the absolute (full) path as the key
                    current_state[os.path.abspath(path)] = {
                        "size": stats["size"],
                        "mtime": stats["mtime"],
                        "permissions": stats["permissions"],
                        "hash": file_hash
                    }
                # Move on to the next path since we finished this single file
                continue

            # If the path is a directory, use os.walk to go through it and all its subdirectories
            for root_dir, _, files in os.walk(path):
                # Loop through every individual file found in this directory
                for file in files:
                    # Construct the full absolute path to the file
                    filepath = os.path.abspath(os.path.join(root_dir, file))
                    # Get the metadata for the file
                    stats = self._get_file_stats(filepath)
                    # Calculate the fingerprint for the file
                    file_hash = self._calculate_sha256(filepath)
                    # If both were successful
                    if stats and file_hash:
                        # Save the file's info in the current_state dictionary
                        current_state[filepath] = {
                            "size": stats["size"],
                            "mtime": stats["mtime"],
                            "permissions": stats["permissions"],
                            "hash": file_hash
                        }
        # Return the complete dictionary of all scanned files
        return current_state

    # Method to take a 'snapshot' (baseline) of safe files and save it
    def generate_baseline(self, paths):
        """
        Scans specified paths and securely saves the structural representation to a local JSON file.
        """
        # Check if the secure vault directory exists
        if not os.path.exists(VAULT_DIR):
            try:
                # If it doesn't exist, create it (and any necessary parent folders)
                os.makedirs(VAULT_DIR, exist_ok=True)
                # Set permissions to 700 so only the root user can access the vault
                os.chmod(VAULT_DIR, 0o700)
            # Catch errors like not having permission to create the folder
            except Exception as e:
                # Return False (failure) and an error message
                return False, f"Failed to create Vault: {e}"

        # Call the scan_directories method to create our snapshot, and save it in self.baseline
        self.baseline = self.scan_directories(paths)
        
        try:
            # Open the baseline JSON file in 'write' mode ("w")
            with open(BASELINE_PATH, "w") as f:
                # Write the baseline dictionary to the file in a formatted, readable JSON format
                json.dump(self.baseline, f, indent=4)
            # Set the permissions of the baseline file to 600, so only root can read/write it
            os.chmod(BASELINE_PATH, 0o600)
            # Return True (success) and a message indicating how many files were saved
            return True, f"Baseline successfully generated for {len(self.baseline)} files."
        # Catch errors if saving the file fails
        except Exception as e:
            # Return False and the error message
            return False, f"Failed to write baseline: {e}"

    # Method to load the saved snapshot (baseline) back into memory
    def load_baseline(self):
        """
        Loads the previously saved structural baseline from the secure vault.
        """
        # Check if the baseline file actually exists
        if not os.path.exists(BASELINE_PATH):
            # If it doesn't, return False and a message to generate one
            return False, "No existing baseline found. Please generate one."
        
        try:
            # Open the baseline JSON file in 'read' mode ("r")
            with open(BASELINE_PATH, "r") as f:
                # Read the JSON data and store it back into the self.baseline dictionary
                self.baseline = json.load(f)
            # Return True and a success message indicating how many items were loaded
            return True, f"Loaded baseline with {len(self.baseline)} items."
        # Catch any errors like permission denied or corrupted file
        except Exception as e:
            # Return False and the error message
            return False, f"Failed to read baseline: {e}"

    # Method to check the current state of files against our saved baseline to find changes
    def verify_integrity(self, paths):
        """
        Compares the current structural state of target directories against the loaded baseline.
        Identifies ADDED, MODIFIED, and DELETED files.
        """
        # Create an empty list to store the results of the comparison
        results = []
        # Get the current state of the files by scanning the paths right now
        current_state = self.scan_directories(paths)

        # Loop through every file found in the current scan
        for filepath, data in current_state.items():
            # If a file is in the current scan but NOT in the baseline...
            if filepath not in self.baseline:
                # It means the file is new. Append an 'ADDED' result to our list
                results.append({"path": filepath, "status": "ADDED", "hash": data["hash"], "permissions": data["permissions"], "mtime": data["mtime"]})
            # If the file IS in the baseline...
            else:
                # Get the original baseline data for this file
                base_data = self.baseline[filepath]
                # Compare the current hash, size, modification time, and permissions with the baseline
                if (base_data["hash"] != data["hash"] or 
                    base_data["size"] != data["size"] or 
                    base_data["mtime"] != data["mtime"] or 
                    base_data["permissions"] != data["permissions"]):
                    # If anything is different, the file was changed. Append a 'MODIFIED' result
                    results.append({"path": filepath, "status": "MODIFIED", "hash": data["hash"], "permissions": data["permissions"], "mtime": data["mtime"]})
                # If nothing is different...
                else:
                    # The file is untouched. Append a 'MATCHED' result
                    results.append({"path": filepath, "status": "MATCHED", "hash": data["hash"], "permissions": data["permissions"], "mtime": data["mtime"]})

        # Now loop through every file that was stored in the baseline
        for filepath in self.baseline.keys():
            # Check if this baseline file's path is inside one of the folders we are currently monitoring
            is_monitored = any(filepath.startswith(os.path.abspath(p)) for p in paths)
            # If it is supposed to be monitored, but it's NOT in the current scan...
            if is_monitored and filepath not in current_state:
                # Get the baseline data for the file
                base_data = self.baseline[filepath]
                # It means the file was removed. Append a 'DELETED' result to our list
                results.append({"path": filepath, "status": "DELETED", "hash": base_data["hash"], "permissions": base_data["permissions"], "mtime": base_data["mtime"]})

        # Return the complete list of all changes found
        return results
