# Developed by: thieveshkar_cb013248
#
# Core Engine for the File Integrity Monitor.
# Handles directory scanning, baseline generation, and structural verification.

import os
import stat
import json
import hashlib
from core.utils import VAULT_DIR, BASELINE_PATH

class IntegrityEngine:
    """
    The core engine responsible for scanning directories, computing baselines,
    and verifying the active system state against stored baselines.
    """
    def __init__(self):
        self.baseline = {}
    
    def _calculate_sha256(self, filepath):
        """
        Calculates the SHA-256 cryptographic hash of a given file.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def _get_file_stats(self, filepath):
        """
        Extracts absolute path, file size, last modified timestamp, and Posix permissions.
        """
        try:
            file_stat = os.stat(filepath)
            size = file_stat.st_size
            mtime = file_stat.st_mtime
            permissions = oct(stat.S_IMODE(file_stat.st_mode)).replace("o", "")
            if len(permissions) == 3:
                permissions = "0" + permissions
            return {
                "size": size,
                "mtime": mtime,
                "permissions": permissions
            }
        except Exception:
            return None

    def scan_directories(self, paths):
        """
        Recursively scans all provided paths and generates an integrity dictionary.
        """
        current_state = {}
        for path in paths:
            if not os.path.exists(path):
                continue
            if os.path.isfile(path):
                stats = self._get_file_stats(path)
                file_hash = self._calculate_sha256(path)
                if stats and file_hash:
                    current_state[os.path.abspath(path)] = {
                        "size": stats["size"],
                        "mtime": stats["mtime"],
                        "permissions": stats["permissions"],
                        "hash": file_hash
                    }
                continue

            for root_dir, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.abspath(os.path.join(root_dir, file))
                    stats = self._get_file_stats(filepath)
                    file_hash = self._calculate_sha256(filepath)
                    if stats and file_hash:
                        current_state[filepath] = {
                            "size": stats["size"],
                            "mtime": stats["mtime"],
                            "permissions": stats["permissions"],
                            "hash": file_hash
                        }
        return current_state

    def generate_baseline(self, paths):
        """
        Scans specified paths and securely saves the structural representation to a local JSON file.
        """
        if not os.path.exists(VAULT_DIR):
            try:
                os.makedirs(VAULT_DIR, exist_ok=True)
                os.chmod(VAULT_DIR, 0o700)
            except Exception as e:
                return False, f"Failed to create Vault: {e}"

        self.baseline = self.scan_directories(paths)
        
        try:
            with open(BASELINE_PATH, "w") as f:
                json.dump(self.baseline, f, indent=4)
            os.chmod(BASELINE_PATH, 0o600)
            return True, f"Baseline successfully generated for {len(self.baseline)} files."
        except Exception as e:
            return False, f"Failed to write baseline: {e}"

    def load_baseline(self):
        """
        Loads the previously saved structural baseline from the secure vault.
        """
        if not os.path.exists(BASELINE_PATH):
            return False, "No existing baseline found. Please generate one."
        
        try:
            with open(BASELINE_PATH, "r") as f:
                self.baseline = json.load(f)
            return True, f"Loaded baseline with {len(self.baseline)} items."
        except Exception as e:
            return False, f"Failed to read baseline: {e}"

    def verify_integrity(self, paths):
        """
        Compares the current structural state of target directories against the loaded baseline.
        Identifies ADDED, MODIFIED, and DELETED files.
        """
        results = []
        current_state = self.scan_directories(paths)

        for filepath, data in current_state.items():
            if filepath not in self.baseline:
                results.append({"path": filepath, "status": "ADDED", "hash": data["hash"], "permissions": data["permissions"], "mtime": data["mtime"]})
            else:
                base_data = self.baseline[filepath]
                if (base_data["hash"] != data["hash"] or 
                    base_data["size"] != data["size"] or 
                    base_data["mtime"] != data["mtime"] or 
                    base_data["permissions"] != data["permissions"]):
                    results.append({"path": filepath, "status": "MODIFIED", "hash": data["hash"], "permissions": data["permissions"], "mtime": data["mtime"]})
                else:
                    results.append({"path": filepath, "status": "MATCHED", "hash": data["hash"], "permissions": data["permissions"], "mtime": data["mtime"]})

        for filepath in self.baseline.keys():
            is_monitored = any(filepath.startswith(os.path.abspath(p)) for p in paths)
            if is_monitored and filepath not in current_state:
                base_data = self.baseline[filepath]
                results.append({"path": filepath, "status": "DELETED", "hash": base_data["hash"], "permissions": base_data["permissions"], "mtime": base_data["mtime"]})

        return results