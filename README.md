# Linux-Secure-FIM

A robust Linux File Integrity Monitor (FIM) featuring real-time SHA-256 baseline verification, VirusTotal threat intelligence integration, immutable vault protection, and continuous background monitoring.

---

## 🚀 Core Features

### Cryptographic Verification

Calculates and monitors:

* SHA-256 hashes
* POSIX file permissions
* File sizes
* Last modified timestamps

This enables detection of unauthorized file additions, modifications, and deletions with high accuracy.

### Active Threat Intelligence

Seamlessly integrates with the VirusTotal v3 API.

When an unknown or modified file is detected, its SHA-256 hash can be automatically checked against multiple security vendors to identify potentially malicious files.

### Vault Immutability (Tamper Resistance)

Includes system-level hardening capabilities.

Using the GUI, administrators can apply the Linux immutable attribute (`chattr +i`) to monitored directories, preventing files from being:

* Modified
* Deleted
* Renamed

even by privileged users until the attribute is removed.

### Continuous Background Monitoring

Utilizes a multithreaded monitoring engine to perform integrity checks at configurable intervals without interrupting the graphical interface.

### Strict Security Posture

Enforces root privilege validation at application startup to ensure access to protected system resources and immutable file operations.

The trusted baseline is stored locally within the project root:

```bash
.baseline.json
```

### Centralized Logging

Records integrity violations, baseline generations, monitoring activity, and security alerts to:

```bash
/var/log/file_integrity_secure_vault.log
```

---

## 📂 Project Structure

```text
Linux-Secure-FIM/
│
├── folder_integrity_tool/
│   │
│   ├── .baseline.json      # Generated integrity baseline
│   ├── main.py             # Main entry point and privilege enforcement
│   │
│   ├── core/
│   │   ├── engine.py       # SHA-256 hashing and integrity verification logic
│   │   ├── utils.py        # Configuration, privilege checks, logging
│   │   └── virustotal.py   # VirusTotal API integration
│   │
│   └── gui/
│       └── app.py          # CustomTkinter graphical interface
│
├── LICENSE
└── README.md
```

---

## 🛠️ Prerequisites

### Operating System

* Linux
* POSIX-compliant filesystem
* `chattr` utility installed

### Privileges

The application must be executed with root privileges (`UID 0`) to:

* Read protected directories
* Apply immutable attributes
* Access restricted system resources

### Python Version

```text
Python 3.x
```

### Dependencies

```bash
pip install customtkinter requests
```

---

## ⚙️ Installation & Setup

### Clone the Repository

```bash
git clone https://github.com/thieveshkar/Linux-Secure-FIM.git
cd Linux-Secure-FIM/folder_integrity_tool
```

### Configure VirusTotal API Key

By default, the tool contains a placeholder API key inside:

```bash
core/utils.py
```

Replace it with your own VirusTotal API key:

```python
VT_API_KEY = "your_personal_virustotal_api_key_here"
```

Alternatively, the API key can be entered directly through the GUI during runtime.

---

## 💻 Usage

### Launch the Application

Run the application from the project directory with root privileges:

```bash
sudo python3 main.py
```

---

### Generate a Baseline

1. Enter one or more target paths in the **Target Paths** field.

Example:

```text
/opt/scan_folder, /var/www/html
```

2. Click **Generate Baseline**.

The tool will:

* Traverse the selected directories
* Calculate cryptographic hashes
* Capture file metadata
* Store the trusted state in `.baseline.json`

---

### Monitor Integrity

#### Manual Scan

Performs a one-time comparison against the stored baseline.

#### Start Monitor

Starts the background monitoring thread.

Detected file states include:

| Status   | Description           |
| -------- | --------------------- |
| MATCHED  | No changes detected   |
| ADDED    | New file detected     |
| MODIFIED | Existing file changed |
| DELETED  | File removed          |

---

### Vault Controls (Hardening)

#### Lock Vault

Applies:

```bash
chattr -R +i
```

to the selected directories.

This makes files and folders immutable.

#### Unlock Vault

Removes the immutable attribute:

```bash
chattr -R -i
```

allowing normal filesystem operations to resume.

---

## 🛡️ Security Considerations

### Time-of-Check to Time-of-Use (TOCTOU)

The monitoring engine operates using periodic polling (default: 60 seconds).

An attacker who modifies a file and restores its original contents and metadata before the next scan cycle may evade detection. This is a known limitation of interval-based monitoring systems.

### Baseline Integrity

The effectiveness of any File Integrity Monitoring system depends entirely on the trustworthiness of the initial baseline.

⚠️ Always ensure monitored directories are free of malicious or unauthorized files before generating a baseline.

If a compromised file exists during baseline creation, it will be considered trusted by the system.

---

## 📜 License

This project is licensed under the MIT License.

See the `LICENSE` file for details.
