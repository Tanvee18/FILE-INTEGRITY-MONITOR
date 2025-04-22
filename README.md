# FILE-INTEGRITY-MONITOR

🔐 File Integrity Monitoring System (FIM) with Metadata Verification and User Alerts
This is a lightweight File Integrity Monitoring (FIM) tool written in C, designed to help detect unauthorized changes to important files on your system. It tracks both file content integrity (via checksum) and file metadata changes (permissions, timestamps, ownership), and logs suspicious activity with optional desktop notifications.

🧩 Features

✅ Checksum-based integrity checking using XOR.

🔍 Metadata tracking: detects changes in inode, permissions, ownership, and timestamps.

👤 User verification: distinguishes changes made by the original user vs others.

📋 Access logging for file access events.

📁 Separate files for:

Integrity data (checksum_store.txt) :Stores file checksums to detect integrity violations.

Metadata history (metadata_store.txt): Stores metadata (inode, permissions, UID/GID, timestamps, username) of monitored files.

Access logs (access_log.txt): Logs important system events (e.g., integrity changes, errors).

SIEM-style alerts (fim_siem_log.txt): Tracks when the monitored file is accessed.

🚨 Desktop notification (Windows only) for real-time alerts.

🖥️ Cross-platform: Works on both Windows and UNIX-like systems (limited metadata support on Windows).

⚙️ How It Works
Prompts the user to enter a filename to monitor.

Logs the access in access_log.txt.

Verifies if any changes in metadata occurred.

Computes a checksum for the file.

Compares the checksum to a stored version:

If unchanged → logs success.

If changed → raises an alert, updates checksum.

Notifies via Windows MessageBox if tampering or metadata changes by another user are detected.


👤 Authors

Developed by:

P. TANVEE SATYA

B. HEMASRI VARAM

P. VENKAT PAVAN
