# mega.py

Overview:
This Python script retrieves the total size and structure of public MEGA file or folder links using the MEGA API. It supports decryption of names (if the link key is provided and pycryptodome is installed) and outputs a formatted summary, including a tree view for folders.

Features:
Calculates total size in bytes and human-readable format (e.g., KB, MB, GB).
Displays folder structure as a tree with names, types, sizes, and timestamps (if available).
Handles file links with name and size output.
Graceful fallback for missing decryption libraries or invalid keys (shows encrypted handles).
Maps MEGA API error codes to readable messages.
Command-line flags: --verbose for detailed logs, --summary to skip the tree for large folders, --export json to save structure as JSON.

Requirements:
Python 3.6 or higher.
Required: requests (pip install requests).
Optional (for decryption): pycryptodome (pip install pycryptodome).
For testing: pytest and requests-mock (pip install pytest requests-mock).

Installation:
Clone the repository:
git clone https://github.com/yourusername/mega-py.git
cd mega-py

Install dependencies:
pip install -r requirements.txt

(If no requirements.txt, manually install requests and optionally pycryptodome.)

Usage
Run the script with a public MEGA URL:
python mega.py https://mega.nz/folder/ABC123#def456

Example output for a folder:

Total Folder Size: 1.23 GB (1324567890 bytes)

Folder Structure:

RootFolder (Folder)
SubFolder (Folder)
file1.txt (File - 500.00 MB [2023-01-01 12:00:00])
file2.jpg (File - 1.00 KB [2023-02-02 13:00:00])
Flags:

--verbose: Enable INFO-level logging.
--summary: Print only the total size.
--export json: Export folder structure to mega_structure.json.

For files:
python mega.py https://mega.nz/file/DEF456#ghi789

Output:
File Name: example.file
Total File Size: 1.00 MB (1048576 bytes)

Testing:
Run unit tests:
pytest test_mega.py

Tests cover formatting, decoding, and mocked API responses.

Contributing:
Fork the repository, make changes, and submit a pull request. Ensure code follows PEP 8 (use black and flake8 for formatting/linting).

License:
MIT License. See LICENSE for details.
