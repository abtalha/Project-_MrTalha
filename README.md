# Project-_MrTalha
For Oscp All in One
# Ultimate Vulnerability Scanner

![Banner](https://img.shields.io/badge/Created%20by-MrTalha-brightgreen)

An interactive, all-in-one vulnerability scanner and reconnaissance tool built in Python. It combines powerful scanning utilities like Nmap, WhatWeb, directory busting, frontend detection, source analysis, robots.txt reading, and vulnerability detection into a user-friendly interactive shell similar to `msfconsole`.

---

## Features

- **Interactive Shell:** Run scans and commands interactively with autocomplete and help.
- **Nmap Scan:** Service and version detection on top 1000 ports.
- **WhatWeb Scan:** Web technology fingerprinting.
- **Frontend Detection:** Detects Bootstrap, React, Vue.js, WordPress themes, and more.
- **Source Analysis:** Extracts HTML comments and links.
- **robots.txt Reader:** Fetches and displays robots.txt content.
- **Vulnerability Detection:** Searches ExploitDB, GitHub, and Google for exploits based on Nmap results.
- **Directory Buster:** Multi-threaded directory and file discovery using multiple wordlists.
- **Colorful and Iconic UI:** Uses Rich for beautiful colored output and spinners.

---

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/ultimate-vulnerability-scanner.git
   cd ultimate-vulnerability-scanner

2. **Install dependencies:**

This tool requires Python 3.7+.

bash

pip install -r requirements.txt
```
The main dependencies are:
typer
prompt_toolkit
rich
requests
beautifulsoup4
```
Usage
Run the tool with:

bash
```
python3 MrTalha.py
```
You will be prompted to enter a target IP address or domain name. After that, you enter an interactive shell where you can run commands:
## Command Line Options

| Command    | Description                                     |
|------------|-------------------------------------------------|
| `nmap`     | Run Nmap scan                                   |
| `whatweb`  | Run WhatWeb scan                                |
| `frontend` | Detect frontend technologies                    |
| `source`   | Analyze source code comments and links          |
| `robots`   | Read robots.txt                                 |
| `vuln`     | Run vulnerability detection (requires Nmap output) |
| `dirbuster`| Run directory buster                            |
| `all`      | Run all scans sequentially                      |
| `help`     | Show help message                               |
| `exit`     | Exit the shell                                  |
Example:
```

pentestgpt> nmap
pentestgpt> vuln
pentestgpt> all
pentestgpt> exit
```


## License
This project is licensed under the MIT License.

## Author
Created by MrTalha
