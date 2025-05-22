import os
import re
import subprocess
import requests
import urllib.parse
from queue import Queue
from threading import Thread, Lock
from bs4 import BeautifulSoup

import typer
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.validation import Validator, ValidationError

from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.align import Align
from rich.spinner import Spinner
from rich.live import Live
import itertools
import time

app = typer.Typer()
console = Console()

colors = [
    "cyan", "magenta", "green", "yellow", "bright_blue", "bright_red", "bright_magenta",
    "bright_cyan", "bright_green", "bright_yellow", "blue", "red", "white", "bright_white"
]
icons = ["🚀", "🔍", "⚡", "🛡️", "🕵️‍♂️", "💻", "🔧", "🔥", "🌐", "🔎"]

lock = Lock()
target_ip = None

color_cycle = itertools.cycle(colors)
icon_cycle = itertools.cycle(icons)

def print_fancy_panel(content, title):
    color = next(color_cycle)
    icon = next(icon_cycle)
    panel_title = Text(f"{icon} {title} {icon}", style=f"bold {color}")
    panel = Panel(
        content,
        title=panel_title,
        border_style=color,
        style=f"bold {color}",
        box=box.DOUBLE,
        padding=(1, 2),
        subtitle=Text("Powered by MrTalha", style=f"italic {color}")
    )
    console.print(panel)

class TargetValidator(Validator):
    def validate(self, document):
        text = document.text.strip()
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        domain_pattern = r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z]{2,})+$"
        if not (re.match(ip_pattern, text) or re.match(domain_pattern, text)):
            raise ValidationError(message="Invalid IP or domain format", cursor_position=len(text))

def print_banner():
    banner_text = r"""
███╗   ███╗███████╗████████╗ █████╗ ██╗     ██╗  ██╗ █████╗ 
████╗ ████║██╔════╝╚══██╔══╝██╔══██╗██║     ██║  ██║██╔══██╗
██╔████╔██║█████╗     ██║   ███████║██║     ███████║███████║
██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██║     ██╔══██║██╔══██║
██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗██║  ██║██║  ██║
╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
"""
    color = next(color_cycle)
    icon = next(icon_cycle)
    styled_banner = Text(banner_text, style=f"bold {color}")
    styled_banner.append(f"\n{icon} Welcome to the Ultimate Vulnerability Scanner {icon}\n", style=f"bold {color}")
    console.print(Align.center(styled_banner))

def loading_animation(task_name, duration=3):
    color = next(color_cycle)
    icon = next(icon_cycle)
    spinner = Spinner("dots")
    with Live(spinner, refresh_per_second=12, console=console) as live:
        start_time = time.time()
        while time.time() - start_time < duration:
            spinner.text = Text(f"{icon} {task_name} in progress... {icon}", style=f"bold {color}")
            time.sleep(0.1)
            # Change color and icon every 2 seconds
            if int(time.time() - start_time) % 2 == 0:
                color = next(color_cycle)
                icon = next(icon_cycle)

def check_tool_installed(tool_name):
    from shutil import which
    return which(tool_name) is not None

def run_nmap():
    name = "Nmap Scan"
    if not check_tool_installed("nmap"):
        print_fancy_panel("Nmap is not installed or not in PATH.", name)
        return None
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=4)
    try:
        result = subprocess.run(
            ["nmap", "-Pn", "-T4", "-sV", "--top-ports", "1000", target_ip],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout or "No output from nmap."
    except subprocess.TimeoutExpired:
        output = "Nmap scan timed out."
    except Exception as e:
        output = f"Error running nmap: {e}"
    print_fancy_panel(output, name)
    return output

def run_whatweb():
    name = "WhatWeb"
    if not check_tool_installed("whatweb"):
        print_fancy_panel("WhatWeb is not installed or not in PATH.", name)
        return
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=3)
    try:
        result = subprocess.run(
            ["whatweb", target_ip],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout or "No output from WhatWeb."
    except subprocess.TimeoutExpired:
        output = "WhatWeb scan timed out."
    except Exception as e:
        output = f"Error running WhatWeb: {e}"
    print_fancy_panel(output, name)

def detect_frontend():
    name = "Frontend Detection"
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=3)
    try:
        url = f"http://{target_ip}"
        res = requests.get(url, timeout=15)
        soup = BeautifulSoup(res.text, 'html.parser')
        found = set()
        for tag in soup.find_all(['link', 'script']):
            src = tag.get('href') or tag.get('src')
            if src:
                src_lower = src.lower()
                if 'bootstrap' in src_lower:
                    found.add("Bootstrap")
                if 'react' in src_lower:
                    found.add("React")
                if 'vue' in src_lower:
                    found.add("Vue.js")
                if 'wp-content/themes' in src_lower:
                    match = re.search(r'wp-content/themes/([^/]+)', src_lower)
                    if match:
                        found.add("WP Theme: " + match.group(1))
        output = "Detected frontend technologies:\n" + "\n".join(f"- {f}" for f in found) if found else "No known frontend technologies detected."
    except Exception as e:
        output = f"Error detecting frontend: {e}"
    print_fancy_panel(output, name)

def analyze_source():
    name = "Source Analysis"
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=3)
    try:
        url = f"http://{target_ip}"
        res = requests.get(url, timeout=15)
        comments = re.findall(r'<!--(.*?)-->', res.text, re.DOTALL)
        comments_text = "\n".join(f"- {c.strip()}" for c in comments) if comments else "No HTML comments found."
        soup = BeautifulSoup(res.text, 'html.parser')
        links = set()
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href.startswith("http") or href.startswith("/"):
                links.add(href)
        links_text = "\n".join(f"- {l}" for l in links) if links else "No links found."
        output = f"HTML Comments:\n{comments_text}\n\nLinks and Directories:\n{links_text}"
    except Exception as e:
        output = f"Error analyzing source: {e}"
    print_fancy_panel(output, name)

def read_robots():
    name = "robots.txt Reader"
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=2)
    try:
        url = f"http://{target_ip}/robots.txt"
        res = requests.get(url, timeout=10)
        output = res.text if res.status_code == 200 else f"robots.txt not found (status code {res.status_code})"
    except Exception as e:
        output = f"Error reading robots.txt: {e}"
    print_fancy_panel(output, name)

def vulnerability_detection(nmap_output):
    name = "Vulnerability Detection"
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=4)

    service_lines = []
    for line in nmap_output.splitlines():
        if re.match(r"^\d+/tcp\s+open\s+", line):
            service_lines.append(line.strip())

    queries = []
    for line in service_lines:
        parts = line.split()
        if len(parts) >= 4:
            service_name = parts[2]
            service_version = " ".join(parts[3:])
            queries.append(f"{service_name} {service_version}")
        elif len(parts) >= 3:
            queries.append(parts[2])

    exploitdb_links = set()
    github_links = set()
    google_searches = []

    for query in queries:
        try:
            search_url = f"https://www.exploit-db.com/search?cve={urllib.parse.quote(query)}"
            res = requests.get(search_url, timeout=10)
            if res.status_code == 200:
                links = re.findall(r'href="(/exploits/\d+)"', res.text)
                for link in links:
                    full_link = f"https://www.exploit-db.com{link}"
                    exploitdb_links.add(full_link)
        except Exception:
            pass

        try:
            github_search_url = f"https://github.com/search?q={urllib.parse.quote(query)}+exploit&type=repositories"
            github_links.add(github_search_url)
        except Exception:
            pass

        google_searches.append(f"https://www.google.com/search?q={urllib.parse.quote(query + ' exploit')}")

    output = ""
    if exploitdb_links:
        output += "Found ExploitDB links:\n"
        for link in sorted(exploitdb_links):
            output += f" - {link}\n"
    else:
        output += "No ExploitDB exploits found.\n"

    if github_links:
        output += "\nGitHub PoC search URLs:\n"
        for link in sorted(github_links):
            output += f" - {link}\n"
    else:
        output += "No GitHub PoC links found.\n"

    output += "\nGoogle Search URLs for Exploits:\n"
    for link in google_searches:
        output += f" - {link}\n"

    print_fancy_panel(output, name)

def dir_buster_worker(target, queue, results_list, session):
    while True:
        path = queue.get()
        if path is None:
            break
        url = f"http://{target}/{path}"
        try:
            r = session.get(url, timeout=3)
            if r.status_code < 400:
                with lock:
                    results_list.append((r.status_code, url))
        except:
            pass
        queue.task_done()

def load_wordlist_from_file(filepath):
    if os.path.isfile(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            return []
    return []

def directory_buster():
    name = "Directory Buster"
    console.print(f"[yellow]Starting {name}...[/yellow]")
    loading_animation(name, duration=5)

    wordlists = []

    fast_wordlist_url = "https://raw.githubusercontent.com/hemaabokila/admin-panel-finder/main/wordlist/wordlist.txt"
    try:
        res = requests.get(fast_wordlist_url, timeout=15)
        if res.status_code == 200:
            fast_list = [line.strip() for line in res.text.splitlines() if line.strip()]
            wordlists.append(fast_list)
    except Exception:
        pass

    seclist_1 = "/usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt"
    seclist_1_list = load_wordlist_from_file(seclist_1)
    if seclist_1_list:
        wordlists.append(seclist_1_list)

    seclist_2 = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    seclist_2_list = load_wordlist_from_file(seclist_2)
    if seclist_2_list:
        wordlists.append(seclist_2_list)

    combined_wordlist = []
    seen = set()
    for wl in wordlists:
        for word in wl:
            if word not in seen:
                combined_wordlist.append(word)
                seen.add(word)

    if not combined_wordlist:
        combined_wordlist = ["admin", "login", "dashboard", "config", "uploads", "images", "css", "js"]

    queue = Queue()
    results_list = []
    num_threads = 70
    session = requests.Session()

    for path in combined_wordlist:
        queue.put(path)

    threads = []
    for _ in range(num_threads):
        t = Thread(target=dir_buster_worker, args=(target_ip, queue, results_list, session))
        t.daemon = True
        t.start()
        threads.append(t)

    start_time = time.time()
    timeout = 90
    while not queue.empty() and (time.time() - start_time) < timeout:
        time.sleep(0.1)

    for _ in range(num_threads):
        queue.put(None)
    for t in threads:
        t.join(timeout=1)

    if results_list:
        output = "Discovered directories and files:\n"
        for status_code, url in sorted(results_list, key=lambda x: x[0]):
            output += f"[{status_code}] {url}\n"
    else:
        output = "No directories or files found."
    print_fancy_panel(output, name)

def run_all():
    nmap_output = run_nmap()
    run_whatweb()
    detect_frontend()
    analyze_source()
    read_robots()
    if nmap_output:
        vulnerability_detection(nmap_output)
    else:
        print_fancy_panel("Skipping Vulnerability Detection due to missing Nmap output.", "Vulnerability Detection")
    directory_buster()

def interactive_shell():
    global target_ip
    commands = {
        "nmap": run_nmap,
        "whatweb": run_whatweb,
        "frontend": detect_frontend,
        "source": analyze_source,
        "robots": read_robots,
        "vuln": lambda: vulnerability_detection(run_nmap() or ""),
        "dirbuster": directory_buster,
        "all": run_all,
        "help": None,
        "exit": None,
        "quit": None,
    }
    completer = WordCompleter(list(commands.keys()), ignore_case=True)
    console.print("[bold green]Type 'help' to see available commands.[/bold green]")
    while True:
        try:
            user_input = prompt("MrTalha> ", completer=completer).strip().lower()
            if user_input in ("exit", "quit"):
                console.print("[bold red]Exiting...[/bold red]")
                break
            elif user_input == "help":
                help_text = "\n".join([
                    "[bold cyan]Available commands:[/bold cyan]",
                    "  nmap       - Run Nmap scan",
                    "  whatweb    - Run WhatWeb scan",
                    "  frontend   - Detect frontend technologies",
                    "  source     - Analyze source code comments and links",
                    "  robots     - Read robots.txt",
                    "  vuln       - Run vulnerability detection (requires nmap output)",
                    "  dirbuster  - Run directory buster",
                    "  all        - Run all scans sequentially",
                    "  help       - Show this help message",
                    "  exit/quit  - Exit the shell",
                ])
                console.print(help_text)
            elif user_input in commands:
                func = commands[user_input]
                if func:
                    func()
            elif user_input == "":
                continue
            else:
                console.print(f"[red]Unknown command: {user_input}[/red]")
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted. Type 'exit' or 'quit' to exit.[/bold red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

@app.command()
def main():
    global target_ip
    print_banner()
    target_ip = prompt("Enter target IP or domain: ", validator=TargetValidator(), validate_while_typing=False).strip()
    interactive_shell()

if __name__ == "__main__":
    app()
