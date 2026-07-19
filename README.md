# Port Scanner

A lightweight, fast, and multi-threaded Python-based network reconnaissance and security assessment tool.

> [!WARNING]
> **Legal Disclaimer:** Only scan systems you own or have explicit written authorization to test. Unauthorized scanning may be illegal in your jurisdiction (e.g., under the U.S. Computer Fraud and Abuse Act or similar laws elsewhere). The author assumes no liability for misuse or damage caused by this tool.

---

## 🚀 Features

* **⚡ Multi-threaded TCP Connect Scanning:** Highly performant scanning using Python's `ThreadPoolExecutor` to speed up scans over wide ranges of ports.
* **🌐 UDP Scanning:** Best-effort, heuristic-based scan logic to identify `open`, `open|filtered`, or `closed` UDP ports.
* **🎏 Banner Grabbing:** Performs lightweight probing on open TCP ports (such as SSH, HTTP, FTP, etc.) to extract service banners and identify running software.
* **🧩 Flexible Port Specification:** Scan individual ports, port ranges, or comma-separated lists of both (e.g., `80`, `1-1024`, `22,80,443,8000-8100`).
* **⚙️ Tunable Performance:** Customize thread counts (`-t`) and individual socket timeouts (`--timeout`) to suit network conditions.
* **📊 Automation-Friendly JSON Export:** Easily save scan results to a structured JSON file (`-o` / `--output`) for ingestion into other security tools.
* **📦 Zero Dependencies:** Written entirely in pure Python using standard libraries (`socket`, `threading`, `concurrent.futures`, `argparse`, `json`). No third-party packages required!

---

## 📋 Requirements

* **Python:** 3.7+
* **Operating System:** Platform-agnostic (Windows, macOS, Linux)

---

## 🔧 Installation & Verification

Since the project uses only the Python standard library, no complex installation is required.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/joelkirubainathan/port-scanner.git
   cd port-scanner
   ```
2. **Ensure python is installed:**
   ```bash
   python --version
   ```
3. **Verify running the script:**
   Run a quick scan against your localhost loopback (`127.0.0.1`) on standard ports to verify the installation:
   ```bash
   python port-scanner.py 127.0.0.1 -p 135,445 -o test_output.json
   ```

---

## 📖 Usage

Run the scanner directly from the command line using `python port-scanner.py` followed by the target and options.

### CLI Options

| Argument / Flag | Description | Default |
| :--- | :--- | :--- |
| `target` | Target IP address or hostname (positional) | *Required* |
| `-p`, `--ports` | Ports to scan (e.g. `80`, `1-1024`, `22,80,443`) | `1-1024` |
| `-t`, `--threads` | Number of concurrent threads to dispatch | `100` |
| `--timeout` | Socket timeout in seconds per port | `1.0` |
| `--udp` | Enable heuristic-based UDP port scanning | `off` |
| `--no-banner` | Disable service banner grabbing on open TCP ports | `off` |
| `-o`, `--output` | Write structured JSON scan results to a file | *None* |
| `-v`, `--verbose` | Show verbose log messages and connection errors | `off` |

### Example Commands

1. **Default Scan:** Scan common TCP ports 1–1024 with 100 threads on localhost.
   ```bash
   python port-scanner.py 127.0.0.1
   ```

2. **Custom Target & Specific Ports:** Scan specific ports on a remote domain name.
   ```bash
   python port-scanner.py example.com -p 22,80,443,8080
   ```

3. **High-Speed Full Port Scan:** Scan all 65,535 TCP ports with an increased thread pool count of 250 threads.
   ```bash
   python port-scanner.py 192.168.1.50 -p 1-65535 -t 250
   ```

4. **TCP & UDP Combined Scan:** Run a custom-timeout scan detecting both TCP and UDP ports on a server.
   ```bash
   python port-scanner.py 192.168.1.1 -p 53,80,137,443 --udp --timeout 0.5
   ```

5. **JSON Export with Banner Grabbing:** Perform a scan, resolve banners, and output the structured findings to a report file.
   ```bash
   python port-scanner.py scanme.nmap.org -p 21-25,80,443 -o scan_results.json
   ```

6. **Quiet / No-Banner Scan with Verbose Logging:** Scan without banner grabbing while capturing detailed connection warnings.
   ```bash
   python port-scanner.py 192.168.1.100 -p 80,443 --no-banner -v
   ```

---

## 🖥️ Example Output

### Console Output
```text
============================================================
 PORT SCANNER — for authorized security testing only
============================================================
[*] Target:      scanme.nmap.org (45.33.32.156)
[*] Ports:       4 port(s)
[*] Protocol(s): TCP + UDP
[*] Threads:     100
[*] Started at:  2026-07-19 23:50:00
------------------------------------------------------------
[+] 22/tcp     open           SSH             -> SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+] 80/tcp     open           HTTP            -> HTTP/1.1 200 OK
[+] 443/tcp    open           HTTPS
[+] 53/udp     open|filtered  DNS
------------------------------------------------------------
[*] Scan completed in 1.42s — 4 open port(s) found.
```

### JSON Results Export (`scan_results.json`)
```json
{
  "target": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "scanned_ports": 4,
  "duration_seconds": 1.42,
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "SSH",
      "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "HTTP",
      "banner": "HTTP/1.1 200 OK"
    },
    {
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": "HTTPS",
      "banner": ""
    },
    {
      "port": 53,
      "protocol": "udp",
      "state": "open|filtered",
      "service": "DNS",
      "banner": ""
    }
  ]
}
```

---

## 🛠️ How It Works

Below is the step-by-step lifecycle of a typical port scan execution:

```mermaid
flowchart TD
    A[Start: Main Script Execution] --> B[Host Resolution]
    B --> C[Thread Dispatch ThreadPoolExecutor]
    C --> D{Protocol Scan Logic}
    
    D -->|TCP Connect Scan| E[Socket Connect Attempt]
    D -->|UDP Scan Heuristic| F[Send Zero-byte Datagram]
    
    E -->|Success / Open| G{Banner Grabbing Enabled?}
    E -->|Closed / Error| J[Discard Port]
    
    F -->|Timeout / No Response| H[Open|Filtered State]
    F -->|UDP Response Data| I[Open State]
    F -->|ICMP Unreachable| J
    
    G -->|Yes| K[Send Light HTTP/Service Probes]
    G -->|No / Skip| L[Live Console Reporting]
    
    K --> L
    H --> L
    I --> L
    
    L --> M[Summary Output & JSON File Export]
    J --> M
    M --> N[End]
```

1. **Host Resolution:** The tool checks the target format. Hostnames are resolved to IPv4 addresses using `socket.gethostbyname()`; literral IP addresses are verified directly.
2. **Thread Dispatch:** The port list is expanded and fed to a `ThreadPoolExecutor` context manager running up to the configured limit (default: `100` worker threads).
3. **Scan Execution:**
   * **TCP Logic:** Attempts a socket connection via `connect_ex()`. A return value of `0` denotes an open port.
   * **UDP Logic:** Sends a payload containing `\x00`. If an ICMP port unreachable response is received, the port is considered closed. If a response is received, it is `open`. If the timeout expires with no reply, it defaults to the ambiguous `open|filtered` state.
4. **Banner Grabbing:** If enabled, the tool queries open TCP ports for details. For silent, request-first protocols (such as HTTP), a small probe request (`HEAD / HTTP/1.1`) is dispatched to retrieve headers.
5. **Live Reporting:** Thread-safe console prints (backed by `threading.Lock()`) post discovered open ports in real-time.
6. **Summary & Export:** The scan completes with a total execution time summary, compiles all open port results sorted by protocol/port, and exports them to a structured JSON file if `--output` is specified.

---

## ⚠️ Disclaimer

This tool is designed for educational, local network troubleshooting, and authorized penetration testing purposes only. Executing port scans against hosts without explicit prior written authorization is highly discouraged and potentially illegal under local and international computer crime laws. The author (`Joel Kirubainathan`) assumes no responsibility for any unauthorized behavior or damages resulting from the use of this software.

---

## 📄 License

This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

* **Joel Kirubainathan** - *Author / Maintainer* - [GitHub](https://github.com/joelkirubainathan)
