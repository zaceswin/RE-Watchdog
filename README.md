# RE-Watchdog 🕵️‍♂️

**RE-Watchdog** is a lightweight, Python-based security tool designed to monitor Linux environments for active reverse engineering tools, debuggers, and dynamic binary instrumentation frameworks. 

## Features
- **Binary Detection:** Scans active processes for known RE frameworks (Ghidra, IDA, Radare2, Frida, GDB, etc.).
- **Anti-Debugging via `/proc`:** Detects active `ptrace` hooks by analyzing `TracerPid` across process statuses. 
- **Modular Pipeline Ready:** Easily extensible to forward logs to external SIEMs, syslog, or automated SOC pipelines.

## Installation

Clone the repository and install the required dependencies:

```bash
git clone [https://github.com/YOUR_USERNAME/RE-Watchdog.git](https://github.com/YOUR_USERNAME/RE-Watchdog.git)
cd RE-Watchdog
pip install -r requirements.txt
