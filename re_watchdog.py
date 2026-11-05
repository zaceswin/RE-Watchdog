### This script uses psutil to iterate through active processes and inspects the /proc/ filesystem to look for TracerPid values, which indicate a process is currently being debugged or hooked. 
###

#!/usr/bin/env python3
import time
import psutil
from datetime import datetime

# Common RE and dynamic analysis tools
RE_TOOLS = {
    'gdb', 'radare2', 'r2', 'cutter', 'ghidra', 'ida', 'ida64',
    'frida-server', 'strace', 'ltrace', 'wireshark', 'edb', 'x64dbg'
}

def check_running_re_tools():
    """Scans process list for known RE framework binaries."""
    detected = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in RE_TOOLS:
                detected.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return detected

def check_ptrace_attachments():
    """Checks /proc/<pid>/status to see if a process is actively being traced."""
    traced = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            with open(f"/proc/{proc.info['pid']}/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split("\t")[1])
                        if tracer_pid != 0: # TracerPid > 0 means it's being debugged
                            try:
                                tracer_name = psutil.Process(tracer_pid).name()
                            except psutil.NoSuchProcess:
                                tracer_name = "Unknown/Dead"
                            
                            traced.append({
                                "target_pid": proc.info['pid'],
                                "target_name": proc.info['name'],
                                "tracer_pid": tracer_pid,
                                "tracer_name": tracer_name
                            })
        except (FileNotFoundError, ProcessLookupError, psutil.AccessDenied):
            pass
    return traced

def main():
    print(f"[*] {datetime.now().strftime('%H:%M:%S')} - Starting RE-Watchdog...")
    print("[*] Monitoring for Reverse Engineering activity and active ptrace hooks.\n")
    
    try:
        while True:
            tools = check_running_re_tools()
            traces = check_ptrace_attachments()
            
            if tools or traces:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"[!] ALERT: RE Activity Detected at {timestamp}")
                
                if tools:
                    print("  [+] Active RE Tools:")
                    for t in tools:
                        print(f"      - {t['name']} (PID: {t['pid']})")
                
                if traces:
                    print("  [+] Processes under active tracing/debugging:")
                    for t in traces:
                        print(f"      - {t['target_name']} (PID: {t['target_pid']}) is hooked by {t['tracer_name']} (PID: {t['tracer_pid']})")
                
                print("-" * 50)
                
            time.sleep(5) # Poll interval
            
    except KeyboardInterrupt:
        print("\n[*] Stopping RE-Watchdog. Stay secure.")

if __name__ == "__main__":
    main()
# Test environment initialized
