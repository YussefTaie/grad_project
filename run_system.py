"""
run_system.py — IDS System Launcher
=====================================
بيشغّل المكونات الثلاثة مع بعض:
  1. api.py         - Flask prediction server (port 5000)
  2. agent_live_real.py - Live packet capture + flow analysis
  3. main_agent.py  - Offline PCAP/CSV analysis (اختياري)

الاستخدام:
  python run_system.py           # يشغّل API + Live Agent
  python run_system.py --offline flows.csv   # + offline analysis
  python run_system.py --api-only            # API فقط بدون capture

ملاحظة:
  - agent_live_real.py يحتاج Admin/root للـ Scapy sniffing
  - شغّل الـ terminal بـ "Run as Administrator"
"""

import argparse
import subprocess
import sys
import time
import os
import signal

PYTHON = sys.executable
CWD    = os.path.dirname(os.path.abspath(__file__))


# ──────────────────────────────────────────────────────────────
# Process Manager
# ──────────────────────────────────────────────────────────────
processes = []

def start_process(script: str, label: str) -> subprocess.Popen:
    print(f"\n[START] {label}")
    print(f"        Command: {PYTHON} {script}")
    proc = subprocess.Popen(
        [PYTHON, script],
        cwd=CWD,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    processes.append((label, proc))
    return proc


def stop_all():
    print("\n\n[STOP] Shutting down all IDS components...")
    for label, proc in processes:
        if proc.poll() is None:
            proc.terminate()
            print(f"  [STOPPED] {label} (PID {proc.pid})")
    print("[DONE] System stopped.")


def wait_for_api(host: str = "127.0.0.1", port: int = 5000, timeout: int = 15):
    """Waits until the Flask API is ready."""
    import socket
    print(f"\n[WAIT] Waiting for API at {host}:{port}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                print(f"[OK]   API is ready!")
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    print(f"[WARN] API did not start within {timeout}s — check api.py logs")
    return False


# ──────────────────────────────────────────────────────────────
# Signal Handler
# ──────────────────────────────────────────────────────────────
def on_signal(sig, frame):
    stop_all()
    sys.exit(0)

signal.signal(signal.SIGINT,  on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ──────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="IDS System Launcher")
    p.add_argument("--api-only",  action="store_true",
                   help="Start only the Flask API (no packet capture)")
    p.add_argument("--mode",      choices=["live", "pcap", "csv"], default="live",
                   help="Agent mode: live | pcap | csv  (default: live)")
    p.add_argument("--input",     metavar="FILE",
                   help="Input file for pcap or csv mode")
    p.add_argument("--watch",     action="store_true",
                   help="Watch CSV file continuously (csv mode only)")
    return p.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print("  IDS SYSTEM LAUNCHER")
    print("=" * 60)
    print(f"  API-only : {args.api_only}")
    print(f"  Mode     : {args.mode}")
    if args.input:
        print(f"  Input    : {args.input}")
    print("=" * 60)

    # 1. Start Flask API
    api_proc = start_process("api.py", "Flask API (port 5000)")
    time.sleep(2)
    wait_for_api()

    if args.api_only:
        print("\n[INFO] API-only mode — send POST to http://127.0.0.1:5000/predict")

    else:
        # 2. Build agent command
        agent_cmd = ["unified_agent.py", "--mode", args.mode]
        if args.input:
            agent_cmd += ["--input", args.input]
        if args.watch:
            agent_cmd.append("--watch")

        agent_label = f"Unified Agent (mode={args.mode})"
        if args.mode == "live":
            print("\n[INFO] *** Make sure this terminal is running as Administrator (Scapy) ***")

        print(f"\n[START] {agent_label}")
        proc = subprocess.Popen(
            [PYTHON] + agent_cmd,
            cwd=CWD,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        processes.append((agent_label, proc))

    # Keep alive
    print("\n[RUNNING] IDS system active. Press Ctrl+C to stop.\n")
    try:
        while True:
            for label, proc in processes:
                if proc.poll() is not None:
                    print(f"\n[ERROR] {label} crashed (exit {proc.returncode}), restarting in 5s...")
                    time.sleep(5)
            time.sleep(2)
    except KeyboardInterrupt:
        stop_all()


if __name__ == "__main__":
    main()
