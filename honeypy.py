# honeypy.py (updated)
import argparse
import subprocess
import sys
import time
import os

def spawn_python_call(code):
    """
    Spawn a separate Python process that runs the provided one-liner code.
    Uses same interpreter (sys.executable) and unbuffered output so prints appear immediately.
    """
    cmd = [sys.executable, "-u", "-c", code]
    return subprocess.Popen(cmd)

def make_honeypot_call_ssh(address, port, username, password):
    # produce python code that imports ssh_honeypot and calls honeypot(...)
    u = repr(username) if username is not None else "None"
    p = repr(password) if password is not None else "None"
    code = (
        "import ssh_honeypot\n"
        f"ssh_honeypot.honeypot({repr(address)}, {int(port)}, {u}, {p})\n"
    )
    return code

def make_honeypot_call_http(port, username, password):
    # produce python code that imports web_honeypot and calls run_web_honeypot(...)
    u = repr(username)
    p = repr(password)
    code = (
        "import web_honeypot\n"
        f"web_honeypot.run_web_honeypot(port={int(port)}, input_username={u}, input_password={p})\n"
    )
    return code

def monitor_process(proc):
    try:
        while True:
            if proc.poll() is not None:
                print(f"[*] Process exited (code {proc.returncode}).", flush=True)
                break
            time.sleep(0.4)
    except KeyboardInterrupt:
        print("\n Exiting HONEYPY... (KeyboardInterrupt)\n", flush=True)
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=1)
        except Exception:
            pass
        sys.exit(0)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)
    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-w', '--http', action='store_true')
    args = parser.parse_args()

    try:
        if args.ssh:
            # normalize username/password to None when not provided
            username = args.username if args.username not in (None, "") else None
            password = args.password if args.password not in (None, "") else None

            print("[-] Running SSH Honeypot...", flush=True)
            print(f"DEBUG: address={args.address} port={args.port} username={username} password={'***' if password else None}", flush=True)

            code = make_honeypot_call_ssh(args.address, args.port, username, password)
            proc = spawn_python_call(code)
            monitor_process(proc)

        elif args.http:
            # provide defaults for http honeypot if not specified
            username = args.username if args.username not in (None, "") else "admin"
            password = args.password if args.password not in (None, "") else "password"

            print("[-] Running HTTP WordPress Honeypot...", flush=True)
            print(f"DEBUG: port={args.port} Username={username}, Password={'***' if password else None}", flush=True)

            code = make_honeypot_call_http(args.port, username, password)
            proc = spawn_python_call(code)
            monitor_process(proc)

        else:
            print("[!] Choose a honeypot type (SSH --ssh) or (HTTP --http).", flush=True)

    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("\n Exiting HONEYPY... (KeyboardInterrupt)\n", flush=True)
    except Exception as e:
        print(f"\nUnexpected error: {e}\n", flush=True)


if __name__ == "__main__":
    main()
