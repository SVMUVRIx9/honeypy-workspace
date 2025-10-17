# ssh_honeypot.py
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading
import sys

logging_format = logging.Formatter('%(asctime)s %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 MyCorp-Jumpbox_1.0"

# try to load host key, show clear error if missing
try:
    host_key = paramiko.RSAKey.from_private_key_file('server.key')
except Exception as e:
    host_key = None
    sys.stderr.write(f"[!] Warning: could not load server.key: {e}\n")

funnel_logger = logging.getLogger("FunnelLogger")
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger("CredsLogger")
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

def emulated_shell(channel, client_ip):
    channel.send(b'corporate-jumpbox2$ ')
    command = b""
    while True:
        try:
            char = channel.recv(1)
            if not char:
                break
            if char in [b'\x7f', b'\b']:
                if len(command) > 0:
                    command = command[:-1]
                    channel.send(b'\b \b')
                continue
            channel.send(char)
            command += char
            # accept CR or LF as Enter
            if char in (b'\r', b'\n'):
                command_str = command.strip().decode(errors="ignore")
                funnel_logger.info(f"{client_ip} executed: {command_str}")
                if command.strip() == b'exit':
                    response = b'\nGoodbye!\r\n'
                    channel.send(response)
                    channel.close()
                    return
                elif command.strip() == b'pwd':
                    response = b'/usr/local/\r\n'
                elif command.strip() == b'whoami':
                    response = b'corpuser1\r\n'
                elif command.strip() == b'ls':
                    response = b'jumpbox1.conf\r\n'
                elif command.strip() == b'cat jumpbox1.conf':
                    response = b'Go to deeboodah.com\r\n'
                elif command.strip() == b'id':
                    response = b'uid=1001(corpuser1) gid=1001(corpusers) groups=1001(corpusers)\r\n'
                elif command.strip() == b'uname':
                    response = b'Linux MyCorp-Jumpbox2 5.15.0-xxx-generic x86_64 GNU/Linux\r\n'
                elif command.strip() == b'hostname':
                    response = b'MyCorp-Jumpbox2\r\n'
                elif command.strip() == b'ls -la':
                    response = (
                        b'total 20\r\n'
                        b'drwxr-xr-x 3 corpuser1 corpusers 4096 Apr 12 10:00 .\r\n'
                        b'drwxr-xr-x 5 root root 4096 Apr 12 09:50 ..\r\n'
                        b'-rw-r--r-- 1 corpuser1 corpusers 123 Apr 12 09:59 jumpbox1.conf\r\n'
                    )
                elif command.strip() == b'netstat -tuln':
                    response = (
                        b'Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n'
                        b'tcp        0      0 0.0.0.0:2223            0.0.0.0:*               LISTEN\r\n'
                    )
                elif command.strip() == b'ps aux':
                    response = (
                        b'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n'
                        b'root         1  0.0  0.1 169084  6008 ?        Ss   Apr12   0:06 /sbin/init\r\n'
                        b'root      1023  0.0  0.2  46232  8320 ?        Ss   Apr12   0:01 /usr/sbin/sshd -D\r\n'
                    )
                else:
                    response = b'bash: ' + command.strip() + b': command not found\r\n'
                channel.send(b'\r\n' + response + b'corporate-jumpbox2$ ')
                command = b""
        except Exception as e:
            funnel_logger.error(f"Shell error: {e}")
            try:
                channel.close()
            except Exception:
                pass
            break

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        creds_logger.info(f"{self.client_ip} attempted login -> username: {username}, password: {password}")
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)
        if host_key is None:
            raise RuntimeError("Host key not loaded (server.key missing or invalid).")
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened. Closing transport.")
            transport.close()
            client.close()
            return
        standard_banner = b"\nWelcome to the GOD VALLEY !! (Ubuntu 24.04 LTS)\r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)
    except Exception as error:
        print(error)
        print("!!! CLOSED !!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!! Error !!!")
        client.close()

def honeypot(address, port, username=None, password=None):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    print(f"SSH Server is listening on port {port}.")
    while True:
        try:
            client, addr = socks.accept()
            t = threading.Thread(target=client_handle, args=(client, addr, username, password))
            t.daemon = True
            t.start()
        except Exception as error:
            print(error)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-a','--address', default='127.0.0.1', help='bind address')
    parser.add_argument('-p','--port', type=int, default=2223, help='port')
    parser.add_argument('-u','--username', type=str, default=None)
    parser.add_argument('-pw','--password', type=str, default=None)
    args = parser.parse_args()
    honeypot(args.address, args.port, args.username, args.password)
