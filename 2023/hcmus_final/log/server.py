import os
import time
import signal
import random
import libscrc
import threading
import socketserver
from Crypto.Util.number import *

LEN = 4
FLAG_FILE = os.getenv("FLAG")
PORT = int(os.getenv("APP_PORT"))
HOST = "0.0.0.0"

assert FLAG_FILE is not None, "Environment variable FLAG not set"
assert PORT is not None, "Environment variable APP_PORT not set"


def timeout_handler(self, signum):
    raise TimeoutError


class Service(socketserver.BaseRequestHandler):
    def handle(self):
        self.flag = self.get_flag()
        try:
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(10)

            n = bytes_to_long(os.urandom(LEN))
            self.send(str(n) + "\n")
            self.send("P=")
            P = int(self.receive())
            self.send("E=")
            E = int(self.receive())
            self.send("M=")
            M = self.receive()
            if P >> (82 - LEN * 8) == n:
                C = libscrc.darc82(M)
                if pow(bytes_to_long(M), E, P) == C % P:
                    self.send(self.flag + "\n")
        except Exception as e:
            self.request.close()

    def get_flag(self):
        with open(FLAG_FILE, "r") as f:
            return f.readline()

    def send(self, string: str):
        self.request.sendall(string.encode("utf-8"))

    def receive(self):
        return self.request.recv(1024).strip()


class ThreadedService(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


def main():
    service = Service
    server = ThreadedService((HOST, PORT), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")
    # Now let the main thread just wait...
    while True:
        time.sleep(10)


if __name__ == "__main__":
    main()
