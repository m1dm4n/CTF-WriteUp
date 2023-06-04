import os
import time
import random
import threading
import socketserver
import numpy as np

FLAG_FILE = os.getenv("FLAG")
PORT = os.getenv("APP_PORT")
HOST = "0.0.0.0"

assert FLAG_FILE is not None, "Environment variable FLAG not set"
assert PORT is not None, "Environment variable APP_PORT not set"


class Service(socketserver.BaseRequestHandler):
    def handle(self):
        self.flag = self.get_flag()
        assert len(self.flag) == 31
        self.user_id = time.time()
        self.send(f"Welcome user: {self.user_id}\n")
        self.salt = [b"\x00", b"\x01", b"\x02", b"\x03"][
            round(2 * np.random.random())
        ]  # os.urandom(1) #A harder version if you want to try
        self.send(
            f"Here is your encoded flag: {self.encode(self.flag, self.gen_key(self.user_id), self.salt)}\n"
        )

    def get_flag(self):
        with open(FLAG_FILE, "rb") as f:
            return f.readline()

    def encode(self, data, key, salt):
        return sum([a * b for a, b in zip(key, data + salt)])

    def gen_key(self, user_id):
        random.seed(user_id)
        return [random.randrange(512) for i in range(32)]

    def send(self, string: str):
        self.request.sendall(string.encode("utf-8"))

    def receive(self):
        return self.request.recv(1024).strip().decode("utf-8")


class ThreadedService(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
    socketserver.DatagramRequestHandler,
):
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
