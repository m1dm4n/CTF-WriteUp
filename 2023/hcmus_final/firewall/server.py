import time
import libscrc
import threading
import socketserver
import os


def firewall(data):
    if libscrc.ecma182(data) == libscrc.ecma182(b"Exit"):
        return True
    return False


FLAG_FILE = os.getenv("FLAG")
PORT = int(os.getenv("APP_PORT"))
HOST = "0.0.0.0"

assert FLAG_FILE is not None, "Environment variable FLAG not set"
assert PORT is not None, "Environment variable APP_PORT not set"


class Service(socketserver.BaseRequestHandler):
    def handle(self):
        self.flag = self.get_flag()
        self.send(f"Hello. What do you want?\n")
        userInput = self.receive()
        if firewall(userInput):
            if userInput.startswith(b"Flag"):
                self.send(self.flag + "\n")
            elif userInput.startswith(b"Exit"):
                self.send("Good bye!\n")
            else:
                self.send("Hein\n")

    def get_flag(self):
        with open(FLAG_FILE, "r") as f:
            return f.readline()

    def send(self, string: str):
        self.request.sendall(string.encode("utf-8"))

    def receive(self):
        return self.request.recv(1024).strip()


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
