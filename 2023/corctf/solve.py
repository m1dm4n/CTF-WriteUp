from gmpy2 import mpz, log2, powmod
from queue import Queue
from threading import Thread
from pwn import log
import sys
from functools import cache

class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                print(str(e))
            finally:
                self.tasks.task_done()


class ThreadPool:
    """Pool of threads consuming tasks from a queue"""

    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()


@cache
def invert(a, b):
    if a == 0:
        return 0
    return powmod(a, -1, b)


def dec(key, out):
    length = len(out)
    if length != 1:
        v19 = mpz(log2(0x10001)) - mpz(log2(length))
        
        sus = powmod(key, 1<<v19, 0x10001)
        num = 1
        mid = length >> 1
        even = [0] * mid 
        odd = [0] * mid
        inv2 = invert(num, 0x10001)
        for i in range(length >> 1):
            ok1 = out[i]
            ok2 = out[ mid + i]
            even[i] = (ok1 + ok2) * inv2 % 0x10001
            o = (even[i] - ok2) % 0x10001
            
            odd[i] = (o * invert(num, 0x10001)) % 0x10001
            num = (sus * num) % 0x10001
        
        odd = dec(key, odd)
        even = dec(key, even)

        inp = []
        for i in range(length >> 1):
            inp.append(even[i])
            inp.append(odd[i])
        return inp
    return out

flag_enc = open("flag.enc", "rb").read() + b'\x00'*10
flag_enc = [int.from_bytes(flag_enc[i:i+2], 'big')
       for i in range(0, len(flag_enc), 2)]
encrypted_b = [len(flag_enc)*i % 0x10001 for i in flag_enc]
def solve(encrypted_b, key_b):
    closure1 = dec(key_b, encrypted_b)
    for key_a in range(0x10001):
        ikey_a = invert(key_a, 0x10001)
        encrypted_a = [(ele-key_b)*ikey_a % 0x10001 for ele in closure1]
        inp = dec(key_a, encrypted_a)
        if inp[0] == 0x636f and inp[1] == 0x7263:
            print(b''.join([i.to_bytes(2, 'big') for i in inp]))
            sys.exit(0)
n_thread = 11
pool = ThreadPool(n_thread)
with log.progress("Curent key_b") as pbar:
    i = 0
    while i < 0x10001:
        pool.add_task(solve, encrypted_b, i)
        i += 1
        pbar.status(str(i))
pool.wait_completion()