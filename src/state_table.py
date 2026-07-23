import time

class ConnectionTable:
    def __init__(self, timeout=120):
        self.table = {}
        self.timeout = timeout

    def key(self, src, sport, dst, dport, proto):
        return (src, sport, dst, dport, proto)

    def add(self, src, sport, dst, dport, proto):
        self.table[self.key(src, sport, dst, dport, proto)] = time.time()

    def is_established(self, src, sport, dst, dport, proto):
        k = self.key(dst, dport, src, sport, proto)
        if k in self.table:
            if time.time() - self.table[k] < self.timeout:
                return True
            else:
                del self.table[k]
        return False