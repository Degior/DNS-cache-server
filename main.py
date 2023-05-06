import socket
import pickle
import time

from dnslib import DNSRecord, QTYPE


class DNSServer:
    def __init__(self, address, port, cache_file):
        self.address = address
        self.port = port
        self.cache_file = cache_file
        self.cache = {}
        self.load_cache()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            server_socket.bind((self.address, self.port))
            print(f"DNS server listening on {self.address}:{self.port}")
            next_cleanup_time = time.time() + 60
            while True:
                data, client_address = server_socket.recvfrom(512)
                query = DNSRecord.parse(data)
                response = self.resolve(query)
                server_socket.sendto(response.pack(), client_address)
                if time.time() >= next_cleanup_time:
                    self.cleanup_cache()
                    next_cleanup_time = time.time() + 60

    def resolve(self, query):
        qname = str(query.q.qname)
        qtype = query.q.qtype
        if qname in self.cache and qtype in self.cache[qname]:
            print(f"Cache hit for {qname} ({QTYPE[qtype]})")
            return self.build_response(query, self.cache[qname][qtype])
        else:
            print(f"Cache miss for {qname} ({QTYPE[qtype]})")
            response = self.forward(query)
            self.update_cache(response)
            return response

    def forward(self, query):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
            resolver_socket.settimeout(5)
            resolver_socket.sendto(query.pack(), ("77.88.8.1", 53))
            data, _ = resolver_socket.recvfrom(512)
            return DNSRecord.parse(data)

    def update_cache(self, response):
        for rr in response.rr:
            qname = str(rr.rname)
            qtype = rr.rtype
            if qname not in self.cache:
                self.cache[qname] = {}
            self.cache[qname][qtype] = rr
        self.save_cache()

    def build_response(self, query, rr):
        response = DNSRecord()
        response.add_question(query.q)
        response.add_answer(rr)
        response.header.id = query.header.id
        response.header.qr = 1
        response.header.ra = 1
        return response

    def load_cache(self):
        try:
            with open(self.cache_file, "rb") as cache_file:
                self.cache = pickle.load(cache_file)
                print(f"Cache loaded from {self.cache_file}")
        except FileNotFoundError:
            print(f"No cache file found at {self.cache_file}")

    def save_cache(self):
        with open(self.cache_file, "wb") as cache_file:
            pickle.dump(self.cache, cache_file)
            print(f"Cache saved to {self.cache_file}")

    def cleanup_cache(self):
        now = time.time()
        for qname in list(self.cache.keys()):
            for qtype in list(self.cache[qname].keys()):
                rr = self.cache[qname][qtype]
                if rr.ttl and rr.ttl < now:
                    del self.cache[qname][qtype]
                    print(f"Removed expired cache entry for {qname} ({QTYPE[qtype]})")
            if not self.cache[qname]:
                del self.cache[qname]
                print(f"Removed empty cache entry for {qname}")


if __name__ == "__main__":
    server = DNSServer("127.0.0.1", 53, "dns_cache.pickle")
    try:
        server.run()
    except KeyboardInterrupt:
        server.save_cache()
