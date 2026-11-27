"""
TCP/IP Protocol Suite - Advanced Multi-threaded Python Web Server
Features: static files + images, JSON API, subnet calculator, DNS lookup,
port lookup, request-header inspector, ping endpoint, server-checked quiz,
live request log.
Run:  python webserver.py   ->  http://127.0.0.1:8000
"""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from collections import deque
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import ipaddress
import json
import mimetypes
import os
import re
import socket
import threading
import time

# ---------- EDIT THESE ----------
REG_NO = "26000792"
NAME = "MELVIN ANDREW F"
# --------------------------------

HOST, PORT = "127.0.0.1", 8000
BASE = os.path.dirname(os.path.abspath(__file__))
START = time.time()
LOCK = threading.Lock()
STATS = {"requests": 0}
LOG = deque(maxlen=25)          # last 25 requests
QUIET = ("/api/stats", "/api/log", "/api/ping", "/favicon.ico")  # not logged

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/script.js": ("script.js", "application/javascript; charset=utf-8"),
}

# name, full form, port, transport, description
_RAW = {
    "Application": [
        ("HTTP", "HyperText Transfer Protocol", "80", "TCP", "Request/response protocol of the web. Browsers send GET/POST requests and servers reply with status codes like 200 or 404."),
        ("HTTPS", "HTTP Secure", "443", "TCP", "HTTP carried inside TLS, giving encryption, integrity and server authentication."),
        ("FTP", "File Transfer Protocol", "20/21", "TCP", "Transfers files using a control connection (21) and a separate data connection (20)."),
        ("TFTP", "Trivial File Transfer Protocol", "69", "UDP", "Very small file transfer protocol with no authentication, used for network booting and config files."),
        ("SMTP", "Simple Mail Transfer Protocol", "25/587", "TCP", "Sends and relays email between mail servers and from clients to servers."),
        ("POP3", "Post Office Protocol v3", "110", "TCP", "Downloads email from a server to a client, usually removing it from the server."),
        ("IMAP", "Internet Message Access Protocol", "143", "TCP", "Lets clients read and manage email while it stays on the server."),
        ("DNS", "Domain Name System", "53", "UDP/TCP", "Translates names such as example.com into IP addresses."),
        ("DHCP", "Dynamic Host Configuration Protocol", "67/68", "UDP", "Automatically gives hosts an IP address, mask, gateway and DNS server."),
        ("Telnet", "Telecommunication Network", "23", "TCP", "Remote terminal access in plain text. Insecure, replaced by SSH."),
        ("SSH", "Secure Shell", "22", "TCP", "Encrypted remote login, command execution and file transfer."),
        ("SNMP", "Simple Network Management Protocol", "161/162", "UDP", "Monitors and manages routers, switches and servers."),
        ("NTP", "Network Time Protocol", "123", "UDP", "Synchronises clocks across machines on a network."),
    ],
    "Transport": [
        ("TCP", "Transmission Control Protocol", "-", "-", "Connection-oriented and reliable. Uses a 3-way handshake, sequence numbers, acknowledgements, flow control and congestion control."),
        ("UDP", "User Datagram Protocol", "-", "-", "Connectionless and fast with no delivery guarantee. Used for DNS, streaming and games."),
        ("SCTP", "Stream Control Transmission Protocol", "-", "-", "Reliable, message-oriented protocol supporting multiple streams and multi-homing."),
    ],
    "Internet": [
        ("IPv4", "Internet Protocol version 4", "-", "-", "32-bit addressing (about 4.3 billion addresses). Routes packets hop by hop using best-effort delivery."),
        ("IPv6", "Internet Protocol version 6", "-", "-", "128-bit addressing with simpler headers, built-in IPsec support and no need for NAT."),
        ("ICMP", "Internet Control Message Protocol", "-", "-", "Carries error and diagnostic messages. Powers ping and traceroute."),
        ("IGMP", "Internet Group Management Protocol", "-", "-", "Manages IPv4 multicast group membership."),
        ("IPsec", "Internet Protocol Security", "-", "-", "Suite that authenticates and encrypts IP packets, used in VPNs."),
        ("ARP", "Address Resolution Protocol", "-", "-", "Maps an IPv4 address to a MAC address on the local network."),
        ("OSPF", "Open Shortest Path First", "-", "-", "Link-state routing protocol that uses Dijkstra's algorithm inside an organisation."),
        ("BGP", "Border Gateway Protocol", "179", "TCP", "Exchanges routes between autonomous systems. It holds the internet together."),
    ],
    "Network Access": [
        ("Ethernet", "IEEE 802.3", "-", "-", "Wired LAN standard. Frames carry source and destination MAC addresses and a CRC check."),
        ("Wi-Fi", "IEEE 802.11", "-", "-", "Wireless LAN standard using CSMA/CA to share the medium."),
        ("PPP", "Point-to-Point Protocol", "-", "-", "Direct link between two nodes, used by dial-up and some broadband links."),
        ("Frame Relay", "Frame Relay", "-", "-", "Older packet-switched WAN technology that uses virtual circuits."),
    ],
}

PROTOCOLS = [
    {"layer": layer, "name": n, "full": f, "port": p, "transport": t, "desc": d}
    for layer, items in _RAW.items() for (n, f, p, t, d) in items
]



QUIZ = [
    ("Which protocol sets up a connection with a three-way handshake?", ["UDP", "TCP", "ICMP", "ARP"], 1,
     "TCP is connection-oriented: SYN, SYN-ACK, ACK."),
    ("Which layer of TCP/IP does IP belong to?", ["Application", "Transport", "Internet", "Network Access"], 2,
     "IP (and ICMP, ARP) work at the Internet layer and handle addressing and routing."),
    ("What is the default port of HTTPS?", ["80", "21", "443", "25"], 2,
     "HTTPS uses TCP port 443. HTTP uses 80."),
    ("Which protocol translates domain names to IP addresses?", ["DHCP", "SNMP", "DNS", "NTP"], 2,
     "DNS maps names such as example.com to IP addresses (port 53)."),
    ("What does ARP map?", ["Name to IP", "IP to MAC", "MAC to port", "IP to name"], 1,
     "ARP finds the MAC address that belongs to an IPv4 address on the local network."),
    ("How many bits are in an IPv6 address?", ["32", "64", "128", "256"], 2,
     "IPv6 addresses are 128 bits long, IPv4 addresses are 32 bits."),
    ("What is the data unit at the Transport layer called (for TCP)?", ["Frame", "Packet", "Segment", "Bit"], 2,
     "TCP data units are segments; UDP's are datagrams."),
    ("Which tool uses ICMP echo messages?", ["ping", "ssh", "wget", "nslookup"], 0,
     "ping sends ICMP Echo Request and waits for Echo Reply."),
]


def subnet_info(ip, prefix):
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    addr = ipaddress.ip_address(ip)
    total = net.num_addresses
    if net.version == 4 and net.prefixlen <= 30:
        first, last, usable = net[1], net[-2], total - 2
    else:
        first, last, usable = net[0], net[-1], total
    info = {
        "IP version": net.version,
        "Network address": str(net.network_address),
        "Subnet mask": str(net.netmask),
        "Wildcard mask": str(net.hostmask),
        "First usable host": str(first),
        "Last usable host": str(last),
        "Usable hosts": usable,
        "Total addresses": total,
        "Private address": addr.is_private,
    }
    if net.version == 4:
        info["Broadcast address"] = str(net.broadcast_address)
        info["Mask (binary)"] = ".".join(f"{int(o):08b}" for o in str(net.netmask).split("."))
        first_octet = int(str(addr).split(".")[0])
        info["Class"] = ("A" if first_octet < 128 else "B" if first_octet < 192 else
                         "C" if first_octet < 224 else "D (multicast)" if first_octet < 240 else "E")
    return info


class Handler(BaseHTTPRequestHandler):
    server_version = "TCPIPServer/2.0"

    # ----- helpers -----
    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def log_request(self, code="-", size="-"):
        path = urlparse(self.path).path
        if path in QUIET:
            return
        stamp = datetime.now().strftime("%H:%M:%S")
        with LOCK:
            STATS["requests"] += 1
            LOG.append({"time": stamp, "client": self.client_address[0], "method": self.command,
                        "path": self.path, "status": str(code)})
        print(f"[{stamp}] {self.client_address[0]} {self.command} {self.path} -> {code}")

    # ----- routing -----
    def do_GET(self):
        url = urlparse(self.path)
        path = url.path
        qs = {k: v[0].strip() for k, v in parse_qs(url.query).items()}

        if path == "/api/protocols":
            return self._json(PROTOCOLS)
        if path == "/api/info":
            return self._json({"reg_no": REG_NO, "name": NAME})
        if path == "/api/stats":
            return self._json({"requests": STATS["requests"], "uptime_seconds": int(time.time() - START)})
        if path == "/api/log":
            with LOCK:
                return self._json(list(LOG)[::-1])
        if path == "/api/ping":
            return self._json({"server_time_ns": time.time_ns()})
        if path == "/api/headers":
            return self._json({
                "Client address": f"{self.client_address[0]}:{self.client_address[1]}",
                "Method": self.command,
                "Path": self.path,
                "HTTP version": self.request_version,
                "Headers": dict(self.headers.items()),
            })

        if path == "/api/subnet":
            try:
                return self._json(subnet_info(qs.get("ip", ""), int(qs.get("prefix", "24"))))
            except ValueError as e:
                return self._json({"error": f"Invalid input: {e}"}, 400)

        if path == "/api/dns":
            host = qs.get("host", "")
            if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
                return self._json({"error": "Enter a valid host name"}, 400)
            try:
                canonical, aliases, addrs = socket.gethostbyname_ex(host)
                return self._json({"Host": host, "Canonical name": canonical,
                                   "Aliases": aliases or ["none"], "IPv4 addresses": addrs})
            except OSError as e:
                return self._json({"error": f"Could not resolve '{host}': {e}"}, 502)

        if path == "/api/port":
            try:
                n = int(qs.get("n", ""))
                if not 0 <= n <= 65535:
                    raise ValueError
            except ValueError:
                return self._json({"error": "Port must be a number from 0 to 65535"}, 400)
            matches = [p["name"] for p in PROTOCOLS if str(n) in p["port"].split("/")]
            rng = ("Well-known (0-1023)" if n < 1024 else
                   "Registered (1024-49151)" if n < 49152 else "Dynamic / private (49152-65535)")
            return self._json({"Port": n, "Range": rng,
                               "Used by": matches or ["no protocol in this list"]})

        if path == "/api/quiz":
            return self._json([{"id": i, "q": q, "options": o} for i, (q, o, _, _) in enumerate(QUIZ)])
        if path == "/api/quiz/check":
            try:
                i, choice = int(qs.get("id", "")), int(qs.get("choice", ""))
                q, _, answer, why = QUIZ[i]
            except (ValueError, IndexError):
                return self._json({"error": "Bad quiz request"}, 400)
            return self._json({"correct": choice == answer, "answer": answer, "explain": why})

        if path in STATIC:
            filename, ctype = STATIC[path]
            full = os.path.join(BASE, filename)
            if os.path.isfile(full):
                with open(full, "rb") as f:
                    return self._send(200, f.read(), ctype)

        if path.startswith("/images/"):
            full = os.path.join(BASE, "images", os.path.basename(path))   # basename blocks ../ tricks
            if os.path.isfile(full):
                ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
                with open(full, "rb") as f:
                    return self._send(200, f.read(), ctype)

        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        self._send(404, b"<h1>404 - Page not found</h1><a href='/'>Back to home</a>",
                   "text/html; charset=utf-8")


if __name__ == "__main__":
    os.makedirs(os.path.join(BASE, "images"), exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print("=" * 58)
    print("Web Server Started!")
    print("Open http://localhost:8000")
    print(" TCP/IP Protocol Suite - Advanced Web Server")
    print(f" Register No : {REG_NO}")
    print(f" Name        : {NAME}")
    print(f" Running at  : http://{HOST}:{PORT}")
    print(" Press Ctrl+C to stop")
    print("=" * 58)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()
