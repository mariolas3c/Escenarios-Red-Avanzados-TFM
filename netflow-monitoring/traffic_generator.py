#!/usr/bin/env python3
"""
Traffic Generator for NetFlow Monitoring Scenario.
Run inside a Mininet host to generate diverse traffic patterns.

Examples:
  h1> python3 /tmp/traffic_generator.py --mode continuous
  h1> python3 /tmp/traffic_generator.py --mode burst
  h1> python3 /tmp/traffic_generator.py --mode http --target 10.0.3.30 --count 50
  h1> python3 /tmp/traffic_generator.py --mode scan
"""

import socket
import time
import random
import threading
import argparse
import subprocess
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

# ─── Topology ────────────────────────────────────────────────────────────────

HOSTS = {
    'h1': '10.0.3.10',
    'h2': '10.0.3.20',
    'h3': '10.0.3.30',
    'h4': '10.0.3.40',
    'h5': '10.0.3.50',
}

WEB_SERVER = '10.0.3.30'   # http.server on :80
SSH_SERVER = '10.0.3.40'   # nc listeners on :22, :21
DB_SERVER  = '10.0.3.50'   # nc listeners on :3306, :5432

# (ip, port, proto, label)
PATTERNS = [
    (WEB_SERVER, 80,    'tcp',  'HTTP web'),
    (WEB_SERVER, 443,   'tcp',  'HTTPS web'),
    (WEB_SERVER, 8080,  'tcp',  'HTTP alt'),
    (SSH_SERVER, 22,    'tcp',  'SSH'),
    (SSH_SERVER, 21,    'tcp',  'FTP control'),
    (SSH_SERVER, 20,    'tcp',  'FTP data'),
    (DB_SERVER,  3306,  'tcp',  'MySQL'),
    (DB_SERVER,  5432,  'tcp',  'PostgreSQL'),
    (DB_SERVER,  6379,  'tcp',  'Redis'),
    (HOSTS['h1'], 0,    'icmp', 'ICMP → h1'),
    (HOSTS['h2'], 0,    'icmp', 'ICMP → h2'),
    (HOSTS['h3'], 0,    'icmp', 'ICMP → h3'),
    (HOSTS['h4'], 0,    'icmp', 'ICMP → h4'),
    (HOSTS['h5'], 0,    'icmp', 'ICMP → h5'),
    (SSH_SERVER, 53,    'udp',  'DNS'),
    (DB_SERVER,  123,   'udp',  'NTP'),
    (HOSTS['h1'], 161,  'udp',  'SNMP'),
    (HOSTS['h2'], 514,  'udp',  'Syslog'),
    (HOSTS['h3'], 5353, 'udp',  'mDNS'),
]


# ─── Low-level senders ───────────────────────────────────────────────────────

def send_tcp(ip, port, payload_size=128, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if port == 80 or port == 8080:
            payload = (f'GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetFlowGen/1.0\r\n\r\n').encode()
        else:
            payload = (b'HELLO\r\n' + os.urandom(max(0, payload_size - 7)))[:payload_size]
        s.sendall(payload)
        try:
            s.recv(4096)
        except Exception:
            pass
        s.close()
        return True
    except Exception:
        return False


def send_udp(ip, port, payload_size=64):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        if port == 53:
            # Minimal DNS query for "example.com"
            payload = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                       b'\x07example\x03com\x00\x00\x01\x00\x01')
        elif port == 123:
            # Minimal NTP client request
            payload = b'\x1b' + b'\x00' * 47
        else:
            payload = os.urandom(payload_size)
        s.sendto(payload, (ip, port))
        s.close()
        return True
    except Exception:
        return False


def send_icmp(ip, count=1, quiet=True):
    try:
        cmd = ['ping', '-c', str(count), '-W', '1', '-q', ip]
        r = subprocess.run(cmd, capture_output=True, timeout=count + 2)
        return r.returncode == 0
    except Exception:
        return False


# ─── Traffic modes ───────────────────────────────────────────────────────────

def mode_continuous(interval_range=(0.2, 1.5)):
    print('[CONTINUOUS] Generating traffic — Ctrl+C to stop\n')
    counter = 0
    try:
        while True:
            ip, port, proto, label = random.choice(PATTERNS)
            size = random.randint(64, 1024)

            if proto == 'tcp':
                ok = send_tcp(ip, port, size)
            elif proto == 'udp':
                ok = send_udp(ip, port, size)
            else:
                ok = send_icmp(ip, count=random.randint(1, 3))

            status = 'OK' if ok else '--'
            print(f'  [{counter:05d}] {proto.upper():<4s} → {ip}:{port:<5d}  {label:<18s} [{status}]')
            counter += 1
            time.sleep(random.uniform(*interval_range))
    except KeyboardInterrupt:
        print(f'\n[*] Sent {counter} flows.')


def mode_burst():
    print('[BURST] Sending simultaneous flows across all patterns...\n')
    results = {}
    threads = []

    def worker(ip, port, proto, label):
        if proto == 'tcp':
            ok = send_tcp(ip, port, 256)
        elif proto == 'udp':
            ok = send_udp(ip, port, 128)
        else:
            ok = send_icmp(ip, 2)
        results[label] = ok
        print(f'  {proto.upper():<4s} → {ip}:{port:<5d}  {label:<20s} [{"OK" if ok else "--"}]')

    for ip, port, proto, label in PATTERNS:
        t = threading.Thread(target=worker, args=(ip, port, proto, label))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)

    ok_count = sum(1 for v in results.values() if v)
    print(f'\n[BURST] Done — {ok_count}/{len(PATTERNS)} successful.')


def mode_http(target, count, delay=0.3):
    print(f'[HTTP] Sending {count} HTTP GET requests → {target}:80\n')
    ok = 0
    sizes = [64, 128, 256, 512, 1024, 2048]
    for i in range(count):
        size = random.choice(sizes)
        result = send_tcp(target, 80, size)
        ok += result
        print(f'  [{i+1:04d}] GET {target}:80  {size}B  [{"OK" if result else "--"}]')
        time.sleep(random.uniform(0, delay * 2))
    print(f'\n[HTTP] Done — {ok}/{count} successful.')


def mode_scan(target=WEB_SERVER):
    print(f'[SCAN] Port scan simulation → {target}  (creates recognizable flow pattern)\n')
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
             445, 993, 995, 1433, 3306, 3389, 5432, 6379, 8080, 8443]
    for port in ports:
        ok = send_tcp(target, port, payload_size=0, timeout=0.3)
        print(f'  TCP → {target}:{port:<5d}  [{"OPEN" if ok else "closed"}]')
        time.sleep(0.05)
    print(f'\n[SCAN] Scanned {len(ports)} ports on {target}.')


def mode_flood(target, port, proto='tcp', count=200, delay=0.01):
    print(f'[FLOOD] {proto.upper()} flood → {target}:{port}  ({count} packets, {delay}s interval)\n')
    ok = 0
    for i in range(count):
        if proto == 'tcp':
            result = send_tcp(target, port, 64, timeout=0.2)
        else:
            result = send_udp(target, port, 64)
        ok += result
        if i % 20 == 0:
            print(f'  [{i:04d}/{count}] sent={ok}')
        time.sleep(delay)
    print(f'\n[FLOOD] Done — {ok}/{count} packets sent.')


def mode_mix(duration=60):
    print(f'[MIX] Mixed traffic for {duration}s\n')
    end = time.time() + duration
    count = 0
    while time.time() < end:
        remaining = end - time.time()
        ip, port, proto, label = random.choice(PATTERNS)
        size = random.randint(32, 2048)
        if proto == 'tcp':
            send_tcp(ip, port, size)
        elif proto == 'udp':
            send_udp(ip, port, size)
        else:
            send_icmp(ip, random.randint(1, 5))
        count += 1
        time.sleep(random.uniform(0.05, 0.5))
    print(f'\n[MIX] Done — {count} flows in {duration}s.')


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='NetFlow Traffic Generator')
    p.add_argument('--mode', default='continuous',
                   choices=['continuous', 'burst', 'http', 'scan', 'flood', 'mix'],
                   help='Traffic mode (default: continuous)')
    p.add_argument('--target', default=WEB_SERVER, help='Target IP for http/scan/flood')
    p.add_argument('--port',   type=int, default=80,  help='Target port for flood mode')
    p.add_argument('--proto',  default='tcp', choices=['tcp', 'udp'], help='Protocol for flood')
    p.add_argument('--count',  type=int, default=20,  help='Request count for http/flood mode')
    p.add_argument('--duration', type=int, default=60, help='Duration for mix mode (seconds)')
    args = p.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════╗
║           NetFlow Traffic Generator                     ║
║  Mode    : {args.mode:<46s}║
║  Target  : {args.target:<46s}║
╚══════════════════════════════════════════════════════════╝
""")

    try:
        if args.mode == 'continuous':
            mode_continuous()
        elif args.mode == 'burst':
            mode_burst()
        elif args.mode == 'http':
            mode_http(args.target, args.count)
        elif args.mode == 'scan':
            mode_scan(args.target)
        elif args.mode == 'flood':
            mode_flood(args.target, args.port, args.proto, args.count)
        elif args.mode == 'mix':
            mode_mix(args.duration)
    except KeyboardInterrupt:
        print('\n[*] Stopped.')


if __name__ == '__main__':
    main()
