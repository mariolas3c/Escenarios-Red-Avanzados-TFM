#!/usr/bin/env python3
"""
NetFlow Collector - Receives NetFlow v5/v9 via UDP and indexes to OpenSearch.

Usage (inside Mininet collector host):
  collector> python3 /tmp/netflow_collector.py --es http://10.0.3.254:9200

Usage (on host machine):
  python3 netflow_collector.py --es http://localhost:9200
"""

import socket
import struct
import datetime
import json
import time
import sys
import argparse
import threading
from collections import deque

sys.stdout.reconfigure(encoding='utf-8')

try:
    from opensearchpy import OpenSearch, helpers
    HAS_ES = True
except ImportError:
    HAS_ES = False

PROTOCOLS = {
    1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE',
    50: 'ESP', 51: 'AH', 89: 'OSPF', 132: 'SCTP',
}

TCP_FLAGS = {0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
             0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR'}

SERVICES = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 123: 'NTP', 143: 'IMAP',
    161: 'SNMP', 443: 'HTTPS', 514: 'SYSLOG', 993: 'IMAPS', 995: 'POP3S',
    3306: 'MYSQL', 5432: 'PGSQL', 6379: 'REDIS', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
}


def ip_from_uint(n):
    return socket.inet_ntoa(struct.pack('!I', n))


def flags_str(byte):
    return ','.join(name for bit, name in TCP_FLAGS.items() if byte & bit) or 'NONE'


# ─── NetFlow v5 parser ────────────────────────────────────────────────────────

NF5_HDR = struct.Struct('!HHIIIIBBh')   # 24 bytes (last field is signed short)
NF5_REC = struct.Struct('!IIIHHIIIIHHcBBBHHBBH')  # 48 bytes


def parse_v5(data, exporter_ip):
    if len(data) < NF5_HDR.size:
        return []

    hdr = NF5_HDR.unpack(data[:NF5_HDR.size])
    version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, eng_type, eng_id, sampling = hdr
    export_ts = datetime.datetime.utcfromtimestamp(unix_secs).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    flows = []
    offset = NF5_HDR.size
    for _ in range(count):
        if offset + NF5_REC.size > len(data):
            break
        r = NF5_REC.unpack(data[offset:offset + NF5_REC.size])
        offset += NF5_REC.size

        (srcaddr, dstaddr, nexthop, in_iface, out_iface,
         dpkts, doctets, t_first, t_last,
         srcport, dstport, pad1, tcp_flags_b, prot, tos,
         src_as, dst_as, src_mask, dst_mask, pad2) = r

        # tcp_flags_b comes as bytes object due to 'c' format
        if isinstance(tcp_flags_b, (bytes, bytearray)):
            tcp_flags_int = tcp_flags_b[0]
        else:
            tcp_flags_int = int(tcp_flags_b)

        duration_ms = max(0, t_last - t_first)
        proto_num = prot if isinstance(prot, int) else prot[0]
        src_ip = ip_from_uint(srcaddr)
        dst_ip = ip_from_uint(dstaddr)

        flows.append({
            '@timestamp': export_ts,
            'netflow': {
                'version': 5,
                'exporter_ip': exporter_ip,
                'flow_sequence': flow_seq,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'next_hop': ip_from_uint(nexthop),
                'src_port': srcport,
                'dst_port': dstport,
                'src_service': SERVICES.get(srcport, ''),
                'dst_service': SERVICES.get(dstport, ''),
                'protocol': PROTOCOLS.get(proto_num, str(proto_num)),
                'protocol_number': proto_num,
                'tcp_flags': flags_str(tcp_flags_int),
                'tcp_flags_raw': tcp_flags_int,
                'tos': tos,
                'packets': dpkts,
                'bytes': doctets,
                'duration_ms': duration_ms,
                'bytes_per_packet': round(doctets / dpkts, 2) if dpkts else 0,
                'input_iface': in_iface,
                'output_iface': out_iface,
                'src_as': src_as,
                'dst_as': dst_as,
                'src_mask': src_mask,
                'dst_mask': dst_mask,
                'engine_type': eng_type,
                'engine_id': eng_id,
            }
        })
    return flows


# ─── NetFlow v9 parser ────────────────────────────────────────────────────────

NF9_FIELD_NAMES = {
    1: 'bytes', 2: 'packets', 4: 'protocol_number', 5: 'tos',
    6: 'tcp_flags_raw', 7: 'src_port', 8: 'src_ip', 10: 'input_iface',
    11: 'dst_port', 12: 'dst_ip', 14: 'output_iface', 15: 'next_hop',
    16: 'src_as', 17: 'dst_as', 18: 'bgp_nexthop', 21: 'flow_end_ms',
    22: 'flow_start_ms', 23: 'out_bytes', 24: 'out_packets',
    27: 'src_ipv6', 28: 'dst_ipv6', 32: 'icmp_type', 56: 'src_mac',
    57: 'dst_mac', 58: 'vlan_id',
}

_v9_templates = {}  # (source_id, template_id) -> list of (field_type, field_len)


def _parse_v9_template_flowset(data, source_id):
    offset = 0
    while offset + 4 <= len(data):
        tmpl_id, count = struct.unpack('!HH', data[offset:offset + 4])
        offset += 4
        fields = []
        for _ in range(count):
            if offset + 4 > len(data):
                break
            ftype, flen = struct.unpack('!HH', data[offset:offset + 4])
            fields.append((ftype, flen))
            offset += 4
        _v9_templates[(source_id, tmpl_id)] = fields


def _decode_v9_field(ftype, raw):
    n = len(raw)
    value = int.from_bytes(raw, 'big')
    if ftype in (8, 12, 15, 18):   # IPv4 addresses
        if n == 4:
            return socket.inet_ntoa(raw)
    if ftype in (27, 28):           # IPv6
        return socket.inet_ntop(socket.AF_INET6, raw)
    return value


def _parse_v9_data_flowset(data, source_id, tmpl_id, export_ts, exporter_ip):
    key = (source_id, tmpl_id)
    if key not in _v9_templates:
        return []
    fields = _v9_templates[key]
    rec_len = sum(fl for _, fl in fields)
    if rec_len == 0:
        return []
    flows = []
    offset = 0
    while offset + rec_len <= len(data):
        raw_fields = {}
        for ftype, flen in fields:
            raw_fields[ftype] = data[offset:offset + flen]
            offset += flen

        decoded = {NF9_FIELD_NAMES.get(ft, f'field_{ft}'): _decode_v9_field(ft, raw)
                   for ft, raw in raw_fields.items()}

        proto_num = decoded.get('protocol_number', 0)
        tcp_flags_int = decoded.get('tcp_flags_raw', 0)
        srcport = decoded.get('src_port', 0)
        dstport = decoded.get('dst_port', 0)

        nf = {
            'version': 9,
            'exporter_ip': exporter_ip,
            'src_ip': decoded.get('src_ip', '0.0.0.0'),
            'dst_ip': decoded.get('dst_ip', '0.0.0.0'),
            'src_port': srcport,
            'dst_port': dstport,
            'src_service': SERVICES.get(srcport, ''),
            'dst_service': SERVICES.get(dstport, ''),
            'protocol': PROTOCOLS.get(proto_num, str(proto_num)),
            'protocol_number': proto_num,
            'tcp_flags': flags_str(tcp_flags_int),
            'tcp_flags_raw': tcp_flags_int,
            'packets': decoded.get('packets', 0),
            'bytes': decoded.get('bytes', 0),
            'input_iface': decoded.get('input_iface', 0),
            'output_iface': decoded.get('output_iface', 0),
            'src_as': decoded.get('src_as', 0),
            'dst_as': decoded.get('dst_as', 0),
            'tos': decoded.get('tos', 0),
        }
        pkts = nf['packets']
        nf['bytes_per_packet'] = round(nf['bytes'] / pkts, 2) if pkts else 0
        flows.append({'@timestamp': export_ts, 'netflow': nf})
    return flows


def parse_v9(data, exporter_ip):
    HDR = struct.Struct('!HHIIII')
    if len(data) < HDR.size:
        return []
    version, count, sys_uptime, unix_secs, sequence, source_id = HDR.unpack(data[:HDR.size])
    export_ts = datetime.datetime.utcfromtimestamp(unix_secs).strftime('%Y-%m-%dT%H:%M:%S.000Z')

    flows = []
    offset = HDR.size
    while offset + 4 <= len(data):
        fs_id, fs_len = struct.unpack('!HH', data[offset:offset + 4])
        if fs_len < 4 or offset + fs_len > len(data):
            break
        fs_data = data[offset + 4:offset + fs_len]
        if fs_id == 0:
            _parse_v9_template_flowset(fs_data, source_id)
        elif fs_id >= 256:
            flows.extend(_parse_v9_data_flowset(fs_data, source_id, fs_id, export_ts, exporter_ip))
        offset += fs_len
    return flows


# ─── OpenSearch helpers ──────────────────────────────────────────────────────

ES_MAPPING = {
    'mappings': {
        'properties': {
            '@timestamp': {'type': 'date'},
            'netflow': {
                'properties': {
                    'src_ip':          {'type': 'ip'},
                    'dst_ip':          {'type': 'ip'},
                    'exporter_ip':     {'type': 'ip'},
                    'next_hop':        {'type': 'ip'},
                    'src_port':        {'type': 'integer'},
                    'dst_port':        {'type': 'integer'},
                    'src_service':     {'type': 'keyword'},
                    'dst_service':     {'type': 'keyword'},
                    'protocol':        {'type': 'keyword'},
                    'protocol_number': {'type': 'integer'},
                    'tcp_flags':       {'type': 'keyword'},
                    'tcp_flags_raw':   {'type': 'integer'},
                    'packets':         {'type': 'long'},
                    'bytes':           {'type': 'long'},
                    'bytes_per_packet':{'type': 'float'},
                    'duration_ms':     {'type': 'long'},
                    'tos':             {'type': 'integer'},
                    'version':         {'type': 'integer'},
                    'input_iface':     {'type': 'integer'},
                    'output_iface':    {'type': 'integer'},
                    'src_as':          {'type': 'integer'},
                    'dst_as':          {'type': 'integer'},
                    'engine_type':     {'type': 'integer'},
                    'engine_id':       {'type': 'integer'},
                }
            }
        }
    }
}


def connect_es(url):
    if not HAS_ES:
        print('[WARN] opensearch-py not installed. Run: pip3 install opensearch-py')
        return None
    try:
        es = OpenSearch([url], request_timeout=5)
        if es.ping():
            print(f'[OK]  Connected to OpenSearch: {url}')
            return es
        print(f'[WARN] OpenSearch ping failed at {url}')
    except Exception as e:
        print(f'[WARN] OpenSearch connection error: {e}')
    return None


def ensure_index(es, index):
    try:
        if not es.indices.exists(index=index):
            es.indices.create(index=index, body=ES_MAPPING)
            print(f'[OK]  Created index: {index}')
        else:
            print(f'[OK]  Index exists: {index}')
    except Exception as e:
        print(f'[WARN] Index setup: {e}')


# ─── Collector ───────────────────────────────────────────────────────────────

class Collector:

    def __init__(self, args):
        self.bind_ip  = args.bind
        self.port     = args.port
        self.index    = args.index
        self.verbose  = args.verbose
        self.es       = None
        self._buf     = []
        self._lock    = threading.Lock()
        self.stats    = {'pkts': 0, 'flows': 0, 'indexed': 0, 'errors': 0}
        self.recent   = deque(maxlen=100)

        if not args.no_es:
            self.es = connect_es(args.es)
            if self.es:
                ensure_index(self.es, self.index)

    def _parse(self, data, addr):
        if len(data) < 2:
            return []
        ver = struct.unpack('!H', data[:2])[0]
        if ver == 5:
            return parse_v5(data, addr[0])
        if ver == 9:
            return parse_v9(data, addr[0])
        if self.verbose:
            print(f'[WARN] Unknown NetFlow version {ver} from {addr[0]}')
        return []

    def _flush(self):
        while True:
            time.sleep(2)
            with self._lock:
                batch, self._buf = self._buf[:], []
            if batch and self.es:
                try:
                    actions = [{'_index': self.index, '_source': f} for f in batch]
                    helpers.bulk(self.es, actions, raise_on_error=False)
                    self.stats['indexed'] += len(batch)
                except Exception as e:
                    self.stats['errors'] += 1
                    if self.verbose:
                        print(f'[ERROR] ES bulk: {e}')

    def _print_flow(self, f):
        n = f['netflow']
        proto  = n.get('protocol', '?')
        src    = f"{n.get('src_ip','?')}:{n.get('src_port','?')}"
        dst    = f"{n.get('dst_ip','?')}:{n.get('dst_port','?')}"
        svc    = n.get('dst_service', '')
        pkts   = n.get('packets', 0)
        byt    = n.get('bytes', 0)
        flags  = n.get('tcp_flags', '') if proto == 'TCP' else ''
        ts     = f['@timestamp'][11:19]
        svc_s  = f'({svc})' if svc else ''
        print(f'  {ts}  {proto:<5s}  {src:<22s} → {dst:<22s}{svc_s:<12s}  {pkts:>6}pkt  {byt:>9}B  {flags}')

    def _stats_loop(self):
        while True:
            time.sleep(15)
            s = self.stats
            es_s = f'  indexed={s["indexed"]}' if self.es else ''
            print(f'\n[STATS] udp_packets={s["pkts"]}  flows_parsed={s["flows"]}  errors={s["errors"]}{es_s}\n')

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind_ip, self.port))

        print(f'[OK]  Listening for NetFlow on {self.bind_ip}:{self.port}')
        es_status = (f'OpenSearch → {self.es}  index={self.index}') if self.es else 'OpenSearch disabled (--no-es)'
        print(f'      {es_status}')
        print()
        print(f'  {"TIME":<8s}  {"PROTO":<5s}  {"SOURCE":<22s}   {"DESTINATION":<22s}{"SERVICE":<12s}  {"PKTS":>6s}  {"BYTES":>9s}  FLAGS')
        print('  ' + '─' * 100)

        threading.Thread(target=self._flush,      daemon=True).start()
        threading.Thread(target=self._stats_loop, daemon=True).start()

        try:
            while True:
                data, addr = sock.recvfrom(65535)
                self.stats['pkts'] += 1
                flows = self._parse(data, addr)
                self.stats['flows'] += len(flows)
                for f in flows:
                    self.recent.append(f)
                    self._print_flow(f)
                    if self.es:
                        with self._lock:
                            self._buf.append(f)
        except KeyboardInterrupt:
            print(f'\n[*] Collector stopped — {self.stats["flows"]} flows processed, {self.stats["indexed"]} indexed.')


def main():
    p = argparse.ArgumentParser(description='NetFlow v5/v9 Collector → OpenSearch')
    p.add_argument('--bind',   default='0.0.0.0',              help='Bind IP (default: 0.0.0.0)')
    p.add_argument('--port',   type=int, default=2055,          help='UDP listen port (default: 2055)')
    p.add_argument('--es',     default='http://localhost:9200', help='OpenSearch URL')
    p.add_argument('--index',  default='netflow-flows',         help='Index name')
    p.add_argument('--no-es',  action='store_true',             help='Disable OpenSearch output')
    p.add_argument('--verbose',action='store_true',             help='Show debug messages')
    args = p.parse_args()

    Collector(args).run()


if __name__ == '__main__':
    main()
