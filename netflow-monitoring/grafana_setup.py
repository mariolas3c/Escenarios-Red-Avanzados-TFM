#!/usr/bin/env python3
"""
Grafana Setup — Creates OpenSearch datasource and NetFlow dashboard via Grafana API.

Usage:
  python3 grafana_setup.py
  python3 grafana_setup.py --grafana http://localhost:3000 --es http://opensearch:9200
"""

import json
import urllib.request
import urllib.error
import base64
import time
import argparse
import sys


class GrafanaClient:

    def __init__(self, url, user, password):
        self.base = url.rstrip('/')
        creds = base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {creds}',
        }

    def request(self, method, path, body=None):
        url = f'{self.base}{path}'
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self.headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read()), r.status
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read()), e.code
            except Exception:
                return {}, e.code
        except Exception as e:
            return {'error': str(e)}, 0

    def wait_ready(self, timeout=90):
        print(f'[*] Waiting for Grafana at {self.base} ...')
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp, status = self.request('GET', '/api/health')
            if status == 200 and resp.get('database') == 'ok':
                print('[OK] Grafana ready')
                return True
            time.sleep(3)
        print(f'[ERR] Grafana not available after {timeout}s')
        return False


# ─── Datasource ──────────────────────────────────────────────────────────────

def create_datasource(client, es_url, index):
    ds = {
        'name':     'OpenSearch-NetFlow',
        'uid':      'opensearch-netflow',
        'type':     'elasticsearch',
        'access':   'proxy',
        'url':      es_url,
        'database': f'{index}*',
        'jsonData': {
            'timeField':                  '@timestamp',
            'esVersion':                  '7.10.0',
            'maxConcurrentShardRequests': 5,
        },
        'isDefault': True,
    }
    resp, status = client.request('POST', '/api/datasources', ds)
    if status == 200:
        print('[OK] Datasource created: OpenSearch-NetFlow')
    elif status == 409:
        # Already exists — update it
        ds_id = resp.get('datasource', {}).get('id') or resp.get('id')
        if ds_id:
            _, s2 = client.request('PUT', f'/api/datasources/{ds_id}', ds)
            print(f'[OK] Datasource updated (id={ds_id})')
        else:
            print('[OK] Datasource already exists')
    else:
        print(f'[WARN] Datasource: {status} {resp}')


# ─── Dashboard builder ────────────────────────────────────────────────────────

DS_REF = {'type': 'elasticsearch', 'uid': 'opensearch-netflow'}


def _target(metrics, bucket_aggs, query=''):
    return {'datasource': DS_REF, 'metrics': metrics, 'bucketAggs': bucket_aggs, 'query': query}


def _count_over_time(interval='auto'):
    return _target(
        [{'id': '1', 'type': 'count'}],
        [{'id': '2', 'type': 'date_histogram', 'field': '@timestamp',
          'settings': {'interval': interval, 'min_doc_count': '1', 'trimEdges': '0'}}],
    )


def _sum_over_time(field, interval='auto'):
    return _target(
        [{'id': '1', 'type': 'sum', 'field': f'netflow.{field}'}],
        [{'id': '2', 'type': 'date_histogram', 'field': '@timestamp',
          'settings': {'interval': interval, 'min_doc_count': '1', 'trimEdges': '0'}}],
    )


def _top_terms(field, size=10, metric='count', metric_field=None):
    metrics = [{'id': '1', 'type': metric}]
    if metric == 'sum' and metric_field:
        metrics = [{'id': '1', 'type': 'sum', 'field': f'netflow.{metric_field}'}]
    return _target(
        metrics,
        [{'id': '2', 'type': 'terms', 'field': f'netflow.{field}',
          'settings': {'size': str(size), 'order': 'desc', 'orderBy': '1'}}],
    )


def _panel(pid, title, ptype, x, y, w, h, targets, extra=None):
    p = {
        'id': pid, 'title': title, 'type': ptype,
        'gridPos': {'x': x, 'y': y, 'w': w, 'h': h},
        'datasource': DS_REF,
        'targets': targets if isinstance(targets, list) else [targets],
    }
    if extra:
        p.update(extra)
    return p


def build_dashboard():
    def stat_panel(pid, title, target, unit, color, x, y, w=4, h=4):
        return _panel(pid, title, 'stat', x, y, w, h, [target], {
            'options': {
                'reduceOptions': {'calcs': ['sum']},
                'colorMode': 'background',
                'graphMode': 'none',
                'textMode': 'auto',
            },
            'fieldConfig': {
                'defaults': {
                    'unit': unit,
                    'color': {'mode': 'fixed', 'fixedColor': color},
                }
            }
        })

    count_target = _count_over_time()
    bytes_target = _sum_over_time('bytes')
    pkts_target  = _sum_over_time('packets')

    panels = [
        # ── Row 0: KPI stats ─────────────────────────────────────────────────
        stat_panel(1,  'Total Flows',   count_target, 'short',  'blue',   0, 0),
        stat_panel(2,  'Total Bytes',   bytes_target, 'bytes',  'green',  4, 0),
        stat_panel(3,  'Total Packets', pkts_target,  'short',  'purple', 8, 0),
        _panel(4, 'Unique Source IPs', 'stat', 12, 0, 4, 4,
               [_target(
                   [{'id': '1', 'type': 'cardinality', 'field': 'netflow.src_ip'}],
                   [{'id': '2', 'type': 'date_histogram', 'field': '@timestamp',
                     'settings': {'interval': 'auto', 'min_doc_count': '1'}}],
               )],
               {'options': {'reduceOptions': {'calcs': ['max']}, 'colorMode': 'background',
                            'graphMode': 'none'},
                'fieldConfig': {'defaults': {'color': {'mode': 'fixed', 'fixedColor': 'orange'}}}}),

        # ── Row 1: Flow rate ─────────────────────────────────────────────────
        _panel(5, 'Flow Rate (flows/min)', 'timeseries', 0, 4, 12, 8, [_count_over_time('1m')],
               {'fieldConfig': {'defaults': {
                   'color': {'mode': 'palette-classic'},
                   'custom': {'lineWidth': 2, 'fillOpacity': 15, 'spanNulls': True},
               }}}),

        _panel(6, 'Throughput (bytes/min)', 'timeseries', 12, 4, 12, 8, [_sum_over_time('bytes', '1m')],
               {'fieldConfig': {'defaults': {
                   'unit': 'Bps',
                   'color': {'mode': 'palette-classic'},
                   'custom': {'lineWidth': 2, 'fillOpacity': 15, 'spanNulls': True},
               }}}),

        # ── Row 2: Top talkers ───────────────────────────────────────────────
        _panel(7, 'Top Source IPs', 'table', 0, 12, 8, 8,
               [_target(
                   [{'id': '1', 'type': 'count'},
                    {'id': '2', 'type': 'sum', 'field': 'netflow.bytes'},
                    {'id': '3', 'type': 'sum', 'field': 'netflow.packets'}],
                   [{'id': '4', 'type': 'terms', 'field': 'netflow.src_ip',
                     'settings': {'size': '10', 'order': 'desc', 'orderBy': '1'}}],
               )],
               {'options': {'sortBy': [{'displayName': 'Count', 'desc': True}]}}),

        _panel(8, 'Top Destination IPs', 'table', 8, 12, 8, 8,
               [_target(
                   [{'id': '1', 'type': 'count'},
                    {'id': '2', 'type': 'sum', 'field': 'netflow.bytes'}],
                   [{'id': '3', 'type': 'terms', 'field': 'netflow.dst_ip',
                     'settings': {'size': '10', 'order': 'desc', 'orderBy': '1'}}],
               )]),

        _panel(9, 'Top Destination Ports / Services', 'table', 16, 12, 8, 8,
               [_target(
                   [{'id': '1', 'type': 'count'},
                    {'id': '2', 'type': 'sum', 'field': 'netflow.bytes'}],
                   [{'id': '3', 'type': 'terms', 'field': 'netflow.dst_port',
                     'settings': {'size': '15', 'order': 'desc', 'orderBy': '1'}}],
               )],
               {'options': {'sortBy': [{'displayName': 'Count', 'desc': True}]}}),

        # ── Row 3: Protocol breakdown ─────────────────────────────────────────
        _panel(10, 'Protocol Distribution', 'piechart', 0, 20, 8, 8,
               [_target(
                   [{'id': '1', 'type': 'count'}],
                   [{'id': '2', 'type': 'terms', 'field': 'netflow.protocol',
                     'settings': {'size': '10', 'order': 'desc', 'orderBy': '1'}}],
               )],
               {'options': {'pieType': 'donut',
                            'reduceOptions': {'calcs': ['sum']},
                            'legend': {'displayMode': 'table', 'placement': 'right'}},
                'transformations': [
                    {'id': 'rowsToFields',
                     'options': {'nameField': 'netflow.protocol', 'valueField': 'Count'}}
                ]}),

        _panel(11, 'Traffic by Protocol (bytes/min)', 'timeseries', 8, 20, 16, 8,
               [{**_target([{'id': '1', 'type': 'sum', 'field': 'netflow.bytes'}],
                            [{'id': '2', 'type': 'date_histogram', 'field': '@timestamp',
                              'settings': {'interval': '1m', 'min_doc_count': '1'}}],
                            query=f'netflow.protocol:{p}'),
                  'alias': p, 'refId': r}
                 for p, r in [('TCP', 'A'), ('UDP', 'B'), ('ICMP', 'C')]],
               {'fieldConfig': {'defaults': {
                   'unit': 'Bps',
                   'custom': {'lineWidth': 2, 'fillOpacity': 10, 'spanNulls': True},
               }}}),

        # ── Row 4: TCP Flags + top flows ─────────────────────────────────────
        _panel(12, 'TCP Flags Distribution', 'piechart', 0, 28, 6, 7,
               [_top_terms('tcp_flags', size=8)],
               {'options': {'pieType': 'pie',
                            'legend': {'displayMode': 'table', 'placement': 'right'}},
                'transformations': [
                    {'id': 'rowsToFields',
                     'options': {'nameField': 'netflow.tcp_flags', 'valueField': 'Count'}}
                ]}),

        _panel(13, 'Bytes per Packet (avg)', 'gauge', 6, 28, 6, 7,
               [_target(
                   [{'id': '1', 'type': 'avg', 'field': 'netflow.bytes_per_packet'}],
                   [{'id': '2', 'type': 'date_histogram', 'field': '@timestamp',
                     'settings': {'interval': 'auto'}}],
               )],
               {'fieldConfig': {'defaults': {
                   'unit': 'bytes',
                   'thresholds': {'steps': [
                       {'color': 'green', 'value': None},
                       {'color': 'yellow', 'value': 500},
                       {'color': 'red', 'value': 1400},
                   ]},
               }}}),

        _panel(14, 'Flows Over Time by Exporter', 'timeseries', 12, 28, 12, 7,
               [{**_target([{'id': '1', 'type': 'count'}],
                            [{'id': '2', 'type': 'date_histogram', 'field': '@timestamp',
                              'settings': {'interval': '1m', 'min_doc_count': '1'}}],
                            query=f'netflow.exporter_ip:{ip}'),
                  'alias': ip, 'refId': r}
                 for ip, r in [('10.0.3.100', 'A')]],
               {'fieldConfig': {'defaults': {
                   'custom': {'lineWidth': 2, 'fillOpacity': 10, 'spanNulls': True},
               }}}),
    ]

    return {
        'title':         'NetFlow — Network Traffic Overview',
        'uid':           'netflow-overview',
        'tags':          ['netflow', 'network', 'monitoring'],
        'timezone':      'browser',
        'refresh':       '30s',
        'time':          {'from': 'now-1h', 'to': 'now'},
        'panels':        panels,
        'schemaVersion': 36,
        'version':       1,
    }


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description='Setup Grafana for NetFlow Monitoring')
    p.add_argument('--grafana',  default='http://localhost:3000',  help='Grafana URL')
    p.add_argument('--user',     default='admin',                  help='Grafana admin user')
    p.add_argument('--password', default='password',               help='Grafana admin password')
    p.add_argument('--es',       default='http://opensearch:9200',
                                                                   help='OpenSearch URL (as seen by Grafana container)')
    p.add_argument('--index',    default='netflow-flows',          help='ES index prefix')
    args = p.parse_args()

    client = GrafanaClient(args.grafana, args.user, args.password)

    if not client.wait_ready():
        sys.exit(1)

    print('[*] Creating OpenSearch datasource...')
    create_datasource(client, args.es, args.index)

    print('[*] Creating NetFlow dashboard...')
    payload = {'dashboard': build_dashboard(), 'folderId': 0, 'overwrite': True}
    resp, status = client.request('POST', '/api/dashboards/db', payload)
    if status == 200:
        uid = resp.get('uid', 'netflow-overview')
        url = f"{args.grafana}/d/{uid}"
        print(f'[OK] Dashboard: {url}')
        print()
        print('=' * 60)
        print('  Grafana dashboard ready!')
        print(f'  URL      : {url}')
        print(f'  Login    : admin / password')
        print(f'  Refresh  : 30s (auto-refreshes)')
        print('=' * 60)
    else:
        print(f'[ERR] Dashboard creation failed ({status}): {resp}')
        sys.exit(1)


if __name__ == '__main__':
    main()
