#!/usr/bin/env python3
"""
Script de demostracion del escenario SDN con Ryu.
Modos:
  --mode demo      Demostracion completa (firewall + bloqueo + estadisticas)
  --mode stats     Muestra estado actual del controlador
  --mode portscan  Lanza un port scan para demostrar deteccion automatica
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

REST_BASE   = 'http://127.0.0.1:8080'
ATACANTE_IP = '10.0.0.30'
SERVIDOR_IP = '10.0.0.100'


def api_get(path):
    try:
        with urllib.request.urlopen('%s%s' % (REST_BASE, path), timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        print('[ERROR] GET %s: %s' % (path, e))
        return None


def api_post(path, data=None):
    try:
        body = json.dumps(data).encode() if data else b''
        req = urllib.request.Request(
            '%s%s' % (REST_BASE, path), data=body, method='POST',
            headers={'Content-Type': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        print('[ERROR] POST %s: %s' % (path, e))
        return None


def api_delete(path):
    try:
        req = urllib.request.Request('%s%s' % (REST_BASE, path), method='DELETE')
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())
    except Exception as e:
        print('[ERROR] DELETE %s: %s' % (path, e))
        return None


def show_stats():
    print('\n--- Estado del Controlador Ryu ---')
    stats = api_get('/sdn/stats')
    if stats:
        print('  Switches conectados : %s' % stats.get('switches', []))
        print('  IPs bloqueadas      : %s' % stats.get('blocked_ips', []))
        flow_stats = stats.get('flow_stats', {})
        total = sum(len(f) for f in flow_stats.values())
        print('  Flujos OpenFlow     : %d' % total)
        for dpid, flows in flow_stats.items():
            for f in flows:
                print('    [dpid=%s] prio=%s pkts=%-6d bytes=%-8d match=%s' % (
                    dpid, f['priority'], f['packets'], f['bytes'], f['match']))

    print('\n--- Tabla MAC del switch ---')
    topology = api_get('/sdn/topology')
    if topology:
        for sw in topology.get('switches', []):
            for mac, port in sw.get('mac_table', {}).items():
                print('  MAC %s -> Puerto %s' % (mac, port))

    print('\n--- Reglas de Firewall ---')
    rules = api_get('/sdn/firewall/rules')
    if rules is not None:
        if rules:
            for r in rules:
                auto = ' [AUTO]' if r.get('auto') else ''
                print('  ID:%-4s  %s -> %s  proto:%-4s  puerto:%-5s  accion:%s%s' % (
                    r['id'], r['src_ip'], r['dst_ip'],
                    r['protocol'], r['dst_port'] or '*',
                    r['action'].upper(), auto))
        else:
            print('  (sin reglas activas)')


def run_full_demo():
    print('\n' + '='*65)
    print('  DEMOSTRACION COMPLETA - SDN + RYU + OPENFLOW 1.3')
    print('='*65)

    print('\n[1/6] Estado inicial:')
    show_stats()

    # Paso 2: bloquear flujo especifico
    print('\n[2/6] Creando regla de firewall: bloquear %s -> %s:80 TCP...'
          % (ATACANTE_IP, SERVIDOR_IP))
    rule = api_post('/sdn/firewall/rules', {
        'src_ip':   ATACANTE_IP,
        'dst_ip':   SERVIDOR_IP,
        'protocol': 'tcp',
        'dst_port': 80,
        'action':   'block',
    })
    if rule:
        print('  [OK] Regla creada: ID=%s' % rule['id'])
        print('  El controlador descartara paquetes TCP %s -> %s:80' % (ATACANTE_IP, SERVIDOR_IP))

    time.sleep(1)

    # Paso 3: ver reglas
    print('\n[3/6] Reglas activas:')
    rules = api_get('/sdn/firewall/rules')
    if rules:
        for r in rules:
            print('  ID:%-4s  %s -> %s:%s  [%s]' % (
                r['id'], r['src_ip'], r['dst_ip'],
                r['dst_port'] or '*', r['action'].upper()))

    time.sleep(1)

    # Paso 4: bloqueo de IP completo
    print('\n[4/6] Bloqueando IP completa del atacante (%s) en el switch...'
          % ATACANTE_IP)
    result = api_post('/sdn/block/%s' % ATACANTE_IP)
    if result:
        print('  [OK] Regla DROP prioridad 200 instalada en OVS para %s' % ATACANTE_IP)
        print('  Todo el trafico IPv4 del atacante sera descartado en el plano de datos')

    time.sleep(1)

    # Paso 5: stats
    print('\n[5/6] Estado tras bloqueos:')
    show_stats()

    # Paso 6: limpieza
    print('\n[6/6] Limpiando bloqueos y restaurando conectividad...')
    api_delete('/sdn/block/%s' % ATACANTE_IP)
    rules = api_get('/sdn/firewall/rules') or []
    for r in rules:
        if not r.get('auto'):
            api_delete('/sdn/firewall/rules/%s' % r['id'])
    print('  [OK] Conectividad restaurada.')

    print('\n' + '='*65)
    print('  Demo completada.')
    print('='*65 + '\n')


def run_portscan(target):
    """
    Lanza un port scan con Scapy para activar la deteccion automatica del
    controlador Ryu (bloqueo automatico tras ANOMALY_PORT_THRESHOLD puertos).
    """
    try:
        from scapy.all import IP, TCP, sr1, RandShort
    except ImportError:
        print('[ERROR] Scapy no instalado: pip3 install scapy')
        sys.exit(1)

    ports = list(range(1, 120))
    print('[*] Port scan a %s (%d puertos) con SYN packets...' % (target, len(ports)))
    print('[*] El controlador deberia detectarlo y bloquear la IP automaticamente.')
    print('[*] Ver log en tiempo real: tail -f /tmp/ryu_controller.log\n')

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags='S', seq=1)
        sr1(pkt, timeout=0.1, verbose=0)

    print('\n[*] Scan completado.')
    print('[*] Verificar bloqueo:')
    print('    curl http://127.0.0.1:8080/sdn/stats')


def main():
    parser = argparse.ArgumentParser(
        description='Demo del escenario SDN con Ryu',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            'Ejemplos:\n'
            '  python3 sdn_demo.py --mode demo\n'
            '  python3 sdn_demo.py --mode stats\n'
            '  python3 sdn_demo.py --mode portscan --target 10.0.0.100\n'
        ),
    )
    parser.add_argument('--mode', choices=['demo', 'stats', 'portscan'],
                        default='stats')
    parser.add_argument('--target', default=SERVIDOR_IP,
                        help='IP objetivo del portscan (default: %s)' % SERVIDOR_IP)
    args = parser.parse_args()

    if args.mode == 'demo':
        run_full_demo()
    elif args.mode == 'stats':
        show_stats()
    elif args.mode == 'portscan':
        run_portscan(args.target)


if __name__ == '__main__':
    main()
