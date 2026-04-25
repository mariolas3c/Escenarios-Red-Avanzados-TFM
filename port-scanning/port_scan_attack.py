#!/usr/bin/env python3
"""
Script de Escaneo de Puertos usando Scapy
Simula diferentes tipos de escaneo: SYN, FIN, XMAS, NULL, ACK y UDP
Compatible con el escenario Mininet de port-scanning + Suricata
"""

from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, send, RandShort
import sys
import os
import time
import argparse
from datetime import datetime

# Puertos objetivo por defecto (top 20 puertos comunes)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]

# Estados de puertos
OPEN     = "abierto"
CLOSED   = "cerrado"
FILTERED = "filtrado"

stats = {
    'open': 0,
    'closed': 0,
    'filtered': 0,
    'total_sent': 0,
}


def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")


def print_header(scan_type, target, ports):
    print('\n' + '='*65)
    print('  ESCANEO DE PUERTOS - %s' % scan_type.upper())
    print('='*65)
    print('Objetivo:   %s' % target)
    print('Tipo:       %s' % scan_type)
    print('Puertos:    %d puertos' % len(ports))
    print('Timestamp:  %s' % get_timestamp())
    print('-'*65)
    print('  %-6s  %-10s  %-15s  %s' % ('PUERTO', 'ESTADO', 'SERVICIO', 'DETALLE'))
    print('-'*65)


def get_service_name(port):
    """Nombre del servicio por puerto"""
    services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind',
        135: 'msrpc', 139: 'netbios-ssn', 143: 'imap', 443: 'https',
        445: 'smb', 993: 'imaps', 995: 'pop3s', 1723: 'pptp',
        3306: 'mysql', 3389: 'rdp', 5900: 'vnc', 8080: 'http-alt',
    }
    return services.get(port, 'unknown')


def print_result(port, status, detail=''):
    service = get_service_name(port)
    marker = {OPEN: '[+]', CLOSED: '[-]', FILTERED: '[?]'}.get(status, '   ')
    if status == OPEN:
        print('%s %-6d  %-10s  %-15s  %s' % (marker, port, status, service, detail))
    elif status == FILTERED:
        print('%s %-6d  %-10s  %-15s  %s' % (marker, port, status, service, detail))
    # Solo mostramos abiertos y filtrados por defecto para no saturar la salida
    status_key = {OPEN: 'open', CLOSED: 'closed', FILTERED: 'filtered'}.get(status, 'filtered')
    stats[status_key] += 1


def syn_scan(target, ports, iface=None, timeout=1):
    """
    SYN Scan (Half-Open / Stealth): envia SYN, espera SYN-ACK o RST
    Equivalente a: nmap -sS <target>
    """
    print_header('SYN Scan (Stealth / Half-Open)', target, ports)
    print('[*] Enviando paquetes SYN...\n')

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags='S', seq=100)
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface)
        stats['total_sent'] += 1

        if resp is None:
            print_result(port, FILTERED, 'no response')
        elif resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags == 0x12:  # SYN-ACK -> puerto abierto
                # Enviar RST para no completar el handshake (stealth)
                rst = IP(dst=target) / TCP(dport=port, sport=resp[TCP].dport,
                                           flags='R', seq=resp[TCP].ack)
                send(rst, verbose=0, iface=iface)
                stats['total_sent'] += 1
                print_result(port, OPEN, 'SYN-ACK recibido')
            elif flags == 0x14:  # RST-ACK -> puerto cerrado
                print_result(port, CLOSED, 'RST recibido')
            else:
                print_result(port, FILTERED, 'flags=%s' % hex(flags))
        elif resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                print_result(port, FILTERED, 'ICMP unreachable tipo %d' % icmp_code)
            else:
                print_result(port, FILTERED, 'ICMP tipo %d' % icmp_type)


def fin_scan(target, ports, iface=None, timeout=1):
    """
    FIN Scan: envia paquete con solo flag FIN
    Puertos abiertos -> no responden (RFC 793)
    Puertos cerrados -> responden con RST
    Equivalente a: nmap -sF <target>
    """
    print_header('FIN Scan', target, ports)
    print('[*] Enviando paquetes FIN...\n')

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags='F', seq=100)
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface)
        stats['total_sent'] += 1

        if resp is None:
            # Sin respuesta en sistema *nix -> posiblemente abierto o filtrado
            print_result(port, OPEN, 'sin respuesta (posible abierto)')
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            print_result(port, CLOSED, 'RST recibido')
        elif resp.haslayer(ICMP):
            print_result(port, FILTERED, 'ICMP unreachable')


def xmas_scan(target, ports, iface=None, timeout=1):
    """
    XMAS Scan: envia paquete con flags FIN+PSH+URG (todos encendidos)
    Equivalente a: nmap -sX <target>
    """
    print_header('XMAS Scan (FIN+PSH+URG)', target, ports)
    print('[*] Enviando paquetes XMAS (FIN+PSH+URG)...\n')

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags='FPU', seq=100)
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface)
        stats['total_sent'] += 1

        if resp is None:
            print_result(port, OPEN, 'sin respuesta (posible abierto)')
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            print_result(port, CLOSED, 'RST recibido')
        elif resp.haslayer(ICMP):
            print_result(port, FILTERED, 'ICMP unreachable')


def null_scan(target, ports, iface=None, timeout=1):
    """
    NULL Scan: envia paquete TCP sin ninguna flag
    Equivalente a: nmap -sN <target>
    """
    print_header('NULL Scan (sin flags TCP)', target, ports)
    print('[*] Enviando paquetes TCP NULL (flags=0)...\n')

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags=0, seq=100)
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface)
        stats['total_sent'] += 1

        if resp is None:
            print_result(port, OPEN, 'sin respuesta (posible abierto)')
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
            print_result(port, CLOSED, 'RST recibido')
        elif resp.haslayer(ICMP):
            print_result(port, FILTERED, 'ICMP unreachable')


def ack_scan(target, ports, iface=None, timeout=1):
    """
    ACK Scan: envia paquete ACK para mapear reglas de firewall
    Puertos no filtrados responden con RST
    Equivalente a: nmap -sA <target>
    """
    print_header('ACK Scan (mapeo de firewall)', target, ports)
    print('[*] Enviando paquetes ACK...\n')

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, sport=RandShort(), flags='A', seq=100)
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface)
        stats['total_sent'] += 1

        if resp is None:
            print_result(port, FILTERED, 'sin respuesta (filtrado por firewall)')
        elif resp.haslayer(TCP) and resp[TCP].flags == 0x04:  # RST
            print_result(port, OPEN, 'RST recibido (no filtrado)')
        elif resp.haslayer(ICMP):
            print_result(port, FILTERED, 'ICMP unreachable')


def udp_scan(target, ports=None, iface=None, timeout=2):
    """
    UDP Scan: envia paquetes UDP vacios
    Puerto cerrado -> ICMP port-unreachable
    Puerto abierto -> sin respuesta o respuesta UDP
    Equivalente a: nmap -sU <target>
    """
    udp_ports = ports if ports else [
        53, 67, 68, 69, 123, 137, 138, 161, 162, 500,
        514, 520, 1900, 4500, 5353
    ]
    print_header('UDP Scan', target, udp_ports)
    print('[*] Enviando paquetes UDP...\n')

    for port in udp_ports:
        pkt = IP(dst=target) / UDP(dport=port, sport=RandShort())
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface)
        stats['total_sent'] += 1

        if resp is None:
            print_result(port, OPEN, 'sin respuesta (open|filtered)')
        elif resp.haslayer(UDP):
            print_result(port, OPEN, 'respuesta UDP recibida')
        elif resp.haslayer(ICMP):
            icmp_type = resp[ICMP].type
            icmp_code = resp[ICMP].code
            if icmp_type == 3 and icmp_code == 3:
                print_result(port, CLOSED, 'ICMP port-unreachable')
            elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
                print_result(port, FILTERED, 'ICMP admin-prohibited')


def print_summary():
    print('\n' + '='*65)
    print('  RESUMEN DEL ESCANEO')
    print('='*65)
    print('Puertos abiertos:    %d' % stats['open'])
    print('Puertos cerrados:    %d' % stats['closed'])
    print('Puertos filtrados:   %d' % stats['filtered'])
    print('Paquetes enviados:   %d' % stats['total_sent'])
    print('='*65 + '\n')


def main():
    parser = argparse.ArgumentParser(
        description='Escaner de puertos educativo para escenario Mininet + Suricata',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplos:
  python3 port_scan_attack.py --target 10.0.1.10 --scan syn
  python3 port_scan_attack.py --target 10.0.1.10 --scan xmas --ports 20-25,80,443
  python3 port_scan_attack.py --target 10.0.1.10 --scan all
        """
    )
    parser.add_argument('--target', required=True, help='IP de la victima (ej: 10.0.1.10)')
    parser.add_argument('--scan', required=True,
                        choices=['syn', 'fin', 'xmas', 'null', 'ack', 'udp', 'all'],
                        help='Tipo de escaneo')
    parser.add_argument('--ports', default=None,
                        help='Rango de puertos (ej: 1-1024 o 22,80,443). Por defecto: top-20')
    parser.add_argument('--iface', default=None,
                        help='Interfaz de red (ej: attacker-eth0)')
    parser.add_argument('--timeout', type=float, default=0.5,
                        help='Timeout por puerto en segundos (default: 0.5)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print('[ERROR] Este script requiere privilegios root.')
        print('[INFO]  Ejecuta: sudo python3 port_scan_attack.py ...')
        sys.exit(1)

    # Resolver lista de puertos
    if args.ports:
        ports = []
        for part in args.ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    else:
        ports = DEFAULT_PORTS

    print('\n[WARNING] Este script es solo para propositos educativos.')
    print('[WARNING] Escanear sistemas sin autorizacion es ILEGAL.\n')
    print('[INFO] Objetivo:  %s' % args.target)
    print('[INFO] Tipo scan: %s' % args.scan)
    print('[INFO] Puertos:   %d a escanear' % len(ports))
    print('[INFO] Interfaz:  %s' % (args.iface or 'auto'))
    print('[INFO] Suricata deberia detectar el trafico en el monitor...\n')

    time.sleep(1)

    scan_map = {
        'syn':  syn_scan,
        'fin':  fin_scan,
        'xmas': xmas_scan,
        'null': null_scan,
        'ack':  ack_scan,
        'udp':  udp_scan,
    }

    try:
        if args.scan == 'all':
            print('[*] Ejecutando TODOS los tipos de escaneo...\n')
            for scan_type, scan_func in scan_map.items():
                if scan_type != 'udp':
                    scan_func(args.target, ports, iface=args.iface, timeout=args.timeout)
                else:
                    scan_func(args.target, iface=args.iface, timeout=args.timeout)
                time.sleep(1)
        else:
            scan_func = scan_map[args.scan]
            if args.scan == 'udp':
                scan_func(args.target, ports, iface=args.iface, timeout=args.timeout)
            else:
                scan_func(args.target, ports, iface=args.iface, timeout=args.timeout)

        print_summary()

    except KeyboardInterrupt:
        print('\n\n[!] Escaneo detenido por el usuario.')
        print_summary()
        sys.exit(0)
    except Exception as e:
        print('\n[ERROR] %s' % e)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
