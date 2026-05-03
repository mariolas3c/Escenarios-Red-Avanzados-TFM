#!/usr/bin/env python3
"""
Monitor de logs WAF en tiempo real.
Analiza ataques detectados por el proxy WAF y muestra estadisticas.
"""

import os
import time
import re
from datetime import datetime
from collections import defaultdict

WAF_ATTACK_LOG = '/tmp/waf_attack_log.txt'
WAF_ACCESS_LOG = '/tmp/waf_access_log.txt'

cat_stats  = defaultdict(int)
ip_stats   = defaultdict(int)
sev_stats  = defaultdict(int)
recent     = []
total_bloq = 0
total_perm = 0

SEVERIDADES = {'CRITICAL': '!!!', 'HIGH': ' ! ', 'MEDIUM': ' - ', 'LOW': '   '}


def parsear_ataque(linea):
    """Extrae campos de una linea del log de ataques WAF."""
    info = {}
    for part in linea.split('|'):
        part = part.strip()
        if part.startswith('IP:'):
            info['ip'] = part[3:].strip()
        elif part.startswith('Cat:'):
            info['cat'] = part[4:].strip()
        elif part.startswith('Sev:'):
            info['sev'] = part[4:].strip()
        elif part.startswith('Regla:'):
            info['regla'] = part[6:].strip()
        elif 'BLOQUEADO' in part:
            info['accion'] = 'BLOQUEADO'
    return info if info else None


def limpiar_pantalla():
    os.system('clear 2>/dev/null || cls 2>/dev/null')


def mostrar_panel():
    limpiar_pantalla()
    ahora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print('=' * 70)
    print('  MONITOR WAF - ModSecurity + Nginx  |  Tiempo Real')
    print(f'  {ahora}')
    print('=' * 70)

    print()
    print(f'  Ataques BLOQUEADOS:  {total_bloq}')
    print(f'  Accesos PERMITIDOS:  {total_perm}')

    # Ataques por categoria
    print()
    print('  [ ATAQUES POR CATEGORIA ]')
    if not cat_stats:
        print('    (Sin ataques detectados todavia...)')
        print('    Ejecuta: atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --all')
    else:
        max_count = max(cat_stats.values()) if cat_stats else 1
        for cat, count in sorted(cat_stats.items(), key=lambda x: -x[1]):
            bar_len = int((count / max_count) * 30)
            bar = '#' * bar_len
            print(f'    {cat:18s} |{bar:<30s}| {count}')

    # Por severidad
    print()
    print('  [ POR SEVERIDAD ]')
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = sev_stats.get(sev, 0)
        sym = SEVERIDADES.get(sev, '   ')
        print(f'    [{sym}] {sev:10s} {count}')

    # Top IPs
    if ip_stats:
        print()
        print('  [ TOP IPs ATACANTES ]')
        top = sorted(ip_stats.items(), key=lambda x: -x[1])[:5]
        for ip, count in top:
            print(f'    {ip:18s} -> {count} ataques')

    # Ultimos ataques
    if recent:
        print()
        print('  [ ULTIMOS 8 ATAQUES DETECTADOS ]')
        for entry in recent[-8:]:
            print(f'    {entry}')

    print()
    print('  [ LOGS ]')
    print(f'    cat /tmp/waf_attack_log.txt   # Detalle de todos los ataques')
    print(f'    cat /tmp/waf_access_log.txt   # Accesos permitidos')
    print()
    print('  Actualizando cada 2 segundos... (Ctrl+C para salir)')
    print('=' * 70)


def contar_access_log(ruta, ultima_pos):
    """Cuenta nuevas lineas de accesos permitidos."""
    global total_perm
    if not os.path.exists(ruta):
        return ultima_pos
    size = os.path.getsize(ruta)
    if size <= ultima_pos:
        return ultima_pos
    with open(ruta, 'r') as f:
        f.seek(ultima_pos)
        for linea in f:
            if 'PERMITIDO' in linea:
                total_perm += 1
    return size


def procesar_attack_log(ruta, ultima_pos):
    """Procesa nuevas entradas del log de ataques."""
    global total_bloq
    if not os.path.exists(ruta):
        return ultima_pos
    size = os.path.getsize(ruta)
    if size <= ultima_pos:
        return ultima_pos
    with open(ruta, 'r') as f:
        f.seek(ultima_pos)
        for linea in f:
            linea = linea.strip()
            if 'BLOQUEADO' not in linea:
                continue
            total_bloq += 1
            info = parsear_ataque(linea)
            if not info:
                continue
            cat = info.get('cat', 'Desconocido')
            ip  = info.get('ip', 'unknown')
            sev = info.get('sev', 'MEDIUM')
            cat_stats[cat]  += 1
            ip_stats[ip]    += 1
            sev_stats[sev]  += 1
            sym = SEVERIDADES.get(sev, '   ')
            entrada = (
                f"{datetime.now().strftime('%H:%M:%S')} "
                f"[{sym}] {cat:15s} "
                f"from {ip}"
            )
            recent.append(entrada)
            # Mantener solo ultimas 50 entradas en memoria
            if len(recent) > 50:
                recent.pop(0)
    return size


def main():
    print('[*] Iniciando monitor WAF...')
    print(f'[*] Log ataques: {WAF_ATTACK_LOG}')
    print(f'[*] Log accesos: {WAF_ACCESS_LOG}')
    print('[*] Esperando eventos... (actualizacion cada 2s)\n')
    time.sleep(2)

    pos_ataque = 0
    pos_acceso = 0

    while True:
        try:
            pos_ataque = procesar_attack_log(WAF_ATTACK_LOG, pos_ataque)
            pos_acceso = contar_access_log(WAF_ACCESS_LOG, pos_acceso)
            mostrar_panel()
        except Exception as e:
            pass
        time.sleep(2)


if __name__ == '__main__':
    main()
