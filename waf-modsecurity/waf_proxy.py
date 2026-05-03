#!/usr/bin/env python3
"""
WAF Proxy - ModSecurity + Nginx simulado
Proxy inverso con motor de reglas OWASP CRS (Core Rule Set) simplificado.
Bloquea ataques web comunes: SQLi, XSS, LFI/Path Traversal, CMDi, Log4Shell.
"""

import http.server
import urllib.request
import urllib.parse
import urllib.error
import re
import logging
import argparse
import threading
import os
from datetime import datetime

# Configuracion por defecto (sobreescrita por argumentos CLI)
BACKEND_HOST     = '10.0.2.90'
BACKEND_PORT     = 5000
WAF_LISTEN_PORT  = 80

# ----------------------------------------------------------------
# Logging
# ----------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('/tmp/waf_proxy.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('waf_proxy')

_attack_logger = logging.getLogger('waf_attacks')
_ah = logging.FileHandler('/tmp/waf_attack_log.txt')
_ah.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
_attack_logger.addHandler(_ah)
_attack_logger.setLevel(logging.WARNING)
_attack_logger.propagate = False

_access_logger = logging.getLogger('waf_access')
_ach = logging.FileHandler('/tmp/waf_access_log.txt')
_ach.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
_access_logger.addHandler(_ach)
_access_logger.setLevel(logging.INFO)
_access_logger.propagate = False

# ----------------------------------------------------------------
# Estadísticas globales
# ----------------------------------------------------------------
stats = {
    'total': 0, 'blocked': 0, 'allowed': 0,
    'sqli': 0, 'xss': 0, 'traversal': 0,
    'cmdinjection': 0, 'log4shell': 0, 'rfi': 0, 'otros': 0
}
stats_lock = threading.Lock()

# ----------------------------------------------------------------
# REGLAS WAF - inspiradas en OWASP ModSecurity CRS
# ----------------------------------------------------------------
WAF_RULES = [
    # SQL Injection (CRS 942xxx)
    {
        'id': '942100', 'category': 'SQLi', 'severity': 'CRITICAL',
        'name': 'SQL Injection detectado via patrones CRS',
        'stat_key': 'sqli',
        'patterns': [
            r"(?i)\b(union[\s\+\|/\*]+select)\b",
            r"(?i)\b(select[\s\+]+[\w\*,\s]+[\s\+]+from[\s\+]+\w+)\b",
            r"(?i)\b(insert[\s\+]+into|delete[\s\+]+from|update[\s\+]+\w+[\s\+]+set)\b",
            r"(?i)\b(drop[\s\+]+(table|database|schema)|truncate[\s\+]+table)\b",
            r"(?i)\b(exec[\s\+]*\(|execute[\s\+]*\(|xp_cmdshell|sp_executesql|sp_execute)\b",
            r"(?i)\b(sleep[\s\+]*\([\d]+\)|benchmark[\s\+]*\(|waitfor[\s\+]+delay)\b",
            r"(?i)\b(or|and)[\s\+]+['\"]?[\w]+['\"]?[\s\+]*[=<>!]+[\s\+]*['\"]?[\w]+",
            r"(?i)(--[\s]*$|;[\s]*--|/\*[\s\S]*?\*/)",
            r"(?i)\b(information_schema|sys\.tables|sysobjects|pg_tables)\b",
        ]
    },
    # Cross-Site Scripting (CRS 941xxx)
    {
        'id': '941100', 'category': 'XSS', 'severity': 'HIGH',
        'name': 'XSS Attack detectado via libinjection',
        'stat_key': 'xss',
        'patterns': [
            r"(?i)<[\s]*(script|iframe|frame|object|embed|applet|link|meta|base)[^>]*>",
            r"(?i)<[^>]+(on(load|click|error|mouseover|mouseout|submit|focus|blur|"
            r"change|input|keydown|keyup|dblclick|contextmenu)[\s]*=)",
            r"(?i)(javascript[\s]*:|vbscript[\s]*:)",
            r"(?i)<[^>]+src[\s]*=[\s]*['\"][\s]*(javascript|vbscript|data)[\s]*:",
            r"(?i)\b(eval[\s]*\(|alert[\s]*\(|confirm[\s]*\(|prompt[\s]*\()\s*['\"]",
            r"(?i)<img[^>]+(onerror|onload)[\s]*=",
            r"(?i)<svg[^>]*(onload|onerror)[\s]*=",
            r"(?i)\bexpression[\s]*\(",
        ]
    },
    # Path Traversal / LFI (CRS 930xxx)
    {
        'id': '930100', 'category': 'PathTraversal', 'severity': 'HIGH',
        'name': 'Path Traversal Attack (LFI)',
        'stat_key': 'traversal',
        'patterns': [
            r"(?i)(\.\.[\\/]){2,}",
            r"(?i)(\.\.%2[fF]){2,}",
            r"(?i)(\.\.%5[cC]){2,}",
            r"(?i)(%2e%2e%2f|%2e%2e/|\.\.%2f|\.\.%5c){1,}",
            r"(?i)\.\./.*(/etc/(passwd|shadow|hosts|group|crontab)|/proc/self)",
            r"(?i)([\\/]etc[\\/](passwd|shadow|hosts|group)|[\\/]proc[\\/]self[\\/])",
            r"(?i)(boot\.ini|win\.ini|system\.ini|\\\\windows\\\\system32)",
            r"(?i)(\.\.[\\/]){1,}(windows|winnt|system32|syswow64)",
        ]
    },
    # Command / OS Injection (CRS 932xxx)
    {
        'id': '932100', 'category': 'CMDInjection', 'severity': 'CRITICAL',
        'name': 'Remote Command Execution via OS Command Injection',
        'stat_key': 'cmdinjection',
        'patterns': [
            r"(?i)[;&|`]\s*(cat|ls|id|whoami|uname|pwd|wget|curl|bash|sh|dash|"
            r"python|perl|php|nc|ncat|netcat|nmap)\b",
            r"(?i)(\|\||\&\&)\s*\w+",
            r"(?i)\$\([\w\s/]+\)",
            r"(?i)`[\w\s/]+`",
            r"(?i)\b(cmd\.exe|/bin/(sh|bash|dash|zsh)|powershell(\.exe)?)\b",
            r"(?i)%0[aAdD].*(id|cat|ls|whoami)",
        ]
    },
    # Remote File Inclusion (CRS 931xxx)
    {
        'id': '931100', 'category': 'RFI', 'severity': 'HIGH',
        'name': 'Remote File Inclusion Attack',
        'stat_key': 'rfi',
        'patterns': [
            r"(?i)=\s*(https?|ftp)://[^\s&]+\.(php|asp|aspx|jsp|cgi|py|pl)",
            r"(?i)(https?|ftp)://[^/\s]+/[^\s]*\?(https?|ftp)://",
        ]
    },
    # Log4Shell CVE-2021-44228 (CRS 944xxx)
    {
        'id': '944150', 'category': 'Log4Shell', 'severity': 'CRITICAL',
        'name': 'Log4Shell / JNDI Injection (CVE-2021-44228)',
        'stat_key': 'log4shell',
        'patterns': [
            # Deteccion directa con ${jndi:
            r"(?i)\$\{jndi\s*:",
            # jndi: como keyword standalone — cubre curl que elimina los {} por glob expansion
            r"(?i)\bjndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nis)s?://",
            # jndi: en cualquier contexto (sin requerir ${})
            r"(?i)\bjndi\s*:",
            # $ codificado como %24 con { como %7B
            r"(?i)%24[\w%]*%7[Bb][\w%]*jndi",
            # $ literal con { codificado como %7B
            r"(?i)\$%7[Bb][\w%]*jndi",
            # Obfuscacion con lower/upper dentro de ${}
            r"(?i)\$\{[\w:\s]*lower[\w:\s]*j[\w:\s]*n[\w:\s]*d[\w:\s]*i",
            r"(?i)\$\{[\w:\s]*upper[\w:\s]*j[\w:\s]*n[\w:\s]*d[\w:\s]*i",
            # Cualquier ${...jndi...}
            r"(?i)\$\{[^}]*jndi[^}]*}",
            # Obfuscacion con interpolacion anidada ${${...}jndi:}
            r"(?i)\$\{\$\{",
        ]
    },
]

# Pagina de bloqueo
BLOCKED_PAGE = """\
<!DOCTYPE html>
<html>
<head>
  <title>403 Forbidden - WAF Blocked</title>
  <style>
    body  {{ font-family: Arial, sans-serif; text-align: center;
             margin-top: 80px; background: #1a1a2e; color: #e0e0e0; }}
    .box  {{ background: #16213e; border: 2px solid #e74c3c;
             border-radius: 10px; display: inline-block; padding: 30px 50px; }}
    h1    {{ color: #e74c3c; font-size: 52px; margin: 0 0 10px 0; }}
    h2    {{ color: #e74c3c; margin-top: 0; }}
    .code {{ background: #0f3460; padding: 12px; border-radius: 5px;
             font-family: monospace; margin: 12px 0; text-align: left; }}
    .badge{{ background: #e74c3c; color: white; padding: 2px 8px;
             border-radius: 3px; font-size: 11px; font-weight: bold; }}
    .foot {{ color: #718096; font-size: 11px; margin-top: 20px; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>&#x26D4; 403</h1>
    <h2>Acceso Bloqueado por WAF</h2>
    <p>ModSecurity ha detectado y bloqueado una peticion maliciosa.</p>
    <div class="code">
      Regla ID:   {rule_id}<br>
      Categoria:  {category}&nbsp;&nbsp;
      Severidad:  <span class="badge">{severity}</span><br>
      Descripcion: {rule_name}
    </div>
    <p class="foot">
      Powered by Nginx 1.24 + ModSecurity v3 (WAF Demo &mdash; TFM Seguridad de Redes)
    </p>
  </div>
</body>
</html>"""


def _inspect(value):
    """
    Evalua un string contra todas las reglas WAF en multiples variantes de decodificacion.
    Retorna la primera regla que coincida, o None.
    """
    # Construir conjunto de variantes a comprobar
    candidates = {value}
    try:
        d1 = urllib.parse.unquote_plus(value)
        candidates.add(d1)
        # Segunda pasada: cubre doble-encoding (%2525 -> %25 -> %)
        d2 = urllib.parse.unquote_plus(d1)
        candidates.add(d2)
        # unquote sin convertir + a espacio (por si el valor viene sin +)
        d3 = urllib.parse.unquote(value)
        candidates.add(d3)
    except Exception:
        pass

    for candidate in candidates:
        for rule in WAF_RULES:
            for pat in rule['patterns']:
                try:
                    if re.search(pat, candidate):
                        return rule
                except re.error:
                    pass
    return None


def inspect_request(method, path, headers, body):
    """
    Inspecciona URL, query params individuales, headers y body contra las reglas WAF.
    Retorna (bloqueado, regla_coincidente, ubicacion, payload) o (False, None, None, None).
    """
    # 1. URL completa (path + query string) en crudo y decodificado
    for target in [path, urllib.parse.unquote(path)]:
        rule = _inspect(target)
        if rule:
            return True, rule, 'URL', target[:200]

    # 2. Valores de query parameters individuales (captura payloads en valores concretos)
    #    Esto cubre el caso en que curl elimina/codifica los {} y el valor llega como
    #    "jndi:ldap://..." sin el prefijo ${
    try:
        parsed = urllib.parse.urlparse(path)
        raw_qs = urllib.parse.unquote_plus(parsed.query)
        for key, values in urllib.parse.parse_qs(raw_qs, keep_blank_values=True).items():
            for val in values:
                rule = _inspect(val)
                if rule:
                    return True, rule, f'Param:{key}', val[:200]
    except Exception:
        pass

    # 3. Headers sensibles
    for h in ('User-Agent', 'Referer', 'X-Forwarded-For', 'Cookie', 'X-Custom-Header'):
        v = headers.get(h, '')
        if v:
            rule = _inspect(v)
            if rule:
                return True, rule, f'Header:{h}', v[:200]

    # 4. Body (POST / PUT)
    if body:
        rule = _inspect(body)
        if rule:
            return True, rule, 'Body', body[:200]

    return False, None, None, None


class WAFProxyHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        self._handle('GET', None)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace') if length else None
        self._handle('POST', body)

    def do_HEAD(self):
        self._handle('HEAD', None)

    def do_PUT(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', errors='replace') if length else None
        self._handle('PUT', body)

    def _handle(self, method, body):
        client_ip = self.client_address[0]
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with stats_lock:
            stats['total'] += 1

        blocked, rule, location, payload = inspect_request(
            method, self.path, self.headers, body
        )

        if blocked:
            self._block(client_ip, method, self.path, rule, location, payload, ts)
        else:
            self._forward(client_ip, method, self.path, body, ts)

    def _block(self, client_ip, method, path, rule, location, payload, ts):
        with stats_lock:
            stats['blocked'] += 1
            stats[rule['stat_key']] += 1

        _attack_logger.warning(
            f"BLOQUEADO | IP:{client_ip} | {method} {path[:80]} | "
            f"Regla:{rule['id']} | Cat:{rule['category']} | "
            f"Sev:{rule['severity']} | Loc:{location} | "
            f"Payload:{payload[:100] if payload else '-'}"
        )

        print(f"\n[!!!] ATAQUE DETECTADO Y BLOQUEADO [!!!]")
        print(f"  Timestamp:  {ts}")
        print(f"  IP:         {client_ip}")
        print(f"  Request:    {method} {path[:70]}")
        print(f"  Regla:      [{rule['id']}] {rule['name']}")
        print(f"  Categoria:  {rule['category']} ({rule['severity']})")
        print(f"  Ubicacion:  {location}")
        if payload:
            print(f"  Payload:    {payload[:70]}")
        print(f"  Respuesta:  HTTP 403 Forbidden\n")

        body_html = BLOCKED_PAGE.format(
            rule_id=rule['id'],
            category=rule['category'],
            severity=rule['severity'],
            rule_name=rule['name']
        ).encode('utf-8')

        self.send_response(403)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body_html)))
        self.send_header('X-WAF-Action', 'BLOCKED')
        self.send_header('X-WAF-Rule', rule['id'])
        self.send_header('Server', 'nginx/1.24.0 (ModSecurity WAF)')
        self.end_headers()
        self.wfile.write(body_html)

    def _forward(self, client_ip, method, path, body, ts):
        backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}{path}"

        with stats_lock:
            stats['allowed'] += 1

        try:
            req = urllib.request.Request(
                backend_url,
                data=body.encode('utf-8') if body else None,
                method=method
            )
            for h in ('Content-Type', 'Accept', 'Accept-Language'):
                v = self.headers.get(h)
                if v:
                    req.add_header(h, v)
            req.add_header('X-Forwarded-For', client_ip)
            req.add_header('X-Real-IP', client_ip)
            req.add_header('X-Forwarded-By', 'WAF-ModSecurity')

            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read()
                status    = resp.status
                ctype     = resp.headers.get('Content-Type', 'text/html')

            _access_logger.info(
                f"PERMITIDO | IP:{client_ip} | {method} {path[:80]} | "
                f"Backend:{status}"
            )

            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(resp_body)))
            self.send_header('X-WAF-Action', 'ALLOWED')
            self.send_header('Server', 'nginx/1.24.0 (ModSecurity WAF)')
            self.end_headers()
            self.wfile.write(resp_body)

        except urllib.error.URLError as e:
            err = f"""<!DOCTYPE html><html><body>
            <h1>502 Bad Gateway</h1>
            <p>Backend no disponible: {str(e)}</p>
            <p>Verifica que Flask este corriendo en {BACKEND_HOST}:{BACKEND_PORT}</p>
            </body></html>""".encode()
            self.send_response(502)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            logger.error(f"Backend no disponible: {e}")

    def log_message(self, fmt, *args):
        pass  # Silenciar logs HTTP por defecto; usamos nuestros loggers


def imprimir_stats():
    with stats_lock:
        s = stats.copy()
    total_ataques = s['blocked']
    print(f"\n{'='*55}")
    print(f"  ESTADISTICAS WAF FINALES")
    print(f"{'='*55}")
    print(f"  Total peticiones:      {s['total']}")
    print(f"  Peticiones BLOQUEADAS: {s['blocked']}")
    print(f"  Peticiones PERMITIDAS: {s['allowed']}")
    print(f"\n  Desglose de ataques bloqueados:")
    print(f"    SQL Injection:       {s['sqli']}")
    print(f"    XSS:                 {s['xss']}")
    print(f"    Path Traversal:      {s['traversal']}")
    print(f"    Command Injection:   {s['cmdinjection']}")
    print(f"    Log4Shell:           {s['log4shell']}")
    print(f"    RFI:                 {s['rfi']}")
    print(f"    Otros:               {s['otros']}")
    print(f"{'='*55}\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='WAF Proxy - ModSecurity + Nginx simulado')
    parser.add_argument('--backend',      default=BACKEND_HOST, help='IP backend Flask')
    parser.add_argument('--backend-port', type=int, default=BACKEND_PORT, help='Puerto backend')
    parser.add_argument('--port',         type=int, default=WAF_LISTEN_PORT, help='Puerto escucha WAF')
    args = parser.parse_args()

    BACKEND_HOST    = args.backend
    BACKEND_PORT    = args.backend_port

    total_patrones = sum(len(r['patterns']) for r in WAF_RULES)

    print('=' * 60)
    print('  WAF Proxy - ModSecurity + Nginx (simulado)')
    print('=' * 60)
    print(f'  Escuchando:      0.0.0.0:{args.port}')
    print(f'  Backend:         {BACKEND_HOST}:{BACKEND_PORT}')
    print(f'  Log ataques:     /tmp/waf_attack_log.txt')
    print(f'  Log accesos:     /tmp/waf_access_log.txt')
    print(f'  Categorias WAF:  {len(WAF_RULES)}')
    print(f'  Patrones totales:{total_patrones}')
    print('=' * 60)
    print()

    server = http.server.HTTPServer(('0.0.0.0', args.port), WAFProxyHandler)
    print(f'[*] WAF iniciado. Esperando peticiones...\n')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n[*] WAF detenido.')
        imprimir_stats()
