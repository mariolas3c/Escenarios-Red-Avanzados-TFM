#!/usr/bin/env python3
"""
Aplicacion Flask vulnerable para demostracion WAF.
Contiene endpoints intencionalmente vulnerables a SQLi, XSS, path traversal y CMDi.
SOLO debe ejecutarse en entornos de laboratorio aislados.
"""

import os
import html
import json
from datetime import datetime

try:
    from flask import Flask, request, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

# Fallback sin Flask
if not HAS_FLASK:
    import urllib.parse
    from http.server import HTTPServer, BaseHTTPRequestHandler

INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
<title>BancoApp - Demo WAF</title>
<style>
  body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
  h1   { color: #2c5282; border-bottom: 2px solid #2c5282; padding-bottom: 8px; }
  .card { background: white; padding: 20px; border-radius: 8px; margin: 12px 0;
          box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
  .card h3 { color: #4a5568; margin-top: 0; }
  a    { color: #3182ce; text-decoration: none; margin: 4px 8px 4px 0; }
  a:hover { text-decoration: underline; }
  input  { padding: 6px; margin: 4px; border: 1px solid #cbd5e0; border-radius: 4px; }
  button { padding: 6px 16px; background: #3182ce; color: white; border: none;
           border-radius: 4px; cursor: pointer; }
  .warn  { color: #c53030; font-size: 12px; }
  .info  { color: #718096; font-size: 12px; }
</style>
</head>
<body>
  <h1>BancoApp &mdash; Aplicacion Demo WAF</h1>
  <p class="warn">&#9888; Aplicacion intencionalmente vulnerable. Solo para uso en laboratorio.</p>
  <div class="card">
    <h3>Navegacion rapida</h3>
    <a href="/buscar?q=noticias">[Buscar]</a>
    <a href="/login">[Login]</a>
    <a href="/archivo?f=manual.pdf">[Archivo]</a>
    <a href="/ping?host=8.8.8.8">[Ping]</a>
    <a href="/api/info">[API Info]</a>
  </div>
  <div class="card">
    <h3>Formulario de Busqueda</h3>
    <form action="/buscar" method="get">
      <input type="text" name="q" placeholder="Buscar en BancoApp..." size="30">
      <button type="submit">Buscar</button>
    </form>
  </div>
  <div class="card">
    <h3>Login</h3>
    <form action="/login" method="post">
      <input type="text"     name="user" placeholder="Usuario">
      <input type="password" name="pass" placeholder="Password">
      <button type="submit">Entrar</button>
    </form>
    <p class="info">Credenciales demo: admin / admin123</p>
  </div>
  <div class="card">
    <h3>Informacion del sistema</h3>
    <p class="info">Backend: Flask (puerto 5000) &nbsp;|&nbsp; WAF proxy: Nginx+ModSecurity (puerto 80)</p>
    <p class="info">Si ves esta pagina via :5000 -&gt; SIN proteccion WAF</p>
    <p class="info">Si ves esta pagina via :80 &nbsp; -&gt; CON proteccion WAF</p>
  </div>
</body>
</html>"""


def ts():
    return datetime.now().strftime('%H:%M:%S')


if HAS_FLASK:
    app = Flask(__name__)

    @app.route('/')
    def index():
        return INDEX_HTML

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user   = request.form.get('user', '')
            passwd = request.form.get('pass', '')
        else:
            user   = request.args.get('user', '')
            passwd = request.args.get('pass', '')

        # Simula una consulta SQL vulnerable (no ejecuta realmente la DB)
        query = f"SELECT * FROM users WHERE user='{user}' AND pass='{passwd}'"

        if user == 'admin' and passwd == 'admin123':
            return f"""<html><body style="font-family:Arial;margin:40px">
            <h2 style="color:green">[{ts()}] Login EXITOSO</h2>
            <p>Bienvenido, <b>{html.escape(user)}</b></p>
            <p>Query simulada: <code>{html.escape(query)}</code></p>
            <p style="color:#c53030">Si llegaste aqui con SQLi, el WAF no bloqueo tu peticion!</p>
            <a href="/">Volver</a></body></html>"""
        else:
            return f"""<html><body style="font-family:Arial;margin:40px">
            <h2 style="color:red">[{ts()}] Login FALLIDO</h2>
            <p>Credenciales incorrectas para: <b>{html.escape(user)}</b></p>
            <p>Query simulada: <code>{html.escape(query)}</code></p>
            <p style="color:#c53030">Nota: La query refleja el input SIN sanitizar (vulnerable a SQLi)</p>
            <a href="/">Volver</a></body></html>""", 401

    @app.route('/buscar')
    def buscar():
        # Intencionalmente NO sanitiza q para demostrar XSS si pasa el WAF
        q = request.args.get('q', '')
        return f"""<html><body style="font-family:Arial;margin:40px">
        <h2>[{ts()}] Resultados de busqueda</h2>
        <p>Busqueda: {q}</p>
        <hr>
        <p>Resultado 1: Articulo sobre "{html.escape(q)}"</p>
        <p>Resultado 2: Guia relacionada con "{html.escape(q)}"</p>
        <p style="color:#c53030">Si ves codigo JS ejecutado arriba, el WAF no filtro el XSS</p>
        <a href="/">Volver</a></body></html>"""

    @app.route('/archivo')
    def archivo():
        # Intencionalmente vulnerable a path traversal
        f = request.args.get('f', 'manual.pdf')
        return f"""<html><body style="font-family:Arial;margin:40px">
        <h2>[{ts()}] Descarga de archivo</h2>
        <p>Archivo solicitado: <code>{html.escape(f)}</code></p>
        <p>[Simulacion] Leyendo: /var/www/documentos/{html.escape(f)}</p>
        <p style="color:#c53030">Si pediste ../../../../etc/passwd y llegaste aqui,
        el WAF no detecto el path traversal</p>
        <a href="/">Volver</a></body></html>"""

    @app.route('/ping')
    def ping():
        # Intencionalmente vulnerable a command injection
        host = request.args.get('host', '127.0.0.1')
        return f"""<html><body style="font-family:Arial;margin:40px">
        <h2>[{ts()}] Herramienta Ping</h2>
        <p>Host: <code>{html.escape(host)}</code></p>
        <p>[Simulacion] Ejecutando: ping -c 3 {html.escape(host)}</p>
        <pre>PING {html.escape(host)}: 56 data bytes
64 bytes from {html.escape(host)}: icmp_seq=0 ttl=64 time=0.5 ms
64 bytes from {html.escape(host)}: icmp_seq=1 ttl=64 time=0.4 ms</pre>
        <p style="color:#c53030">Si usaste ; | && y llegaste aqui, el WAF no detecto el CMDi</p>
        <a href="/">Volver</a></body></html>"""

    @app.route('/api/info')
    def api_info():
        return jsonify({
            'app':       'BancoApp Demo',
            'version':   '1.0.0',
            'backend':   'Flask/Python',
            'waf':       'ModSecurity + Nginx (simulado)',
            'timestamp': datetime.now().isoformat(),
            'endpoints': ['/', '/login', '/buscar', '/archivo', '/ping', '/api/info']
        })

    if __name__ == '__main__':
        print('[*] Iniciando aplicacion Flask en 0.0.0.0:5000')
        app.run(host='0.0.0.0', port=5000, debug=False)

else:
    # Fallback sin Flask usando http.server
    import urllib.parse
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class FallbackHandler(BaseHTTPRequestHandler):

        def do_GET(self):
            self._dispatch('GET', b'')

        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length) if length > 0 else b''
            self._dispatch('POST', body)

        def _dispatch(self, method, body_bytes):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            body_str = body_bytes.decode('utf-8', errors='replace')
            body_params = urllib.parse.parse_qs(body_str)

            def get(key, default=''):
                return (params.get(key) or body_params.get(key) or [default])[0]

            p = parsed.path
            if p == '/':
                resp, code = INDEX_HTML.encode(), 200
            elif p == '/buscar':
                q = get('q', '')
                resp = f'<html><body><h2>Busqueda: {q}</h2><a href="/">Volver</a></body></html>'.encode()
                code = 200
            elif p == '/login':
                user = get('user', '')
                passwd = get('pass', '')
                query = f"SELECT * FROM users WHERE user='{user}' AND pass='{passwd}'"
                if user == 'admin' and passwd == 'admin123':
                    resp = f'<html><body><h2 style="color:green">Login OK: {html.escape(user)}</h2></body></html>'.encode()
                    code = 200
                else:
                    resp = f'<html><body><h2 style="color:red">Login FALLIDO</h2><p>Query: {html.escape(query)}</p></body></html>'.encode()
                    code = 401
            elif p == '/archivo':
                f = get('f', 'manual.pdf')
                resp = f'<html><body><h2>Archivo: {html.escape(f)}</h2></body></html>'.encode()
                code = 200
            elif p == '/ping':
                host = get('host', '127.0.0.1')
                resp = f'<html><body><h2>Ping: {html.escape(host)}</h2><pre>Simulado OK</pre></body></html>'.encode()
                code = 200
            elif p == '/api/info':
                data = json.dumps({'app': 'BancoApp', 'backend': 'http.server fallback'})
                resp = data.encode()
                code = 200
            else:
                resp = b'<html><body><h1>404 Not Found</h1></body></html>'
                code = 404

            self.send_response(code)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def log_message(self, fmt, *args):
            pass

    if __name__ == '__main__':
        print('[*] Flask no disponible. Iniciando servidor HTTP fallback en 0.0.0.0:5000')
        print('[!] Instala Flask: pip3 install flask')
        HTTPServer(('0.0.0.0', 5000), FallbackHandler).serve_forever()
