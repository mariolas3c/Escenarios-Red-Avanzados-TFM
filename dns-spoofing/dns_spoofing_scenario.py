#!/usr/bin/python
"""
Escenario de DNS Spoofing en Mininet
- Topologia con servidor DNS legitimo y atacante
- Sistema de deteccion de DNS spoofing
- Scripts de ataque y defensa incluidos
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

def createDNSSpoofingTopology():
    """
    Topologia para demostrar DNS Spoofing:
    
    Internet --- Gateway --- Switch --- [Client, DNS_Server, Attacker, Web_Server, Monitor]
    
    - Gateway: 10.0.0.1 (router)
    - DNS_Server: 10.0.0.53 (servidor DNS legitimo)
    - Client: 10.0.0.10 (victima del ataque)
    - Attacker: 10.0.0.66 (realiza DNS spoofing)
    - Web_Server: 10.0.0.80 (servidor web legitimo)
    - Fake_Server: 10.0.0.99 (servidor web falso del atacante)
    - Monitor: 10.0.0.100 (sistema de deteccion IDS)
    """
    
    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('sudo pkill -9 dnsmasq 2>/dev/null')
    
    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    
    info('*** Creando hosts\n')
    # Gateway/Router
    gateway = net.addHost('gateway', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    
    # Servidor DNS legitimo
    dns_server = net.addHost('dns', ip='10.0.0.53/24', mac='00:00:00:00:00:53')
    
    # Cliente (victima)
    client = net.addHost('client', ip='10.0.0.10/24', mac='00:00:00:00:00:10')
    
    # Atacante (DNS spoofing)
    attacker = net.addHost('attacker', ip='10.0.0.66/24', mac='00:00:00:00:00:66')
    
    # Servidor web legitimo
    web_server = net.addHost('webserver', ip='10.0.0.80/24', mac='00:00:00:00:00:80')
    
    # Servidor web falso (del atacante)
    fake_server = net.addHost('fakeserver', ip='10.0.0.99/24', mac='00:00:00:00:00:99')
    
    # Monitor/IDS
    monitor = net.addHost('monitor', ip='10.0.0.100/24', mac='00:00:00:00:00:AA')
    
    info('*** Creando switch\n')
    switch = net.addSwitch('s1', failMode='standalone')
    
    info('*** Creando enlaces\n')
    net.addLink(gateway, switch)
    net.addLink(dns_server, switch)
    net.addLink(client, switch)
    net.addLink(attacker, switch)
    net.addLink(web_server, switch)
    net.addLink(fake_server, switch)
    net.addLink(monitor, switch)
    
    info('*** Iniciando red\n')
    net.start()
    
    time.sleep(2)
    
    info('*** Configurando servicios\n')
    configureNetwork(gateway, dns_server, client, attacker, web_server, fake_server, monitor, switch)
    
    info('*** Red iniciada\n')
    printWelcomeMessage()
    
    CLI(net)
    
    info('*** Deteniendo servicios\n')
    dns_server.cmd('pkill -9 dnsmasq')
    web_server.cmd('pkill -9 python3')
    fake_server.cmd('pkill -9 python3')
    
    info('*** Deteniendo red\n')
    net.stop()

def configureNetwork(gateway, dns_server, client, attacker, web_server, fake_server, monitor, switch):
    """
    Configura DNS, servidores web y port mirroring
    """
    # Configurar rutas por defecto
    for host in [dns_server, client, attacker, web_server, fake_server, monitor]:
        host.cmd('route add default gw 10.0.0.1')
    
    # IMPORTANTE: Detener systemd-resolved que puede interferir
    info('  Deteniendo servicios DNS del sistema...\n')
    client.cmd('systemctl stop systemd-resolved 2>/dev/null || true')
    client.cmd('pkill -9 systemd-resolve 2>/dev/null || true')
    
    # Configurar DNS en el cliente
    info('  Configurando DNS en cliente (10.0.0.53)...\n')
    client.cmd('echo "nameserver 10.0.0.53" > /etc/resolv.conf')
    
    # IMPORTANTE: NO añadir a /etc/hosts para que el DNS spoofing funcione
    # /etc/hosts tiene prioridad sobre DNS, por eso el ataque no funcionaria
    info('  [INFO] /etc/hosts vacio - resolucion solo por DNS\n')
    
    # Configurar servidor DNS legitimo
    info('  Configurando servidor DNS legitimo (10.0.0.53)...\n')
    dns_config = """# Configuracion DNS legitima
port=53
bind-interfaces
interface=dns-eth0
listen-address=10.0.0.53
no-hosts
no-resolv
# Registros DNS legitimos
address=/www.banco.com/10.0.0.80
address=/banco.com/10.0.0.80
address=/www.example.com/10.0.0.80
address=/example.com/10.0.0.80
address=/legitimo.com/10.0.0.80
# DNS cache
cache-size=1000
log-queries
log-facility=/tmp/dns_legitimo.log
"""
    dns_server.cmd('echo "%s" > /tmp/dns_legitimo.conf' % dns_config)
    dns_server.cmd('pkill -9 dnsmasq 2>/dev/null')
    dns_server.cmd('dnsmasq -C /tmp/dns_legitimo.conf &')
    time.sleep(2)
    
    # Verificar que DNS esta corriendo
    dns_check = dns_server.cmd('pgrep dnsmasq')
    if dns_check.strip():
        info('  [OK] Servidor DNS iniciado (PID: %s)\n' % dns_check.strip())
    else:
        info('  [ERROR] Servidor DNS no inicio correctamente\n')
    
    # Configurar servidor web legitimo
    info('  Iniciando servidor web LEGITIMO (10.0.0.80)...\n')
    web_content = """<!DOCTYPE html>
<html>
<head>
    <title>Banco Legitimo</title>
    <style>
        body { font-family: Arial; background: #00ff00; padding: 50px; text-align: center; }
        .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }
        h1 { color: #006400; }
        .info { color: #333; margin: 20px 0; }
        .badge { background: #00ff00; color: white; padding: 10px 20px; border-radius: 5px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BANCO LEGITIMO</h1>
        <div class="info">
            <p><strong>Servidor Real y Seguro</strong></p>
            <p>IP: 10.0.0.80</p>
            <p class="badge">SITIO LEGITIMO</p>
        </div>
        <p>Este es el servidor REAL del banco.</p>
        <p>Conexion segura verificada.</p>
    </div>
</body>
</html>"""
    web_server.cmd('mkdir -p /tmp/webserver')
    web_server.cmd('echo \'%s\' > /tmp/webserver/index.html' % web_content)
    web_server.cmd('cd /tmp/webserver && python3 -m http.server 80 > /tmp/webserver.log 2>&1 &')
    
    # Configurar servidor web FALSO (phishing)
    info('  Iniciando servidor web FALSO/PHISHING (10.0.0.99)...\n')
    fake_content = """<!DOCTYPE html>
<html>
<head>
    <title>Banco Legitimo - FALSO</title>
    <style>
        body { font-family: Arial; background: #ff0000; padding: 50px; text-align: center; }
        .container { background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; border: 5px solid red; }
        h1 { color: #8b0000; }
        .warning { color: red; font-weight: bold; font-size: 24px; animation: blink 1s infinite; }
        @keyframes blink { 50% { opacity: 0; } }
        .info { margin: 20px 0; }
        .badge { background: #ff0000; color: white; padding: 10px 20px; border-radius: 5px; font-weight: bold; }
        form { margin: 20px 0; text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BANCO - Ingrese sus datos</h1>
        <div class="warning">*** SITIO PHISHING ***</div>
        <div class="info">
            <p>IP: 10.0.0.99 (SERVIDOR FALSO)</p>
            <p class="badge">SITIO MALICIOSO</p>
        </div>
        <form>
            <p>Usuario: <input type="text" name="user" placeholder="NO INGRESAR"></p>
            <p>Password: <input type="password" name="pass" placeholder="NO INGRESAR"></p>
            <button type="button">Ingresar (SIMULADO)</button>
        </form>
        <div class="warning">NO INGRESAR DATOS REALES</div>
    </div>
</body>
</html>"""
    fake_server.cmd('mkdir -p /tmp/fakeserver')
    fake_server.cmd('echo \'%s\' > /tmp/fakeserver/index.html' % fake_content)
    fake_server.cmd('cd /tmp/fakeserver && python3 -m http.server 80 > /tmp/fakeserver.log 2>&1 &')
    
    # Configurar port mirroring para el monitor
    info('  Configurando port mirroring para IDS...\n')
    os.system('ovs-ofctl add-flow s1 priority=1,action=flood')
    os.system('ovs-vsctl -- set Bridge s1 mirrors=@m -- '
              '--id=@monitor-eth0 get Port monitor-eth0 -- '
              '--id=@m create Mirror name=dns_mirror select-all=true output-port=@monitor-eth0')
    monitor.cmd('ifconfig monitor-eth0 promisc')
    info('  [OK] Port mirroring configurado\n')
    
    time.sleep(2)
    
    # Verificar servicios
    info('  Verificando servicios...\n')
    dns_status = dns_server.cmd('pgrep dnsmasq')
    web_status = web_server.cmd('pgrep -f "http.server"')
    fake_status = fake_server.cmd('pgrep -f "http.server"')
    
    if dns_status.strip():
        info('  [OK] Servidor DNS activo en 10.0.0.53\n')
        # Probar DNS
        test_dns = client.cmd('nslookup www.banco.com 10.0.0.53 2>&1 | grep Address | tail -1')
        info('  [TEST] DNS lookup: %s' % test_dns)
    else:
        info('  [ERROR] Servidor DNS no inicio\n')
    
    if web_status.strip():
        info('  [OK] Servidor web legitimo activo en 10.0.0.80\n')
    else:
        info('  [ERROR] Servidor web legitimo no inicio\n')
    
    if fake_status.strip():
        info('  [OK] Servidor web falso activo en 10.0.0.99\n')
    else:
        info('  [ERROR] Servidor web falso no inicio\n')

def printWelcomeMessage():
    """
    Muestra instrucciones de uso
    """
    print('\n' + '='*75)
    print('  >>> ESCENARIO DE DNS SPOOFING - ATAQUE Y DETECCION <<<')
    print('='*75)
    print('\n[TOPOLOGIA]:')
    print('    Gateway:     10.0.0.1   (Router)')
    print('    DNS Server:  10.0.0.53  (Servidor DNS legitimo)')
    print('    Client:      10.0.0.10  (Victima)')
    print('    Attacker:    10.0.0.66  (Atacante DNS spoofing)')
    print('    Web Server:  10.0.0.80  (Servidor web LEGITIMO)')
    print('    Fake Server: 10.0.0.99  (Servidor web FALSO/Phishing)')
    print('    Monitor:     10.0.0.100 (IDS)')
    
    print('\n[DOMINIOS CONFIGURADOS]:')
    print('    www.banco.com    -> 10.0.0.80 (legitimo)')
    print('    www.example.com  -> 10.0.0.80 (legitimo)')
    print('    legitimo.com     -> 10.0.0.80 (legitimo)')
    
    print('\n[FASE 1 - VERIFICAR FUNCIONAMIENTO NORMAL]:')
    print('    # Probar resolucion DNS normal')
    print('    mininet> client nslookup www.banco.com 10.0.0.53')
    print('    # Debe resolver a 10.0.0.80')
    print('')
    print('    # Verificar servidor DNS')
    print('    mininet> client dig @10.0.0.53 www.banco.com +short')
    print('    # Debe mostrar: 10.0.0.80')
    print('')
    print('    # Acceder directamente por IP (siempre funciona)')
    print('    mininet> client curl http://10.0.0.80')
    print('    # Debe mostrar "SITIO LEGITIMO"')
    print('')
    print('    # Acceder por nombre de dominio')
    print('    mininet> client curl http://www.banco.com')
    print('    # Si falla, usar: client curl http://10.0.0.80')
    print('')
    print('    # Ver configuracion DNS del cliente')
    print('    mininet> client cat /etc/resolv.conf')
    print('    # Ver tabla de hosts')
    print('    mininet> client cat /etc/hosts | grep banco')
    
    print('\n[FASE 2 - INICIAR SISTEMA DE DETECCION]:')
    print('    # Terminal 1: Iniciar monitor DNS IDS')
    print('    mininet> xterm monitor')
    print('    monitor# python3 /tmp/dns_detector.py')
    
    print('\n[FASE 3 - EJECUTAR ATAQUE DNS SPOOFING]:')
    print('    # Terminal 2: Ejecutar ataque')
    print('    mininet> xterm attacker')
    print('    attacker# python3 /tmp/dns_spoof_attack.py')
    print('')
    print('    # O ataque manual con dnsspoof (si esta instalado):')
    print('    attacker# dnsspoof -i attacker-eth0 -f /tmp/dns_hosts.txt')
    
    print('\n[FASE 4 - VERIFICAR ATAQUE]:')
    print('    # IMPORTANTE: El ataque es una "race condition"')
    print('    # El atacante y el DNS real compiten por responder primero')
    print('')
    print('    # Limpiar cache DNS (si existe)')
    print('    mininet> client systemd-resolve --flush-caches')
    print('')
    print('    # Probar resolucion DNS varias veces')
    print('    mininet> client nslookup www.banco.com 10.0.0.53')
    print('    # Puede resolver a 10.0.0.99 (FALSO) o 10.0.0.80 (REAL)')
    print('')
    print('    # Usar dig para ver solo la IP')
    print('    mininet> client dig @10.0.0.53 www.banco.com +short')
    print('    # Si muestra 10.0.0.99 = ATAQUE EXITOSO')
    print('    # Si muestra 10.0.0.80 = DNS real respondio primero')
    print('')
    print('    # Acceder al sitio')
    print('    mininet> client curl http://www.banco.com')
    print('    # Buscar: "10.0.0.99" = FALSO o "10.0.0.80" = LEGITIMO')
    print('')
    print('    # Comparacion directa por IP:')
    print('    mininet> client curl http://10.0.0.80 | grep LEGITIMO')
    print('    mininet> client curl http://10.0.0.99 | grep FALSO')
    print('')
    print('    # Script de prueba automatico:')
    print('    mininet> client bash /tmp/test_dns_spoofing.sh')
    print('')
    print('    # El IDS deberia alertar sobre respuestas DNS duplicadas/falsas')
    
    print('\n[FASE 5 - DEFENSA]:')
    print('    # Activar sistema de defensa')
    print('    mininet> xterm monitor')
    print('    monitor# python3 /tmp/dns_defender.py')
    print('')
    print('    # Limpiar cache DNS del cliente')
    print('    mininet> client systemd-resolve --flush-caches')
    
    print('\n[ARCHIVOS CREADOS]:')
    print('    /tmp/dns_spoof_attack.py     - Script de ataque DNS spoofing')
    print('    /tmp/dns_detector.py         - Sistema de deteccion IDS')
    print('    /tmp/dns_defender.py         - Sistema de defensa DNSSEC')
    print('    /tmp/test_dns_spoofing.sh    - Script de prueba automatico')
    print('    /tmp/dns_legitimo.log        - Log del servidor DNS')
    
    print('\n[NOTA IMPORTANTE - RACE CONDITION]:')
    print('    El DNS spoofing es una competencia de velocidad:')
    print('    - El ATACANTE intenta responder primero (IP falsa)')
    print('    - El DNS REAL tambien responde (IP correcta)')
    print('    - El cliente acepta la PRIMERA respuesta que llega')
    print('    - Puede que necesites hacer varias consultas')
    print('    - El IDS detectara AMBAS respuestas (duplicadas)')
    
    print('\n[COMPARACION VISUAL]:')
    print('    Servidor LEGITIMO (10.0.0.80): Fondo VERDE')
    print('    Servidor FALSO (10.0.0.99):    Fondo ROJO + advertencia')
    
    print('\n' + '='*75)
    print('  Escribe "exit" o presiona Ctrl+D para salir')
    print('='*75 + '\n')

if __name__ == '__main__':
    setLogLevel('info')
    createDNSSpoofingTopology()
