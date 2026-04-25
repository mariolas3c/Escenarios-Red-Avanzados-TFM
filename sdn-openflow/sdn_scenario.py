#!/usr/bin/python
"""
Escenario SDN con Controlador Ryu + OpenFlow 1.3 en Mininet
- L2 switch con aprendizaje de MACs gestionado por Ryu
- Firewall dinamico via REST API (bloqueo por IP, por flujo)
- Estadisticas de flujo OpenFlow
- Deteccion automatica de port scans y bloqueo en el plano de datos
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

CONTROLLER_IP   = '127.0.0.1'
CONTROLLER_PORT = 6633
REST_PORT       = 8080

SUBNET       = '10.0.0'
CLIENTE1_IP  = '%s.10'  % SUBNET
CLIENTE2_IP  = '%s.20'  % SUBNET
ATACANTE_IP  = '%s.30'  % SUBNET
SERVIDOR_IP  = '%s.100' % SUBNET

RYU_APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ryu_controller.py')
RYU_LOG = '/tmp/ryu_controller.log'
RYU_PID = '/tmp/ryu_controller.pid'


def start_ryu():
    """Inicia el controlador Ryu como proceso background en el host."""
    info('*** Iniciando controlador Ryu...\n')
    os.system('pkill -f ryu-manager 2>/dev/null; pkill -f ryu_controller 2>/dev/null')
    os.system('rm -f %s' % RYU_PID)
    time.sleep(1)

    cmd = (
        'ryu-manager --ofp-tcp-listen-port %d %s > %s 2>&1 &'
        % (CONTROLLER_PORT, RYU_APP, RYU_LOG)
    )
    os.system(cmd)

    for attempt in range(20):
        time.sleep(1)
        result = os.popen(
            'curl -s --max-time 1 http://127.0.0.1:%d/sdn/stats 2>/dev/null' % REST_PORT
        ).read().strip()
        if result:
            info('  [OK] Controlador Ryu activo (REST en :%d)\n' % REST_PORT)
            return True
        info('  Esperando controlador... (%d/20)\n' % (attempt + 1))

    info('  [WARN] Controlador puede no haber iniciado. Ver: tail -f %s\n' % RYU_LOG)
    return False


def createSDNTopology():
    """
    Topologia SDN con controlador Ryu:

    [cliente1] --+
    [cliente2] --+-- s1 (OVS OF1.3) --[Ryu Controller 127.0.0.1:6633]
    [atacante] --+
    [servidor] --+
    """

    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('pkill -f ryu-manager 2>/dev/null; pkill -f ryu_controller 2>/dev/null')
    time.sleep(1)

    start_ryu()

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    info('*** Registrando controlador remoto\n')
    net.addController('c0', controller=RemoteController,
                      ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    info('*** Creando hosts\n')
    cliente1 = net.addHost('cliente1', ip='%s/24' % CLIENTE1_IP,
                           mac='00:00:00:00:00:10')
    cliente2 = net.addHost('cliente2', ip='%s/24' % CLIENTE2_IP,
                           mac='00:00:00:00:00:20')
    atacante = net.addHost('atacante', ip='%s/24' % ATACANTE_IP,
                           mac='00:00:00:00:00:30')
    servidor = net.addHost('servidor', ip='%s/24' % SERVIDOR_IP,
                           mac='00:00:00:00:00:AA')

    info('*** Creando switch OpenFlow 1.3\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

    info('*** Creando enlaces\n')
    net.addLink(cliente1, s1)
    net.addLink(cliente2, s1)
    net.addLink(atacante, s1)
    net.addLink(servidor, s1)

    info('*** Iniciando red\n')
    net.start()
    time.sleep(3)

    info('*** Configurando escenario\n')
    configureScenario(cliente1, cliente2, atacante, servidor)

    info('*** Escenario listo\n')
    printWelcomeMessage()

    CLI(net)

    info('*** Deteniendo servicios\n')
    servidor.cmd('pkill -9 python3 2>/dev/null')
    servidor.cmd('pkill -9 nc 2>/dev/null')
    os.system('pkill -f ryu-manager 2>/dev/null')
    os.system('pkill -f ryu_controller 2>/dev/null')

    info('*** Deteniendo red\n')
    net.stop()


def configureScenario(cliente1, cliente2, atacante, servidor):
    """Levanta servicios en el servidor y copia scripts auxiliares."""

    info('  Levantando servicios en servidor (%s)...\n' % SERVIDOR_IP)

    servidor.cmd('mkdir -p /tmp/sdn_web')
    servidor.cmd(
        'printf "<h1>Servidor SDN</h1><p>Controlado por Ryu + OpenFlow 1.3</p>" '
        '> /tmp/sdn_web/index.html'
    )
    servidor.cmd(
        'cd /tmp/sdn_web && python3 -m http.server 80 > /tmp/servidor_http.log 2>&1 &'
    )

    for port in [21, 22, 8080]:
        servidor.cmd('while true; do nc -l -p %d 2>/dev/null; done &' % port)

    time.sleep(1)

    if servidor.cmd('pgrep -f "http.server"').strip():
        info('  [OK] HTTP activo en %s:80\n' % SERVIDOR_IP)
    else:
        info('  [WARN] HTTP no inicio\n')

    # Copiar scripts auxiliares
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for script in ('sdn_demo.py',):
        src = os.path.join(script_dir, script)
        if os.path.exists(src):
            os.system('cp %s /tmp/%s' % (src, script))
            info('  [OK] Script disponible: /tmp/%s\n' % script)


def printWelcomeMessage():
    REST = 'http://127.0.0.1:%d' % REST_PORT

    print('\n' + '='*75)
    print('  >>> ESCENARIO SDN - CONTROLADOR RYU + OPENFLOW 1.3 <<<')
    print('='*75)

    print('\n[TOPOLOGIA]:')
    print('    cliente1: %s  (usuario normal)' % CLIENTE1_IP)
    print('    cliente2: %s  (segundo usuario)' % CLIENTE2_IP)
    print('    atacante: %s  (host sospechoso)' % ATACANTE_IP)
    print('    servidor: %s (HTTP:80, FTP:21, SSH:22, 8080)' % SERVIDOR_IP)
    print('    switch:   s1 (OVS + OpenFlow 1.3) -> Ryu @ 127.0.0.1:%d' % CONTROLLER_PORT)

    print('\n[CONTROLADOR RYU]:')
    print('    OpenFlow: 127.0.0.1:%d' % CONTROLLER_PORT)
    print('    REST API: %s' % REST)
    print('    Logs:     tail -f %s' % RYU_LOG)

    print('\n[FASE 1 - VERIFICAR CONECTIVIDAD]:')
    print('    mininet> pingall')
    print('    mininet> cliente1 curl http://%s' % SERVIDOR_IP)
    print('    mininet> atacante  curl http://%s' % SERVIDOR_IP)

    print('\n[FASE 2 - VER ESTADO DEL CONTROLADOR (REST API)]:')
    print('    mininet> sh curl -s %s/sdn/topology  | python3 -m json.tool' % REST)
    print('    mininet> sh curl -s %s/sdn/stats     | python3 -m json.tool' % REST)
    print('    mininet> sh curl -s %s/sdn/firewall/rules | python3 -m json.tool' % REST)
    print('')
    print('    # Ver flujos OpenFlow instalados en el switch')
    print('    mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1')

    print('\n[FASE 3 - FIREWALL DINAMICO (bloquear flujo especifico)]:')
    print('    # Bloquear trafico del atacante al servidor puerto 80')
    print('    mininet> sh curl -s -X POST %s/sdn/firewall/rules \\' % REST)
    print("      -H 'Content-Type: application/json' \\")
    print('      -d \'{"src_ip":"%s","dst_ip":"%s","protocol":"tcp","dst_port":80,"action":"block"}\''
          % (ATACANTE_IP, SERVIDOR_IP))
    print('')
    print('    # Verificar bloqueo')
    print('    mininet> atacante curl http://%s     # debe fallar (bloqueado)' % SERVIDOR_IP)
    print('    mininet> cliente1 curl http://%s     # debe funcionar (no bloqueado)' % SERVIDOR_IP)
    print('')
    print('    # Ver reglas activas')
    print('    mininet> sh curl -s %s/sdn/firewall/rules | python3 -m json.tool' % REST)
    print('')
    print('    # Eliminar la regla (sustituir 1 por el ID recibido al crearla)')
    print('    mininet> sh curl -X DELETE %s/sdn/firewall/rules/1' % REST)

    print('\n[FASE 4 - BLOQUEO COMPLETO DE IP (regla DROP en plano de datos)]:')
    print('    # Bloquear todas las comunicaciones del atacante')
    print('    mininet> sh curl -X POST %s/sdn/block/%s' % (REST, ATACANTE_IP))
    print('')
    print('    # El switch instala una regla DROP prioridad 200')
    print('    mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200')
    print('')
    print('    # El atacante queda completamente aislado')
    print('    mininet> atacante ping -c3 %s     # debe fallar' % SERVIDOR_IP)
    print('    mininet> atacante curl http://%s  # debe fallar' % SERVIDOR_IP)
    print('')
    print('    # Desbloquear (elimina la regla DROP del switch)')
    print('    mininet> sh curl -X DELETE %s/sdn/block/%s' % (REST, ATACANTE_IP))

    print('\n[FASE 5 - DETECCION AUTOMATICA DE PORT SCAN]:')
    print('    # Asegurar que el atacante NO esta bloqueado')
    print('    mininet> sh curl -X DELETE %s/sdn/block/%s' % (REST, ATACANTE_IP))
    print('')
    print('    # Lanzar port scan desde el atacante')
    print('    mininet> atacante python3 /tmp/sdn_demo.py --mode portscan --target %s' % SERVIDOR_IP)
    print('    # O con nmap (si instalado):')
    print('    mininet> atacante nmap -sS --min-rate 50 %s' % SERVIDOR_IP)
    print('')
    print('    # El controlador detecta el scan y bloquea automaticamente')
    print('    mininet> sh tail -10 %s' % RYU_LOG)
    print('    mininet> sh curl -s %s/sdn/stats | python3 -m json.tool' % REST)

    print('\n[FASE 6 - ESTADISTICAS DE FLUJOS OPENFLOW]:')
    print('    # Generar trafico')
    print('    mininet> cliente1 ping -c5 %s' % SERVIDOR_IP)
    print('    mininet> cliente2 curl http://%s' % SERVIDOR_IP)
    print('')
    print('    # Ver estadisticas tras unos segundos')
    print('    mininet> sh curl -s %s/sdn/stats | python3 -m json.tool' % REST)
    print('    mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1')

    print('\n[FASE 7 - DEMO AUTOMATICA]:')
    print('    mininet> sh python3 /tmp/sdn_demo.py --mode demo')

    print('\n[DIAGNOSTICO]:')
    print('    mininet> sh ovs-vsctl show              # estado del switch OVS')
    print('    mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1  # flujos activos')
    print('    mininet> sh tail -f %s       # log controlador' % RYU_LOG)

    print('\n' + '='*75)
    print('  Escribe "exit" o presiona Ctrl+D para salir')
    print('='*75 + '\n')


if __name__ == '__main__':
    setLogLevel('info')
    createSDNTopology()
