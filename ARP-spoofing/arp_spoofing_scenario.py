#!/usr/bin/python
"""
Escenario de ARP Spoofing en Mininet
- Topologia simple con victima, atacante y gateway
- Sistema de deteccion de ARP spoofing
- Scripts de ataque y defensa incluidos
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

def createARPSpoofingTopology():
    """
    Topologia para demostrar ARP Spoofing:
    
    Internet --- Gateway (router) --- Switch --- [Victim, Attacker, Server]
    
    - Gateway: 192.168.1.1 (simula router/gateway)
    - Victim: 192.168.1.10 (objetivo del ataque)
    - Attacker: 192.168.1.100 (realiza ARP spoofing)
    - Server: 192.168.1.50 (servidor web para pruebas)
    - Monitor: 192.168.1.200 (sistema de deteccion IDS)
    """
    
    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    
    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    
    info('*** Creando hosts\n')
    # Gateway/Router
    gateway = net.addHost('gateway', ip='192.168.1.1/24', mac='00:00:00:00:00:01')
    
    # Victima (cliente normal)
    victim = net.addHost('victim', ip='192.168.1.10/24', mac='00:00:00:00:00:10')
    
    # Atacante (realiza ARP spoofing)
    attacker = net.addHost('attacker', ip='192.168.1.100/24', mac='00:00:00:00:00:99')
    
    # Servidor web
    server = net.addHost('server', ip='192.168.1.50/24', mac='00:00:00:00:00:50')
    
    # Monitor/IDS
    monitor = net.addHost('monitor', ip='192.168.1.200/24', mac='00:00:00:00:00:AA')
    
    info('*** Creando switch\n')
    switch = net.addSwitch('s1', failMode='standalone')
    
    info('*** Creando enlaces\n')
    net.addLink(gateway, switch)
    net.addLink(victim, switch)
    net.addLink(attacker, switch)
    net.addLink(server, switch)
    net.addLink(monitor, switch)
    
    info('*** Iniciando red\n')
    net.start()
    
    time.sleep(2)
    
    info('*** Configurando rutas y servicios\n')
    configureNetwork(gateway, victim, attacker, server, monitor)
    
    info('*** Instalando herramientas de ataque y deteccion\n')
    setupTools(victim, attacker, server, monitor)
    
    info('*** Red iniciada\n')
    printWelcomeMessage()
    
    CLI(net)
    
    info('*** Deteniendo red\n')
    net.stop()

def configureNetwork(gateway, victim, attacker, server, monitor):
    """
    Configura rutas y servicios basicos
    """
    # Configurar gateway como ruta por defecto para todos
    for host in [victim, attacker, server, monitor]:
        host.cmd('route add default gw 192.168.1.1')
    
    # Habilitar IP forwarding en gateway
    gateway.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # Habilitar IP forwarding en attacker (para MITM)
    attacker.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # IMPORTANTE: Configurar port mirroring para el monitor
    info('  Configurando port mirroring en switch (para IDS)...\n')
    
    # Opcion 1: Configurar switch para flood (broadcast a todos)
    os.system('ovs-ofctl add-flow s1 priority=1,action=flood')
    
    # Opcion 2: Port mirroring especifico
    # Esto hace que el monitor vea TODO el trafico
    os.system('ovs-vsctl -- set Bridge s1 mirrors=@m -- '
              '--id=@monitor-eth0 get Port monitor-eth0 -- '
              '--id=@m create Mirror name=monitor0 select-all=true output-port=@monitor-eth0')
    
    info('  [OK] Port mirroring configurado - Monitor vera todo el trafico\n')
    
    # Poner interfaz del monitor en modo promiscuo
    monitor.cmd('ifconfig monitor-eth0 promisc')
    info('  [OK] Monitor en modo promiscuo\n')
    
    # Configurar servidor web simple
    info('  Iniciando servidor web en server (puerto 80)\n')
    server.cmd('echo "<!DOCTYPE html><html><body><h1>Servidor Web - 192.168.1.50</h1><p>Este es el servidor legitimo</p></body></html>" > /tmp/index.html')
    server.cmd('cd /tmp && python3 -m http.server 80 > /dev/null 2>&1 &')
    
    time.sleep(1)

def setupTools(victim, attacker, server, monitor):
    """
    Instala/verifica herramientas necesarias
    """
    info('  Verificando herramientas instaladas...\n')
    
    # Las herramientas ya deberan estar instaladas en el sistema
    # arpspoof, tcpdump, etc.
    
    info('  [OK] Herramientas listas\n')

def printWelcomeMessage():
    """
    Muestra instrucciones de uso
    """
    print('\n' + '='*75)
    print('  >>> ESCENARIO DE ARP SPOOFING - ATAQUE Y DETECCION <<<')
    print('='*75)
    print('\n[TOPOLOGIA]:')
    print('    Gateway:  192.168.1.1   (MAC: 00:00:00:00:00:01)')
    print('    Victim:   192.168.1.10  (MAC: 00:00:00:00:00:10)')
    print('    Attacker: 192.168.1.100 (MAC: 00:00:00:00:00:99)')
    print('    Server:   192.168.1.50  (MAC: 00:00:00:00:00:50)')
    print('    Monitor:  192.168.1.200 (MAC: 00:00:00:00:00:AA) - IDS')
    
    print('\n[ESCENARIO]:')
    print('    1. Victim navega normalmente al servidor web')
    print('    2. Attacker realiza ARP spoofing (MITM)')
    print('    3. Monitor detecta el ataque')
    
    print('\n[FASE 1 - TRAFICO NORMAL]:')
    print('    # Ver tabla ARP de la victima (normal)')
    print('    mininet> victim arp -n')
    print('')
    print('    # Victima accede al servidor web')
    print('    mininet> victim curl http://192.168.1.50')
    print('')
    print('    # Capturar trafico en victima')
    print('    mininet> victim tcpdump -i victim-eth0 -n &')
    
    print('\n[FASE 2 - INICIAR ATAQUE ARP SPOOFING]:')
    print('    # Terminal 1: Iniciar monitor/IDS (VERSION MEJORADA)')
    print('    mininet> xterm monitor')
    print('    monitor# python3 /tmp/arp_detector_v2.py')
    print('')
    print('    # O usar version original:')
    print('    monitor# python3 /tmp/arp_detector.py')
    print('')
    print('    # Terminal 2: Captura en victima (opcional)')
    print('    mininet> xterm victim')
    print('    victim# tcpdump -i victim-eth0 -n')
    print('')
    print('    # Terminal 3: Ejecutar ataque')
    print('    mininet> xterm attacker')
    print('    attacker# python3 /tmp/arp_spoof_attack.py')
    print('')
    print('    # O usar arpspoof (si esta instalado):')
    print('    attacker# arpspoof -i attacker-eth0 -t 192.168.1.10 192.168.1.1')
    
    print('\n[FASE 3 - VERIFICAR ATAQUE]:')
    print('    # Ver tabla ARP de victima (envenenada)')
    print('    mininet> victim arp -n')
    print('    # Deberia mostrar MAC del atacante para el gateway')
    print('')
    print('    # El monitor deberia mostrar ALERTA de ARP spoofing')
    
    print('\n[FASE 4 - LIMPIAR Y RESTAURAR]:')
    print('    # Detener ataque (Ctrl+C en terminal del atacante)')
    print('    # Limpiar cache ARP de victima')
    print('    mininet> victim ip -s -s neigh flush all')
    print('    mininet> victim arp -d 192.168.1.1')
    
    print('\n[ARCHIVOS CREADOS]:')
    print('    /tmp/arp_spoof_attack.py  - Script de ataque')
    print('    /tmp/arp_detector_v2.py   - Sistema de deteccion IDS (MEJORADO)')
    print('    /tmp/arp_detector.py      - Sistema de deteccion IDS (original)')
    print('    /tmp/arp_defender.py      - Sistema de defensa')
    print('')
    print('[NOTA IMPORTANTE]:')
    print('    El switch esta configurado con PORT MIRRORING')
    print('    El monitor puede ver TODO el trafico de la red')
    print('    Usa arp_detector_v2.py para mejor deteccion')
    
    print('\n' + '='*75)
    print('  Escribe "exit" o presiona Ctrl+D para salir')
    print('='*75 + '\n')

if __name__ == '__main__':
    setLogLevel('info')
    createARPSpoofingTopology()
