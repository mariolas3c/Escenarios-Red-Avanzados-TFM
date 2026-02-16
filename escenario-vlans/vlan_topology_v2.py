#!/usr/bin/python
"""
Topología de Mininet con VLANs - VERSIÓN CORREGIDA CON AISLAMIENTO REAL
- 3 VLANs diferentes (VLAN 10, 20, 30) CON AISLAMIENTO COMPLETO
- Servidor DHCP en VLAN 10
- Demostración de dominios de broadcast separados
- Configuración mejorada y verificada de VLANs
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

def createVLANTopology():
    """
    Topología con AISLAMIENTO REAL entre VLANs
    """
    
    # Limpiar procesos previos
    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('sudo pkill -9 dnsmasq 2>/dev/null')
    
    # Crear red con switches OVS en modo standalone (sin controlador OpenFlow)
    # Esto permite que las VLANs funcionen correctamente
    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)
    
    info('*** Creando switches (modo standalone para VLANs)\n')
    # Switches sin controlador - modo learning switch con VLANs
    s1 = net.addSwitch('s1', failMode='standalone')
    s2 = net.addSwitch('s2', failMode='standalone')
    s3 = net.addSwitch('s3', failMode='standalone')
    s4 = net.addSwitch('s4', failMode='standalone')
    
    info('*** Creando hosts\n')
    # VLAN 10 - Management (10.0.10.0/24)
    h1 = net.addHost('h1', ip='10.0.10.10/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.10.20/24', mac='00:00:00:00:00:02')
    dhcp_server = net.addHost('dhcp', ip='10.0.10.1/24', mac='00:00:00:00:00:03')
    
    # VLAN 20 - Departamento A (10.0.20.0/24)
    h3 = net.addHost('h3', ip='10.0.20.10/24', mac='00:00:00:00:00:04')
    h4 = net.addHost('h4', ip='10.0.20.20/24', mac='00:00:00:00:00:05')
    
    # VLAN 30 - Departamento B (10.0.30.0/24)
    h5 = net.addHost('h5', ip='10.0.30.10/24', mac='00:00:00:00:00:06')
    h6 = net.addHost('h6', ip='10.0.30.20/24', mac='00:00:00:00:00:07')
    
    info('*** Creando enlaces\n')
    # Enlaces trunk entre switches (permiten múltiples VLANs)
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s1, s4)
    
    # Enlaces de acceso (un solo VLAN por puerto)
    # VLAN 10
    net.addLink(h1, s2)
    net.addLink(h2, s2)
    net.addLink(dhcp_server, s2)
    
    # VLAN 20
    net.addLink(h3, s3)
    net.addLink(h4, s3)
    
    # VLAN 30
    net.addLink(h5, s4)
    net.addLink(h6, s4)
    
    info('*** Iniciando red\n')
    net.start()
    
    # Esperar a que los switches estén listos
    time.sleep(2)
    
    info('*** Configurando VLANs con OVS\n')
    configureVLANs(s1, s2, s3, s4)
    
    # Verificar configuración
    info('*** Verificando configuracion de VLANs\n')
    verifyVLANConfig(s1, s2, s3, s4)
    
    info('*** Configurando servidor DHCP\n')
    configureDHCPServer(dhcp_server)
    
    info('*** Red iniciada con aislamiento VLAN\n')
    
    CLI(net)
    
    info('*** Deteniendo servidor DHCP\n')
    dhcp_server.cmd('pkill -9 dnsmasq 2>/dev/null')
    
    info('*** Deteniendo red\n')
    net.stop()

def configureVLANs(s1, s2, s3, s4):
    """
    Configura VLANs usando Open vSwitch de forma correcta
    IMPORTANTE: Usa 'trunks' para puertos trunk (múltiples VLANs)
                Usa 'tag' para puertos access (una sola VLAN)
    """
    
    info('  === Configurando Switch s1 (TRUNK) ===\n')
    # s1 es el switch central - todos sus puertos son TRUNK
    # Los puertos trunk deben usar 'trunks' NO 'tag'
    s1.cmd('ovs-vsctl set port s1-eth1 trunks=10,20,30')  # a s2
    s1.cmd('ovs-vsctl set port s1-eth2 trunks=10,20,30')  # a s3
    s1.cmd('ovs-vsctl set port s1-eth3 trunks=10,20,30')  # a s4
    info('    [OK] s1-eth1, s1-eth2, s1-eth3 configurados como TRUNK [10,20,30]\n')
    
    info('  === Configurando Switch s2 (ACCESS - VLAN 10) ===\n')
    # s2: puerto 1 es trunk (hacia s1), el resto son access VLAN 10
    s2.cmd('ovs-vsctl set port s2-eth1 trunks=10,20,30')  # trunk a s1
    s2.cmd('ovs-vsctl set port s2-eth2 tag=10')  # access h1
    s2.cmd('ovs-vsctl set port s2-eth3 tag=10')  # access h2
    s2.cmd('ovs-vsctl set port s2-eth4 tag=10')  # access dhcp
    info('    [OK] s2-eth1: TRUNK, s2-eth2/3/4: ACCESS VLAN 10\n')
    
    info('  === Configurando Switch s3 (ACCESS - VLAN 20) ===\n')
    # s3: puerto 1 es trunk (hacia s1), el resto son access VLAN 20
    s3.cmd('ovs-vsctl set port s3-eth1 trunks=10,20,30')  # trunk a s1
    s3.cmd('ovs-vsctl set port s3-eth2 tag=20')  # access h3
    s3.cmd('ovs-vsctl set port s3-eth3 tag=20')  # access h4
    info('    [OK] s3-eth1: TRUNK, s3-eth2/3: ACCESS VLAN 20\n')
    
    info('  === Configurando Switch s4 (ACCESS - VLAN 30) ===\n')
    # s4: puerto 1 es trunk (hacia s1), el resto son access VLAN 30
    s4.cmd('ovs-vsctl set port s4-eth1 trunks=10,20,30')  # trunk a s1
    s4.cmd('ovs-vsctl set port s4-eth2 tag=30')  # access h5
    s4.cmd('ovs-vsctl set port s4-eth3 tag=30')  # access h6
    info('    [OK] s4-eth1: TRUNK, s4-eth2/3: ACCESS VLAN 30\n')
    
    # Limpiar MAC learning tables para asegurar que las VLANs funcionen
    info('  === Limpiando tablas MAC ===\n')
    for switch in [s1, s2, s3, s4]:
        switch.cmd('ovs-ofctl del-flows ' + switch.name)
    
    time.sleep(1)

def verifyVLANConfig(s1, s2, s3, s4):
    """
    Verifica que la configuración de VLANs sea correcta
    """
    info('  Verificando configuracion...\n')
    
    # Verificar s2 (VLAN 10)
    tag_s2_eth2 = s2.cmd('ovs-vsctl get port s2-eth2 tag').strip()
    tag_s2_eth3 = s2.cmd('ovs-vsctl get port s2-eth3 tag').strip()
    
    if tag_s2_eth2 == '10' and tag_s2_eth3 == '10':
        info('  [OK] s2 correctamente configurado en VLAN 10\n')
    else:
        info('  [ERROR] s2 no esta correctamente configurado\n')
    
    # Verificar s3 (VLAN 20)
    tag_s3_eth2 = s3.cmd('ovs-vsctl get port s3-eth2 tag').strip()
    
    if tag_s3_eth2 == '20':
        info('  [OK] s3 correctamente configurado en VLAN 20\n')
    else:
        info('  [ERROR] s3 no esta correctamente configurado\n')
    
    # Verificar s4 (VLAN 30)
    tag_s4_eth2 = s4.cmd('ovs-vsctl get port s4-eth2 tag').strip()
    
    if tag_s4_eth2 == '30':
        info('  [OK] s4 correctamente configurado en VLAN 30\n')
    else:
        info('  [ERROR] s4 no esta correctamente configurado\n')

def configureDHCPServer(dhcp_server):
    """
    Configura servidor DHCP sin conflictos de puerto
    """
    info('  Configurando dnsmasq (solo DHCP)\n')
    
    dhcp_config = """port=0
interface=dhcp-eth0
dhcp-range=10.0.10.50,10.0.10.100,255.255.255.0,12h
dhcp-option=3,10.0.10.1
dhcp-option=6,8.8.8.8
log-dhcp
"""
    
    dhcp_server.cmd('echo "%s" > /tmp/dnsmasq_vlan.conf' % dhcp_config)
    dhcp_server.cmd('pkill -9 dnsmasq 2>/dev/null')
    dhcp_server.cmd('dnsmasq --conf-file=/tmp/dnsmasq_vlan.conf --log-facility=/tmp/dnsmasq.log &')
    
    time.sleep(1)
    result = dhcp_server.cmd('pgrep dnsmasq')
    
    if result.strip():
        info('  [OK] Servidor DHCP activo en 10.0.10.1 (Rango: 10.0.10.50-100)\n')
    else:
        info('  [ERROR] ERROR al iniciar DHCP\n')

if __name__ == '__main__':
    setLogLevel('info')
    createVLANTopology()
