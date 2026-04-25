#!/usr/bin/python
"""
Escenario de Escaneo de Puertos + Suricata IDS en Mininet
- Topologia con victima, atacante y monitor IDS
- Suricata detecta escaneos SYN, FIN, XMAS, NULL y UDP
- Scripts de ataque incluidos (Scapy + nmap)
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time

SUBNET = "10.0.1"
VICTIM_IP   = "%s.10" % SUBNET
ATTACKER_IP = "%s.20" % SUBNET
MONITOR_IP  = "%s.100" % SUBNET

SURICATA_RULES = "/tmp/suricata_portscan.rules"
SURICATA_LOGS  = "/tmp/suricata-logs"
SURICATA_CONF  = "/tmp/suricata_min.yaml"
ATTACK_SCRIPT  = "/tmp/port_scan_attack.py"

def createPortScanTopology():
    """
    Topologia para demostrar escaneo de puertos + deteccion con Suricata:

    [Attacker] --+
    [Victim]   --+-- Switch -- [Monitor/Suricata IDS]

    - Victim:   10.0.1.10  (servicios abiertos: HTTP, SSH, FTP, Telnet...)
    - Attacker: 10.0.1.20  (realiza escaneos de puertos)
    - Monitor:  10.0.1.100 (Suricata IDS via port mirroring)
    """

    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('sudo pkill -9 suricata 2>/dev/null')
    os.system('sudo pkill -9 "nc " 2>/dev/null')
    os.system('rm -f /tmp/suricata.pid')

    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)

    info('*** Creando hosts\n')
    victim   = net.addHost('victim',   ip='%s/24' % VICTIM_IP,   mac='00:00:00:01:00:10')
    attacker = net.addHost('attacker', ip='%s/24' % ATTACKER_IP, mac='00:00:00:01:00:20')
    monitor  = net.addHost('monitor',  ip='%s/24' % MONITOR_IP,  mac='00:00:00:01:00:AA')

    info('*** Creando switch\n')
    switch = net.addSwitch('s1', failMode='standalone')

    info('*** Creando enlaces\n')
    net.addLink(victim,   switch)
    net.addLink(attacker, switch)
    net.addLink(monitor,  switch)

    info('*** Iniciando red\n')
    net.start()
    time.sleep(2)

    info('*** Configurando escenario\n')
    configureScenario(victim, attacker, monitor, switch)

    info('*** Escenario listo\n')
    printWelcomeMessage()

    CLI(net)

    info('*** Deteniendo servicios\n')
    victim.cmd('pkill -9 python3 2>/dev/null')
    victim.cmd('pkill -9 nc 2>/dev/null')
    monitor.cmd('pkill -9 suricata 2>/dev/null')

    info('*** Deteniendo red\n')
    net.stop()


def configureScenario(victim, attacker, monitor, switch):
    """
    1. Levanta servicios en la victima (puertos abiertos/filtrados)
    2. Configura port mirroring hacia el monitor
    3. Escribe reglas Suricata y configuracion minima
    4. Inicia Suricata en el monitor
    5. Copia el script de ataque al atacante
    """

    # --- Servicios en la victima ---
    info('  Levantando servicios en la victima (%s)...\n' % VICTIM_IP)

    # HTTP en puerto 80
    victim.cmd('mkdir -p /tmp/victim_web')
    victim.cmd('echo "<h1>Servidor Victima</h1>" > /tmp/victim_web/index.html')
    victim.cmd('cd /tmp/victim_web && python3 -m http.server 80 > /tmp/victim_http.log 2>&1 &')

    # Puertos abiertos simulados con netcat (SSH=22, FTP=21, Telnet=23, SMTP=25, MySQL=3306)
    for port in [21, 22, 23, 25, 3306, 8080]:
        victim.cmd('while true; do nc -l -p %d 2>/dev/null; done &' % port)

    time.sleep(1)

    # Verificar servicios
    http_pid = victim.cmd('pgrep -f "http.server"').strip()
    if http_pid:
        info('  [OK] HTTP activo en %s:80\n' % VICTIM_IP)
    else:
        info('  [WARN] HTTP no inicio correctamente\n')

    # --- Port mirroring hacia el monitor ---
    info('  Configurando port mirroring hacia el monitor...\n')

    # Obtener el nombre del puerto del switch (s1-ethX) que conecta al monitor
    monitor_sw_intf = None
    for intf in switch.intfList():
        if intf.link:
            n1 = intf.link.intf1.node
            n2 = intf.link.intf2.node
            if monitor in (n1, n2) and switch in (n1, n2):
                monitor_sw_intf = (intf.link.intf1 if intf.link.intf1.node == switch
                                   else intf.link.intf2).name
                break
    if not monitor_sw_intf:
        info('  [WARN] No se encontro el puerto del switch para monitor, usando s1-eth3\n')
        monitor_sw_intf = 's1-eth3'
    info('  Puerto OVS del monitor: %s\n' % monitor_sw_intf)

    os.system('ovs-ofctl add-flow s1 priority=1,action=flood')
    os.system(
        'ovs-vsctl -- set Bridge s1 mirrors=@m '
        '-- --id=@mon get Port %(port)s '
        '-- --id=@m create Mirror name=scan_mirror select-all=true output-port=@mon'
        % {'port': monitor_sw_intf}
    )
    monitor.cmd('ifconfig monitor-eth0 promisc')
    info('  [OK] Port mirroring activo\n')

    # --- Reglas Suricata ---
    info('  Escribiendo reglas Suricata en %s...\n' % SURICATA_RULES)
    rules = (
        '# Reglas de deteccion de escaneo de puertos\n'
        '\n'
        '# SYN Scan (nmap -sS): muchos SYN sin completar handshake\n'
        'alert tcp any any -> $HOME_NET any ('
        'msg:"SCAN SYN Port Scan Detectado"; '
        'flags:S,FSRPAU; '
        'flow:to_server; '
        'threshold:type threshold, track by_src, count 5, seconds 10; '
        'classtype:attempted-recon; sid:1000001; rev:3;)\n'
        '\n'
        '# NULL Scan: paquete TCP sin flags\n'
        'alert tcp any any -> $HOME_NET any ('
        'msg:"SCAN NULL Scan Detectado"; '
        'flags:0,FSRPAU; '
        'classtype:attempted-recon; sid:1000002; rev:2;)\n'
        '\n'
        '# FIN Scan: solo flag FIN\n'
        'alert tcp any any -> $HOME_NET any ('
        'msg:"SCAN FIN Scan Detectado"; '
        'flags:F,FSRPAU; '
        'classtype:attempted-recon; sid:1000003; rev:2;)\n'
        '\n'
        '# XMAS Scan: FIN+PSH+URG\n'
        'alert tcp any any -> $HOME_NET any ('
        'msg:"SCAN XMAS Scan Detectado"; '
        'flags:FPU,FSRPAU; '
        'classtype:attempted-recon; sid:1000004; rev:2;)\n'
        '\n'
        '# ACK Scan: solo flag ACK (mapeo de firewall)\n'
        'alert tcp any any -> $HOME_NET any ('
        'msg:"SCAN ACK Scan Detectado"; '
        'flags:A,FSRPAU; '
        'flow:to_server; '
        'threshold:type threshold, track by_src, count 5, seconds 10; '
        'classtype:attempted-recon; sid:1000005; rev:3;)\n'
        '\n'
        '# Barrido UDP (muchos paquetes UDP a distintos puertos)\n'
        'alert udp any any -> $HOME_NET any ('
        'msg:"SCAN UDP Port Scan Detectado"; '
        'flow:to_server; '
        'threshold:type threshold, track by_src, count 5, seconds 10; '
        'classtype:attempted-recon; sid:1000006; rev:2;)\n'
        '\n'
        '# Deteccion de nmap (User-Agent tipico en HTTP)\n'
        'alert tcp any any -> $HOME_NET 80 ('
        'msg:"SCAN nmap HTTP User-Agent Detectado"; '
        'content:"Nmap Scripting Engine"; http_header; nocase; '
        'classtype:attempted-recon; sid:1000007; rev:1;)\n'
        '\n'
        '# Conexiones a muchos puertos (TCP Connect scan, nmap -sT): mas rapido que Scapy\n'
        'alert tcp any any -> $HOME_NET any ('
        'msg:"SCAN TCP Connect Scan Detectado"; '
        'flags:S,FSRPAU; '
        'flow:to_server; '
        'threshold:type threshold, track by_src, count 20, seconds 5; '
        'classtype:attempted-recon; sid:1000008; rev:2;)\n'
    )
    os.makedirs(SURICATA_LOGS, exist_ok=True)
    with open(SURICATA_RULES, 'w') as f:
        f.write(rules)

    # --- Configuracion minima de Suricata ---
    info('  Escribiendo configuracion Suricata en %s...\n' % SURICATA_CONF)
    suricata_yaml = """%%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[%(subnet)s.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS:  "$HOME_NET"
    DNS_SERVERS:  "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS:  "$EXTERNAL_NET"
    DNP3_SERVER:  "$HOME_NET"
    DNP3_CLIENT:  "any"
    MODBUS_CLIENT: "any"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT:  "any"
    ENIP_SERVER:  "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: %(logs)s

stats:
  enabled: no

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: no

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: notice
        filename: suricata.log

af-packet:
  - interface: monitor-eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    checksum-checks: no

defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

flow:
  memcap: 32mb
  hash-size: 65536
  prealloc: 1000
  emergency-recovery: 30
  prune-flows: 5

stream:
  memcap: 32mb
  checksum-validation: no
  inline: no
  reassembly:
    memcap: 64mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

host:
  hash-size: 4096
  prealloc: 1000
  memcap: 8mb

app-layer:
  protocols:
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    tls:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

rule-files:
  - %(rules)s
""" % {
        'subnet': SUBNET,
        'logs':   SURICATA_LOGS,
        'rules':  SURICATA_RULES,
    }
    # Escribir el yaml directamente con Python
    with open(SURICATA_CONF, 'w') as f:
        f.write(suricata_yaml)

    # --- Iniciar Suricata ---
    info('  Comprobando si Suricata esta instalado...\n')
    suricata_bin = monitor.cmd('which suricata').strip()
    if not suricata_bin:
        info('  [ERROR] Suricata no encontrado. Ejecuta primero: ./setup_portscan_scenario.sh\n')
    else:
        info('  [OK] Suricata encontrado en: %s\n' % suricata_bin)
        info('  Iniciando Suricata en monitor (%s)...\n' % MONITOR_IP)
        monitor.cmd(
            'suricata -c %(conf)s --af-packet=monitor-eth0 '
            '-l %(logs)s -D --pidfile /tmp/suricata.pid '
            '> %(logs)s/suricata_init.log 2>&1' % {
                'conf': SURICATA_CONF,
                'logs': SURICATA_LOGS,
            }
        )
        time.sleep(3)
        pid = monitor.cmd('cat /tmp/suricata.pid 2>/dev/null').strip()
        if pid:
            info('  [OK] Suricata iniciado (PID: %s)\n' % pid)
            info('  [INFO] Alertas en: %s/fast.log\n' % SURICATA_LOGS)
            info('  [INFO] EVE JSON en: %s/eve.json\n' % SURICATA_LOGS)
        else:
            info('  [WARN] Suricata puede no haber iniciado. Revisa: %s/suricata_init.log\n' % SURICATA_LOGS)

    # --- Copiar script de ataque ---
    info('  Copiando script de ataque al atacante...\n')
    script_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'port_scan_attack.py')
    if os.path.exists(script_src):
        attacker.cmd('cp %s %s' % (script_src, ATTACK_SCRIPT))
        attacker.cmd('chmod +x %s' % ATTACK_SCRIPT)
        info('  [OK] Script de ataque disponible en %s\n' % ATTACK_SCRIPT)
    else:
        info('  [WARN] No se encontro port_scan_attack.py junto al escenario\n')

    time.sleep(1)


def printWelcomeMessage():
    print('\n' + '='*75)
    print('  >>> ESCENARIO DE ESCANEO DE PUERTOS + SURICATA IDS <<<')
    print('='*75)

    print('\n[TOPOLOGIA]:')
    print('    Victim:   %s  (servicios: HTTP:80, SSH:22, FTP:21, Telnet:23, SMTP:25, MySQL:3306)' % VICTIM_IP)
    print('    Attacker: %s  (realiza escaneos de puertos)' % ATTACKER_IP)
    print('    Monitor:  %s (Suricata IDS via port mirroring)' % MONITOR_IP)

    print('\n[LOGS SURICATA]:')
    print('    Alertas rapidas:  %s/fast.log' % SURICATA_LOGS)
    print('    EVE JSON:         %s/eve.json' % SURICATA_LOGS)
    print('    Log inicio:       %s/suricata_init.log' % SURICATA_LOGS)

    print('\n[FASE 1 - VERIFICAR CONECTIVIDAD]:')
    print('    mininet> victim ping -c2 %s' % ATTACKER_IP)
    print('    mininet> attacker curl http://%s' % VICTIM_IP)

    print('\n[FASE 2 - MONITOREAR ALERTAS SURICATA]:')
    print('    mininet> monitor tail -f %s/fast.log' % SURICATA_LOGS)
    print('    # O en tiempo real con formato JSON:')
    print('    mininet> monitor tail -f %s/eve.json | python3 -m json.tool' % SURICATA_LOGS)

    print('\n[FASE 3 - EJECUTAR ESCANEOS DESDE ATACANTE]:')
    print('')
    print('    # === USANDO SCRIPT SCAPY (no requiere nmap) ===')
    print('    mininet> attacker python3 %s --target %s --scan syn' % (ATTACK_SCRIPT, VICTIM_IP))
    print('    mininet> attacker python3 %s --target %s --scan fin' % (ATTACK_SCRIPT, VICTIM_IP))
    print('    mininet> attacker python3 %s --target %s --scan xmas' % (ATTACK_SCRIPT, VICTIM_IP))
    print('    mininet> attacker python3 %s --target %s --scan null' % (ATTACK_SCRIPT, VICTIM_IP))
    print('    mininet> attacker python3 %s --target %s --scan ack' % (ATTACK_SCRIPT, VICTIM_IP))
    print('    mininet> attacker python3 %s --target %s --scan udp' % (ATTACK_SCRIPT, VICTIM_IP))
    print('    mininet> attacker python3 %s --target %s --scan all' % (ATTACK_SCRIPT, VICTIM_IP))
    print('')
    print('    # === USANDO NMAP (si esta instalado) ===')
    print('    mininet> attacker nmap -sS %s          # SYN Scan (stealth)' % VICTIM_IP)
    print('    mininet> attacker nmap -sT %s          # TCP Connect Scan' % VICTIM_IP)
    print('    mininet> attacker nmap -sF %s          # FIN Scan' % VICTIM_IP)
    print('    mininet> attacker nmap -sX %s          # XMAS Scan' % VICTIM_IP)
    print('    mininet> attacker nmap -sN %s          # NULL Scan' % VICTIM_IP)
    print('    mininet> attacker nmap -sA %s          # ACK Scan' % VICTIM_IP)
    print('    mininet> attacker nmap -sU --top-ports 20 %s  # UDP Scan' % VICTIM_IP)
    print('    mininet> attacker nmap -A %s           # Scan agresivo (OS + Version + Scripts)' % VICTIM_IP)

    print('\n[FASE 4 - VERIFICAR DETECCION]:')
    print('    mininet> monitor cat %s/fast.log' % SURICATA_LOGS)
    print('    mininet> monitor grep "SCAN" %s/fast.log | wc -l' % SURICATA_LOGS)
    print('    mininet> monitor python3 -c "')
    print('      import json, sys')
    print('      for line in open(\'%s/eve.json\'):" ' % SURICATA_LOGS)
    print('        try: e=json.loads(line); print(e[\'alert\'][\'signature\']) if e.get(\'event_type\')==\'alert\' else None')
    print('        except: pass')

    print('\n[FASE 5 - ANALISIS MANUAL]:')
    print('    # Ver estado de Suricata')
    print('    mininet> monitor cat /tmp/suricata.pid')
    print('    mininet> monitor kill -USR2 $(cat /tmp/suricata.pid)  # Dump stats')
    print('')
    print('    # Verificar puertos abiertos en la victima')
    print('    mininet> victim ss -tlnp')
    print('    mininet> victim ss -ulnp')
    print('')
    print('    # Captura de trafico en monitor')
    print('    mininet> monitor tcpdump -i monitor-eth0 -n tcp and host %s -c 50' % ATTACKER_IP)

    print('\n[TIPOS DE ESCANEO DETECTADOS POR SURICATA]:')
    print('    SID 1000001 - SYN Scan       (nmap -sS, muchos SYN sin completar)')
    print('    SID 1000002 - NULL Scan       (nmap -sN, TCP sin flags)')
    print('    SID 1000003 - FIN Scan        (nmap -sF, solo flag FIN)')
    print('    SID 1000004 - XMAS Scan       (nmap -sX, FIN+PSH+URG)')
    print('    SID 1000005 - ACK Scan        (nmap -sA, mapeo de firewall)')
    print('    SID 1000006 - UDP Scan        (nmap -sU)')
    print('    SID 1000007 - nmap HTTP NSE   (User-Agent Nmap en HTTP)')
    print('    SID 1000008 - Connect Scan    (nmap -sT, muchos SYN completos)')

    print('\n' + '='*75)
    print('  Escribe "exit" o presiona Ctrl+D para salir')
    print('='*75 + '\n')


if __name__ == '__main__':
    setLogLevel('info')
    createPortScanTopology()
