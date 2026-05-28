#!/usr/bin/python
"""
Escenario de BGP Hijacking multi-AS en Mininet
- Topologia con 4 sistemas autonomos (AS65001 victima, AS65002 transito,
  AS65003 atacante, AS65004 cliente) interconectados por un IXP.
- Cada router corre zebra + bgpd (FRR) en su propio namespace Mininet.
- Demuestra dos variantes de hijack: prefijo identico y sub-prefix (more-specific).
- Monitor pasivo en el IXP via port mirroring para inspeccion BGP con tshark.
"""

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import re
import subprocess
import time


# --- Localizacion de binarios FRR ---
def find_frr_binary(name):
    """FRR en Ubuntu/Debian instala los daemons en /usr/lib/frr/, fuera del PATH."""
    candidates = [
        '/usr/lib/frr/%s' % name,
        '/usr/sbin/%s' % name,
        '/usr/bin/%s' % name,
    ]
    for path in candidates:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    # Fallback: confiar en PATH
    return name


ZEBRA_BIN = find_frr_binary('zebra')
BGPD_BIN  = find_frr_binary('bgpd')


def get_frr_version():
    """Devuelve (major, minor) leyendo `bgpd --version`. (0,0) si falla."""
    try:
        out = subprocess.check_output([BGPD_BIN, '--version'],
                                      stderr=subprocess.STDOUT, timeout=5).decode()
        m = re.search(r'(\d+)\.(\d+)', out)
        if m:
            return (int(m.group(1)), int(m.group(2)))
    except Exception:
        pass
    return (0, 0)


FRR_VERSION = get_frr_version()
# `no bgp ebgp-requires-policy` solo existe a partir de FRR 7.4
EBGP_POLICY_TUNABLE = FRR_VERSION >= (7, 4)

# --- Numeros de AS ---
AS_VICTIMA   = 65001
AS_TRANSITO  = 65002
AS_ATACANTE  = 65003
AS_CLIENTE   = 65004

# --- Subred IXP (CGNAT, no choca con otros escenarios) ---
IXP_SUBNET   = '100.64.0'
R1_IXP_IP    = '%s.1'  % IXP_SUBNET
R2_IXP_IP    = '%s.2'  % IXP_SUBNET
R3_IXP_IP    = '%s.3'  % IXP_SUBNET
R4_IXP_IP    = '%s.4'  % IXP_SUBNET
MONITOR_IP   = '%s.100' % IXP_SUBNET

# --- Subredes cliente por AS ---
VICTIMA_SUBNET    = '10.0.10'
ATACANTE_SUBNET   = '10.0.30'
CLIENTE_SUBNET    = '10.0.40'

R1_LAN_IP         = '%s.1'  % VICTIMA_SUBNET
H_VICTIMA_IP      = '%s.10' % VICTIMA_SUBNET
R3_LAN_IP         = '%s.1'  % ATACANTE_SUBNET
H_ATACANTE_IP     = '%s.10' % ATACANTE_SUBNET
R4_LAN_IP         = '%s.1'  % CLIENTE_SUBNET
H_CLIENTE_IP      = '%s.10' % CLIENTE_SUBNET

# Prefijo objetivo del hijack
PREFIJO_VICTIMA   = '%s.0/24' % VICTIMA_SUBNET   # 10.0.10.0/24

# --- Rutas y ficheros FRR por router ---
FRR_DIRS = {
    'r1': '/tmp/r1',
    'r2': '/tmp/r2',
    'r3': '/tmp/r3',
    'r4': '/tmp/r4',
}

ATTACK_SCRIPT_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 'bgp_hijack_attack.py')
ATTACK_SCRIPT_DST = '/tmp/bgp_hijack_attack.py'


# =========================================================================
# Generacion de configuracion FRR
# =========================================================================

def zebra_conf(hostname, static_routes=None):
    lines = [
        "hostname %s" % hostname,
        "password zebra",
        "enable password zebra",
        "log file %s/zebra.log" % FRR_DIRS[hostname],
    ]
    if static_routes:
        lines.append("!")
        for route in static_routes:
            lines.append("ip route %s" % route)
    lines.append("line vty")
    return "\n".join(lines) + "\n"


def bgpd_conf(hostname, asn, router_id, networks, neighbors,
              compare_routerid=False):
    """
    networks: lista de prefijos 'a.b.c.d/n' a anunciar.
    neighbors: lista de tuplas (ip_vecino, asn_vecino).
    compare_routerid: activa 'bgp bestpath compare-routerid' (necesario en r4
      para que FRR 7.2 omita el criterio 'Older Path' y use el router-id como
      desempate final, garantizando que el atacante (router-id menor) gane).
    """
    cfg = []
    cfg.append("frr defaults traditional")
    cfg.append("hostname %s" % hostname)
    cfg.append("password zebra")
    cfg.append("log file %s/bgpd.log" % FRR_DIRS[hostname])
    cfg.append("!")
    cfg.append("router bgp %d" % asn)
    cfg.append(" bgp router-id %s" % router_id)
    if EBGP_POLICY_TUNABLE:
        # Solo en FRR >= 7.4 esta directiva existe y es necesaria
        cfg.append(" no bgp ebgp-requires-policy")
    if compare_routerid:
        # Omite el criterio "Older Path" (FRR 7.2) y usa router-id como ultimo
        # desempate. Sin esto, el path de r1 (mas antiguo) siempre gana.
        cfg.append(" bgp bestpath compare-routerid")
    cfg.append(" no bgp network import-check")
    cfg.append(" timers bgp 3 9")
    for nip, nasn in neighbors:
        cfg.append(" neighbor %s remote-as %d" % (nip, nasn))
        cfg.append(" neighbor %s advertisement-interval 1" % nip)
    cfg.append(" !")
    cfg.append(" address-family ipv4 unicast")
    for pfx in networks:
        cfg.append("  network %s" % pfx)
    for nip, _ in neighbors:
        cfg.append("  neighbor %s activate" % nip)
        cfg.append("  neighbor %s soft-reconfiguration inbound" % nip)
    cfg.append(" exit-address-family")
    cfg.append("!")
    cfg.append("line vty")
    cfg.append("")
    return "\n".join(cfg)


def write_frr_files(router_name, asn, router_id, networks, neighbors,
                    compare_routerid=False, static_routes=None):
    d = FRR_DIRS[router_name]
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'zebra.conf'), 'w') as f:
        f.write(zebra_conf(router_name, static_routes=static_routes))
    with open(os.path.join(d, 'bgpd.conf'), 'w') as f:
        f.write(bgpd_conf(router_name, asn, router_id, networks, neighbors,
                          compare_routerid=compare_routerid))
    # Permisos relajados para que FRR pueda leer/escribir aun bajo AppArmor complain
    os.system('chmod -R 777 %s' % d)


# =========================================================================
# Arranque de daemons FRR dentro del namespace de cada router
# =========================================================================

def start_frr_on(router, name):
    """Inicia zebra y bgpd como daemons dentro del namespace del router Mininet."""
    d = FRR_DIRS[name]

    # Forwarding y desactivar reverse-path filtering
    router.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null')
    router.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null')
    router.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0 > /dev/null')
    for intf in router.intfNames():
        router.cmd('sysctl -w net.ipv4.conf.%s.rp_filter=0 > /dev/null' % intf)

    # Limpiar PIDs/sockets previos
    router.cmd('rm -f %s/zebra.pid %s/bgpd.pid %s/zserv.api %s/*.vty' %
               (d, d, d, d))

    # zebra primero (proporciona el socket zserv que usa bgpd).
    # FRR exige que --user pertenezca al grupo frrvty (compile-time). Esto se
    # garantiza al inicio del escenario con `usermod -aG frrvty root`.
    router.cmd(
        '%s -d -u root -g root '
        '-f %s/zebra.conf '
        '-i %s/zebra.pid '
        '-z %s/zserv.api '
        '--vty_socket %s '
        '> %s/zebra_start.log 2>&1' % (ZEBRA_BIN, d, d, d, d, d)
    )
    time.sleep(1)

    # bgpd despues
    router.cmd(
        '%s -d -u root -g root '
        '-f %s/bgpd.conf '
        '-i %s/bgpd.pid '
        '-z %s/zserv.api '
        '--vty_socket %s '
        '> %s/bgpd_start.log 2>&1' % (BGPD_BIN, d, d, d, d, d)
    )
    time.sleep(0.5)

    # Verificar PIDs
    zpid = router.cmd('cat %s/zebra.pid 2>/dev/null' % d).strip()
    bpid = router.cmd('cat %s/bgpd.pid 2>/dev/null' % d).strip()
    if zpid and bpid:
        info('  [OK] FRR en %s (zebra=%s, bgpd=%s)\n' % (name, zpid, bpid))
    else:
        info('  [ERROR] FRR en %s no arranco. zpid=%r bpid=%r\n'
             % (name, zpid, bpid))
        # Volcar los logs de arranque para diagnostico
        for log in ('zebra_start.log', 'bgpd_start.log',
                    'zebra.log', 'bgpd.log'):
            path = '%s/%s' % (d, log)
            content = router.cmd('cat %s 2>/dev/null | tail -10' % path).strip()
            if content:
                info('    --- %s ---\n' % path)
                for line in content.splitlines():
                    info('    %s\n' % line)


# =========================================================================
# Topologia
# =========================================================================

def createBGPTopology():
    """
    Topologia multi-AS:

        [h_victima]                            [h_atacante]
         AS65001                                  AS65003
            |                                        |
          [r1]---+                              +---[r3]
       100.64.0.1|                              |100.64.0.3
                 |                              |
                 +------ s1 IXP 100.64.0/24 ----+
                 |                              |
       100.64.0.2|                              |100.64.0.4
          [r2]---+                              +---[r4]
         AS65002                                  AS65004
        (transito)                                  |
                                                [h_cliente]
                          [monitor]
                       100.64.0.100
                    (port mirror + tshark)
    """

    info('*** FRR detectado: zebra=%s, bgpd=%s, version=%d.%d\n'
         % (ZEBRA_BIN, BGPD_BIN, FRR_VERSION[0], FRR_VERSION[1]))
    if FRR_VERSION == (0, 0):
        info('*** [ERROR] No se pudo ejecutar bgpd. Ejecuta primero '
             './setup_bgp_scenario.sh\n')

    # FRR comprueba via NSS que el usuario configurado (--user) pertenece al
    # grupo frrvty. getgrnam consulta /etc/group en caliente, asi que basta
    # con anadir root al grupo aqui (idempotente, no requiere re-login).
    info('*** Garantizando pertenencia de root al grupo frrvty\n')
    if os.system('getent group frrvty > /dev/null 2>&1') == 0:
        if os.system('id -nG root | grep -qw frrvty') != 0:
            os.system('usermod -aG frrvty root')
            info('  [OK] root anadido al grupo frrvty\n')
        else:
            info('  [OK] root ya pertenece al grupo frrvty\n')
    else:
        info('  [WARN] grupo frrvty no existe; FRR puede no estar instalado\n')

    info('*** Limpiando configuracion previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('sudo pkill -9 bgpd 2>/dev/null')
    os.system('sudo pkill -9 zebra 2>/dev/null')
    os.system('sudo rm -rf /tmp/r1 /tmp/r2 /tmp/r3 /tmp/r4')
    os.system('sudo rm -f /tmp/hijack.vtysh /tmp/defend.vtysh '
              '/tmp/vtysh_r3.txt /tmp/vtysh_r4.txt')
    time.sleep(1)

    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True,
                  controller=None)

    info('*** Creando hosts cliente\n')
    h_victima  = net.addHost('h_victima',  ip=None, mac='00:00:00:10:00:10')
    h_atacante = net.addHost('h_atacante', ip=None, mac='00:00:00:30:00:10')
    h_cliente  = net.addHost('h_cliente',  ip=None, mac='00:00:00:40:00:10')

    info('*** Creando routers AS\n')
    r1 = net.addHost('r1', ip=None, mac='00:00:00:01:00:01')
    r2 = net.addHost('r2', ip=None, mac='00:00:00:02:00:02')
    r3 = net.addHost('r3', ip=None, mac='00:00:00:03:00:03')
    r4 = net.addHost('r4', ip=None, mac='00:00:00:04:00:04')

    info('*** Creando monitor pasivo\n')
    monitor = net.addHost('monitor', ip=None, mac='00:00:00:00:00:AA')

    info('*** Creando switch IXP\n')
    s1 = net.addSwitch('s1', failMode='standalone')

    info('*** Creando enlaces IXP (routers <-> s1, monitor <-> s1)\n')
    net.addLink(r1, s1)
    net.addLink(r2, s1)
    net.addLink(r3, s1)
    net.addLink(r4, s1)
    net.addLink(monitor, s1)

    info('*** Creando enlaces LAN cliente (router <-> host)\n')
    net.addLink(r1, h_victima)
    net.addLink(r3, h_atacante)
    net.addLink(r4, h_cliente)

    info('*** Iniciando red\n')
    net.start()
    time.sleep(2)

    info('*** Asignando direcciones IP\n')
    # Routers - interfaz IXP (eth0) + interfaz LAN (eth1)
    r1.setIP('%s/24' % R1_IXP_IP, intf='r1-eth0')
    r1.setIP('%s/24' % R1_LAN_IP, intf='r1-eth1')

    r2.setIP('%s/24' % R2_IXP_IP, intf='r2-eth0')

    r3.setIP('%s/24' % R3_IXP_IP, intf='r3-eth0')
    r3.setIP('%s/24' % R3_LAN_IP, intf='r3-eth1')

    r4.setIP('%s/24' % R4_IXP_IP, intf='r4-eth0')
    r4.setIP('%s/24' % R4_LAN_IP, intf='r4-eth1')

    # Hosts cliente: una sola interfaz, default route via router del AS
    h_victima.setIP('%s/24'  % H_VICTIMA_IP,  intf='h_victima-eth0')
    h_victima.cmd('ip route add default via %s' % R1_LAN_IP)

    h_atacante.setIP('%s/24' % H_ATACANTE_IP, intf='h_atacante-eth0')
    h_atacante.cmd('ip route add default via %s' % R3_LAN_IP)

    # El servidor HTTP impostor corre en r3 directamente (alias en la interfaz IXP).
    # Cuando r4 redirige trafico para 10.0.10.10 hacia r3, r3 lo acepta como
    # direccion local y lo sirve sin necesidad de forwarding ni rutas estaticas.
    r3.cmd('ip addr add %s/32 dev r3-eth0' % H_VICTIMA_IP)

    h_cliente.setIP('%s/24'  % H_CLIENTE_IP,  intf='h_cliente-eth0')
    h_cliente.cmd('ip route add default via %s' % R4_LAN_IP)

    # Monitor en IXP
    monitor.setIP('%s/24' % MONITOR_IP, intf='monitor-eth0')

    info('*** Configurando escenario\n')
    configureScenario(r1, r2, r3, r4, h_victima, h_atacante, h_cliente,
                      monitor, s1)

    info('*** Escenario listo\n')
    printWelcomeMessage()

    CLI(net)

    info('*** Deteniendo daemons FRR\n')
    for r in (r1, r2, r3, r4):
        r.cmd('pkill -9 -f "bgpd .*%s" 2>/dev/null'  % r.name)
        r.cmd('pkill -9 -f "zebra .*%s" 2>/dev/null' % r.name)
    h_victima.cmd('pkill -9 -f "http.server" 2>/dev/null')
    r3.cmd('pkill -9 -f "http.server" 2>/dev/null')
    monitor.cmd('pkill -9 tshark 2>/dev/null')

    info('*** Deteniendo red\n')
    net.stop()


# =========================================================================
# Configuracion del escenario (FRR, servicios HTTP, port mirror)
# =========================================================================

def configureScenario(r1, r2, r3, r4, h_victima, h_atacante, h_cliente,
                      monitor, switch):
    """
    1. Escribe configs FRR y arranca zebra+bgpd en cada router.
    2. Configura port mirroring en s1 hacia el monitor.
    3. Levanta servidores HTTP en victima y atacante (bandera visible).
    4. Copia el script de ataque a /tmp/.
    """

    # --- Configuracion BGP (malla completa eBGP) ---
    info('  Generando configuraciones FRR...\n')

    # r1 = victima AS65001
    # router-id 1.1.1.1 (mayor que r3=0.0.0.1 -> pierde el desempate en r4)
    write_frr_files(
        'r1', AS_VICTIMA, '1.1.1.1',
        networks=[PREFIJO_VICTIMA],
        neighbors=[
            (R2_IXP_IP, AS_TRANSITO),
            (R3_IXP_IP, AS_ATACANTE),
            (R4_IXP_IP, AS_CLIENTE),
        ],
    )

    # r2 = transito AS65002 (no anuncia prefijos cliente)
    write_frr_files(
        'r2', AS_TRANSITO, '2.2.2.2',
        networks=[],
        neighbors=[
            (R1_IXP_IP, AS_VICTIMA),
            (R3_IXP_IP, AS_ATACANTE),
            (R4_IXP_IP, AS_CLIENTE),
        ],
    )

    # r3 = atacante AS65003
    # router-id 0.0.0.1 (MENOR que r1=1.1.1.1 -> gana el desempate en r4)
    # El servidor HTTP impostor corre en r3 directamente (ver createBGPTopology),
    # asi que no se necesita ruta estatica hacia h_atacante.
    write_frr_files(
        'r3', AS_ATACANTE, '0.0.0.1',
        networks=['%s.0/24' % ATACANTE_SUBNET],
        neighbors=[
            (R1_IXP_IP, AS_VICTIMA),
            (R2_IXP_IP, AS_TRANSITO),
            (R4_IXP_IP, AS_CLIENTE),
        ],
    )

    # r4 = cliente AS65004
    # compare-routerid: omite el criterio "Older Path" de FRR 7.2 y usa el
    # router-id como ultimo desempate (r3=0.0.0.1 < r1=1.1.1.1 -> r3 gana).
    write_frr_files(
        'r4', AS_CLIENTE, '4.4.4.4',
        networks=['%s.0/24' % CLIENTE_SUBNET],
        compare_routerid=True,
        neighbors=[
            (R1_IXP_IP, AS_VICTIMA),
            (R2_IXP_IP, AS_TRANSITO),
            (R3_IXP_IP, AS_ATACANTE),
        ],
    )

    info('  Arrancando FRR en cada router...\n')
    start_frr_on(r1, 'r1')
    start_frr_on(r2, 'r2')
    start_frr_on(r3, 'r3')
    start_frr_on(r4, 'r4')

    info('  Esperando convergencia BGP (10s)...\n')
    time.sleep(10)

    # Health-check: comprobar peers en r4
    summary = r4.cmd('vtysh --vty_socket /tmp/r4 -c "show ip bgp summary" 2>/dev/null')
    established = summary.count('Estab')
    if established >= 3:
        info('  [OK] r4 tiene %d peers Established\n' % established)
    else:
        info('  [WARN] r4 solo %d peers Established. Ver /tmp/r4/bgpd.log\n'
             % established)

    # --- Port mirroring hacia el monitor ---
    info('  Configurando port mirroring hacia el monitor...\n')
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
        info('  [WARN] No se encontro el puerto del switch para monitor\n')
        monitor_sw_intf = 's1-eth5'
    info('  Puerto OVS del monitor: %s\n' % monitor_sw_intf)

    os.system('ovs-ofctl add-flow s1 priority=1,action=flood')
    os.system(
        'ovs-vsctl -- set Bridge s1 mirrors=@m '
        '-- --id=@mon get Port %(port)s '
        '-- --id=@m create Mirror name=bgp_mirror select-all=true output-port=@mon'
        % {'port': monitor_sw_intf}
    )
    monitor.cmd('ifconfig monitor-eth0 promisc')
    info('  [OK] Port mirroring activo en IXP\n')

    # Escribir los HTML directamente desde Python: todos los hosts Mininet
    # comparten el mismo filesystem, asi se evitan problemas con printf/shell.
    os.makedirs('/tmp/victima_web', exist_ok=True)
    with open('/tmp/victima_web/index.html', 'w') as _f:
        _f.write(
            '<html><body>'
            '<h1>Servidor LEGITIMO AS65001</h1>'
            '<p>Prefijo 10.0.10.0/24 anunciado por r1.</p>'
            '<p>Si ves esta pagina, BGP esta enrutando al destino correcto.</p>'
            '</body></html>'
        )

    os.makedirs('/tmp/atacante_web', exist_ok=True)
    with open('/tmp/atacante_web/index.html', 'w') as _f:
        _f.write(
            '<html><body>'
            '<h1>!!! HIJACKED por AS65003 !!!</h1>'
            '<p>El trafico para 10.0.10.10 ha sido redirigido al router atacante r3.</p>'
            '<p>BGP hijack exitoso.</p>'
            '</body></html>'
        )

    # --- Servidor HTTP LEGITIMO en la victima ---
    info('  Levantando servidor HTTP legitimo en h_victima (%s)...\n' % H_VICTIMA_IP)
    h_victima.cmd(
        'cd /tmp/victima_web && python3 -m http.server 80 '
        '> /tmp/victima_http.log 2>&1 &'
    )

    # --- Servidor HTTP IMPOSTOR en r3 (bind 10.0.10.10 local al router) ---
    # r3 tiene 10.0.10.10/32 como alias en r3-eth0 (asignado en createBGPTopology).
    # Al correr el servidor en el propio r3, el trafico hijackeado llega al alias
    # y se entrega localmente sin necesidad de forwarding ni rutas estaticas.
    info('  Levantando servidor HTTP impostor en r3 (%s)...\n' % H_VICTIMA_IP)
    r3.cmd(
        'cd /tmp/atacante_web && python3 -m http.server 80 --bind %s '
        '> /tmp/r3_impostor_http.log 2>&1 &' % H_VICTIMA_IP
    )

    time.sleep(2)
    if h_victima.cmd('pgrep -f "http.server"').strip():
        info('  [OK] HTTP victima activo en %s:80\n' % H_VICTIMA_IP)
    if r3.cmd('pgrep -af "http.server.*%s"' % H_VICTIMA_IP).strip():
        info('  [OK] HTTP impostor activo en r3:%s:80\n' % H_VICTIMA_IP)
    else:
        info('  [WARN] HTTP impostor no inicio. Ver /tmp/r3_impostor_http.log\n')

    # --- Copiar script de ataque ---
    info('  Copiando script de ataque a %s...\n' % ATTACK_SCRIPT_DST)
    if os.path.exists(ATTACK_SCRIPT_SRC):
        os.system('cp %s %s' % (ATTACK_SCRIPT_SRC, ATTACK_SCRIPT_DST))
        os.system('chmod +x %s' % ATTACK_SCRIPT_DST)
        info('  [OK] Script disponible en %s\n' % ATTACK_SCRIPT_DST)
    else:
        info('  [WARN] No se encontro bgp_hijack_attack.py junto al escenario\n')

    time.sleep(1)


# =========================================================================
# Mensaje de bienvenida
# =========================================================================

def printWelcomeMessage():
    print('\n' + '='*78)
    print('  >>> ESCENARIO DE BGP HIJACKING (multi-AS con FRR) <<<')
    print('='*78)

    print('\n[TOPOLOGIA]:')
    print('    r1 AS%d  IXP %s  LAN %s   <- victima, anuncia %s'
          % (AS_VICTIMA,  R1_IXP_IP, R1_LAN_IP, PREFIJO_VICTIMA))
    print('    r2 AS%d  IXP %s             <- transito (sin host)'
          % (AS_TRANSITO, R2_IXP_IP))
    print('    r3 AS%d  IXP %s  LAN %s   <- atacante (router-id 0.0.0.1, menor que r1)'
          % (AS_ATACANTE, R3_IXP_IP, R3_LAN_IP))
    print('    r4 AS%d  IXP %s  LAN %s   <- cliente'
          % (AS_CLIENTE,  R4_IXP_IP, R4_LAN_IP))
    print('')
    print('    h_victima  %s   (HTTP legitimo en h_victima:80)'  % H_VICTIMA_IP)
    print('    h_atacante %s   (host LAN del atacante AS65003)' % H_ATACANTE_IP)
    print('    r3         alias %s  (HTTP impostor en r3:80, acepta trafico hijackeado)'
          % H_VICTIMA_IP)
    print('    h_cliente  %s   (origen del trafico)'        % H_CLIENTE_IP)
    print('    monitor    %s  (port mirror del IXP)'        % MONITOR_IP)

    print('\n[FASE 1 - VERIFICAR PEERS BGP]:')
    print('    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp summary"')
    print('    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp"')
    print('    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp %s"'
          % PREFIJO_VICTIMA)

    print('\n[FASE 2 - TRAFICO LEGITIMO (antes del hijack)]:')
    print('    mininet> h_cliente curl -s http://%s' % H_VICTIMA_IP)
    print('    # Debe responder con "Servidor LEGITIMO AS65001"')

    print('\n[FASE 3 - HIJACK DE PREFIJO IDENTICO (10.0.10.0/24)]:')
    print('    mininet> r3 python3 %s --mode prefix-hijack' % ATTACK_SCRIPT_DST)
    print('    # r3 (router-id 0.0.0.1) < r1 (1.1.1.1) -> gana el desempate')

    print('\n[FASE 4 - VERIFICAR REDIRECCION]:')
    print('    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp %s"'
          % PREFIJO_VICTIMA)
    print('    mininet> h_cliente curl -s http://%s' % H_VICTIMA_IP)
    print('    # Debe responder con "!!! HIJACKED por AS65003 !!!"')

    print('\n[FASE 5 - SUB-PREFIX HIJACK (10.0.10.0/25, longest-prefix gana)]:')
    print('    mininet> r3 python3 %s --mode subprefix-hijack' % ATTACK_SCRIPT_DST)
    print('    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp 10.0.10.0/25"')
    print('    mininet> h_cliente curl -s http://%s' % H_VICTIMA_IP)

    print('\n[FASE 6 - INSPECCION DE MENSAJES BGP UPDATE]:')
    print('    mininet> monitor tshark -i monitor-eth0 -Y bgp -O bgp -c 20')
    print('    # Lanzar en otra terminal y volver a inyectar el hijack para capturar')

    print('\n[FASE 7 - DEFENSA (prefix-list rechaza anuncios falsos en r4)]:')
    print('    mininet> r3 python3 %s --mode defend' % ATTACK_SCRIPT_DST)
    print('    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp %s"'
          % PREFIJO_VICTIMA)
    print('    mininet> h_cliente curl -s http://%s' % H_VICTIMA_IP)
    print('    # Tras la defensa, vuelve a servir contenido legitimo')

    print('\n[FASE 8 - RETIRAR EL HIJACK]:')
    print('    mininet> r3 python3 %s --mode withdraw' % ATTACK_SCRIPT_DST)

    print('\n[DIAGNOSTICO]:')
    print('    mininet> r1 vtysh --vty_socket /tmp/r1 -c "show ip bgp"')
    print('    mininet> r4 ip route                       # tabla del kernel')
    print('    mininet> sh tail -f /tmp/r4/bgpd.log       # log BGP de r4')
    print('    mininet> sh ovs-vsctl list mirror          # estado del port mirror')

    print('\n' + '='*78)
    print('  Escribe "exit" o presiona Ctrl+D para salir')
    print('='*78 + '\n')


if __name__ == '__main__':
    setLogLevel('info')
    createBGPTopology()
