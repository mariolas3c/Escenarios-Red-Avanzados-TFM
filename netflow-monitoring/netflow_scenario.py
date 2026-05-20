#!/usr/bin/python3
"""
NetFlow Monitoring Scenario — Monitorización completa de tráfico con NetFlow + OpenSearch

Arquitectura:
  h1 (10.0.3.10) ─┐
  h2 (10.0.3.20)  │
  h3 (10.0.3.30)  ├──[s1 OVS]── monitor (10.0.3.100)  ← softflowd exporter
  h4 (10.0.3.40)  │    │ mirror       │ Netflow v5 UDP:2055
  h5 (10.0.3.50) ─┘    │              ▼
                        └────── collector (10.0.3.200)  ← netflow_collector.py
                                        │ HTTP JSON
                                        ▼
                            OpenSearch (10.0.3.254:9200)  ← host via OVS bridge
                                        │
                                        ▼
                               Grafana (10.0.3.254:3000)

Los hosts 10.0.3.254 y Docker corren en la máquina host (IP asignada al bridge OVS).
"""

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
import os
import sys
import time
import shutil
import subprocess

sys.stdout.reconfigure(encoding='utf-8')

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
HOST_BRIDGE_IP = '10.0.3.254'   # IP que se asigna al bridge OVS en la máquina host
COLLECTOR_IP   = '10.0.3.200'
NETFLOW_PORT   = 2055
ES_URL         = f'http://{HOST_BRIDGE_IP}:9200'
GRAFANA_URL    = f'http://{HOST_BRIDGE_IP}:3000'


# ─── Helpers ─────────────────────────────────────────────────────────────────

def cleanup():
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('pkill -f softflowd    > /dev/null 2>&1')
    os.system('pkill -f netflow_collector > /dev/null 2>&1')
    os.system('pkill -f traffic_generator > /dev/null 2>&1')
    os.system('pkill -f "http.server" > /dev/null 2>&1')
    # Remove previous OVS bridge IP if any
    os.system(f'ip addr del {HOST_BRIDGE_IP}/24 dev s1 2>/dev/null')


def copy_scripts():
    for name in ['netflow_collector.py', 'traffic_generator.py', 'grafana_setup.py']:
        src = os.path.join(SCRIPTS_DIR, name)
        if os.path.exists(src):
            shutil.copy2(src, f'/tmp/{name}')
            os.chmod(f'/tmp/{name}', 0o755)


def check_softflowd():
    if shutil.which('softflowd'):
        return True
    print('[WARN] softflowd not installed. Install with: sudo apt-get install -y softflowd')
    return False


def check_docker():
    has_docker = shutil.which('docker') is not None
    has_compose = (shutil.which('docker-compose') is not None or
                   subprocess.run(['docker', 'compose', 'version'],
                                  capture_output=True).returncode == 0)
    return has_docker and has_compose


def start_docker_services():
    compose_file = os.path.join(SCRIPTS_DIR, 'docker-compose.yml')
    if not os.path.exists(compose_file):
        print('[WARN] docker-compose.yml not found, skipping Docker services')
        return False

    print('[*] Starting Elasticsearch + Grafana via Docker Compose...')

    # Try docker compose (v2) first, then docker-compose (v1)
    for cmd in [f'docker compose -f {compose_file} up -d',
                f'docker-compose -f {compose_file} up -d']:
        ret = os.system(f'{cmd} 2>&1')
        if ret == 0:
            break
    else:
        print('[WARN] Docker Compose failed — services may not be available')
        return False

    print('[*] Waiting for OpenSearch...')
    for _ in range(45):
        r = os.system('curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1')
        if r == 0:
            print('[OK] OpenSearch ready')
            break
        time.sleep(2)
    else:
        print('[WARN] OpenSearch not responding after 90s')
        return False

    print('[*] Setting up Grafana dashboard...')
    # Give Grafana a moment to fully start
    time.sleep(5)
    setup_script = os.path.join(SCRIPTS_DIR, 'grafana_setup.py')
    os.system(f'python3 {setup_script} --grafana http://localhost:3000 '
              f'--es http://opensearch:9200 2>&1 | grep -E "OK|ERR|WARN|ready|Dashboard"')
    return True


def assign_bridge_ip():
    """Assign HOST_BRIDGE_IP to the OVS bridge so Mininet hosts can reach host services."""
    os.system(f'ip addr add {HOST_BRIDGE_IP}/24 dev s1 2>/dev/null || true')
    os.system(f'ip link set s1 up 2>/dev/null')
    print(f'[OK] Host IP on Mininet subnet: {HOST_BRIDGE_IP}')


def setup_port_mirror(switch_name, monitor_port_name):
    """Mirror all traffic on the OVS bridge to the monitor port."""
    print(f'[*] Configuring port mirroring → {monitor_port_name}')
    # Create mirror: all traffic → monitor port
    # NOTE: do NOT add a priority=1 FLOOD rule here — OVS excludes the mirror
    # output port from the FLOOD group, which breaks connectivity to collector.
    # The default priority=0 NORMAL rule (L2 learning) works correctly.
    os.system(
        f'ovs-vsctl -- set Bridge {switch_name} mirrors=@m '
        f'-- --id=@mon get Port {monitor_port_name} '
        f'-- --id=@m create Mirror name=netflow-mirror '
        f'select-all=true output-port=@mon > /dev/null 2>&1'
    )
    print('[OK] Port mirroring active')


def configure_services(h1, h2, h3, h4, h5, monitor, collector):
    # monitor-eth1 is the dedicated mirror capture interface (no IP needed)
    monitor.cmd('ifconfig monitor-eth1 promisc up')

    # h3: web server
    h3.cmd('python3 -m http.server 80 --directory /var/www/html &> /tmp/http_server.log &')
    h3.cmd('python3 -m http.server 8080 --directory /tmp &> /tmp/http_alt.log &')

    # h4: fake SSH / FTP listeners (netcat, accept and close)
    h4.cmd('while true; do nc -l -p 22  < /dev/null; done &> /dev/null &')
    h4.cmd('while true; do nc -l -p 21  < /dev/null; done &> /dev/null &')

    # h5: fake DB listeners
    h5.cmd('while true; do nc -l -p 3306 < /dev/null; done &> /dev/null &')
    h5.cmd('while true; do nc -l -p 5432 < /dev/null; done &> /dev/null &')
    h5.cmd('while true; do nc -l -p 6379 < /dev/null; done &> /dev/null &')

    time.sleep(1)

    # softflowd on monitor: capture on mirror interface (eth1), export via normal interface (eth0)
    if check_softflowd():
        monitor.cmd(
            f'softflowd -i monitor-eth1 '
            f'-n {COLLECTOR_IP}:{NETFLOW_PORT} '
            f'-v 5 '
            f'-t maxlife=60 '
            f'-p /tmp/softflowd.pid '
            f'&> /tmp/softflowd.log &'
        )
        print(f'[OK] softflowd started on monitor → NetFlow v5 → {COLLECTOR_IP}:{NETFLOW_PORT}')
    else:
        print(f'[WARN] softflowd not running — install it and run manually inside monitor:')
        print(f'       monitor> softflowd -i monitor-eth1 -n {COLLECTOR_IP}:{NETFLOW_PORT} -v 5')

    # Start collector on the collector host
    collector.cmd(
        f'python3 /tmp/netflow_collector.py '
        f'--bind 0.0.0.0 --port {NETFLOW_PORT} '
        f'--es {ES_URL} '
        f'&> /tmp/netflow_collector.log &'
    )
    print(f'[OK] netflow_collector.py started on collector — logs: /tmp/netflow_collector.log')
    time.sleep(1)


def print_welcome():
    print(f"""
╔══════════════════════════════════════════════════════════════════════════╗
║         NETFLOW MONITORING SCENARIO — TFM Network Lab                  ║
╠══════════════════════════════════════════════════════════════════════════╣
║  TOPOLOGÍA                                                              ║
║    h1 (10.0.3.10)  ─┐                                                  ║
║    h2 (10.0.3.20)   │                                                  ║
║    h3 (10.0.3.30)   ├── [s1] ── monitor (10.0.3.100) [softflowd]      ║
║    h4 (10.0.3.40)   │     │mirror      │ UDP:2055                      ║
║    h5 (10.0.3.50)  ─┘     │            ▼                               ║
║                            └── collector (10.0.3.200) [collector.py]   ║
║                                         │ HTTP                         ║
║                             OpenSearch ({HOST_BRIDGE_IP}:9200)              ║
║                             Grafana ({HOST_BRIDGE_IP}:3000)                ║
╠══════════════════════════════════════════════════════════════════════════╣
║  SERVICIOS ACTIVOS                                                      ║
║    h3: HTTP server :80, :8080                                           ║
║    h4: SSH sim :22,  FTP sim :21                                        ║
║    h5: MySQL sim :3306,  PgSQL sim :5432,  Redis sim :6379              ║
║    monitor: softflowd (exporter NetFlow v5 → collector:2055)            ║
║    collector: netflow_collector.py (→ OpenSearch)                       ║
╠══════════════════════════════════════════════════════════════════════════╣
║  INICIO RÁPIDO                                                          ║
║  1. Generar tráfico (en terminal xterm de h1 o h2):                     ║
║     mininet> xterm h1                                                   ║
║     h1> python3 /tmp/traffic_generator.py --mode continuous             ║
║     h1> python3 /tmp/traffic_generator.py --mode burst                  ║
║     h1> python3 /tmp/traffic_generator.py --mode scan                   ║
║                                                                         ║
║  2. Ver flows en tiempo real:                                           ║
║     mininet> h2 tail -f /tmp/netflow_collector.log                      ║
║                                                                         ║
║  3. Ver dashboard Grafana: {GRAFANA_URL}                    ║
║     Login: admin / password                                             ║
║                                                                         ║
║  4. Verificar softflowd:                                                ║
║     mininet> monitor cat /tmp/softflowd.log                             ║
║                                                                         ║
║  5. Reiniciar colector con --no-es (solo terminal, sin ES):             ║
║     mininet> collector python3 /tmp/netflow_collector.py --no-es        ║
╚══════════════════════════════════════════════════════════════════════════╝
""")


# ─── Main scenario ───────────────────────────────────────────────────────────

def netflow_scenario():
    cleanup()

    # ── Network topology ──────────────────────────────────────────────────────
    net = Mininet(switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)

    # Traffic-generating hosts
    h1 = net.addHost('h1', ip='10.0.3.10/24', mac='00:00:00:03:00:01')
    h2 = net.addHost('h2', ip='10.0.3.20/24', mac='00:00:00:03:00:02')
    h3 = net.addHost('h3', ip='10.0.3.30/24', mac='00:00:00:03:00:03')
    h4 = net.addHost('h4', ip='10.0.3.40/24', mac='00:00:00:03:00:04')
    h5 = net.addHost('h5', ip='10.0.3.50/24', mac='00:00:00:03:00:05')

    # Infrastructure hosts
    monitor   = net.addHost('monitor',   ip='10.0.3.100/24', mac='00:00:00:03:00:0a')
    collector = net.addHost('collector', ip='10.0.3.200/24', mac='00:00:00:03:00:0b')

    s1 = net.addSwitch('s1', failMode='standalone')

    # Links — order determines port numbers on s1:
    # h1→s1-eth1, h2→s1-eth2, h3→s1-eth3, h4→s1-eth4, h5→s1-eth5
    # monitor→s1-eth6, collector→s1-eth7
    # monitor-capture→s1-eth8  (dedicated mirror output — keeps monitor-eth0 for normal traffic)
    for host in [h1, h2, h3, h4, h5, monitor, collector]:
        net.addLink(host, s1)
    # Second link for monitor: s1-eth8 is the mirror output port.
    # OVS excludes the mirror output port from normal L2 forwarding, so using
    # a dedicated capture interface prevents monitor from being isolated.
    net.addLink(monitor, s1)

    net.start()
    time.sleep(2)

    # ── Post-start configuration ───────────────────────────────────────────────
    assign_bridge_ip()

    # Port mirroring: all traffic on s1 → monitor-eth1 (s1-eth8, capture-only port)
    setup_port_mirror('s1', 's1-eth8')

    copy_scripts()

    # Start Elasticsearch + Grafana via Docker Compose
    if check_docker():
        start_docker_services()
    else:
        print('[WARN] Docker not available — Elasticsearch and Grafana will not start.')
        print('       Run: sudo apt-get install docker.io  &&  pip3 install docker-compose')
        print('       Or start them manually and set ES_URL in netflow_collector.py')

    # Configure services on hosts
    configure_services(h1, h2, h3, h4, h5, monitor, collector)

    print_welcome()

    CLI(net)

    # ── Cleanup ────────────────────────────────────────────────────────────────
    net.stop()
    os.system(f'ip addr del {HOST_BRIDGE_IP}/24 dev s1 2>/dev/null || true')


if __name__ == '__main__':
    netflow_scenario()
