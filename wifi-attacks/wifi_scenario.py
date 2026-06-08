#!/usr/bin/python
"""
Escenario WiFi 802.11: Deauth + Evil Twin + Ataque WEP en Mininet-WiFi

Topología:
  [sta1 (víctima)  10.0.4.10] ─── 802.11g WEP ─┐
  [sta2 (cliente)  10.0.4.20] ─── 802.11g WEP ─┤── [ap1 SSID:RedInsegura] ──[s1]── [server 10.0.4.100]
  [attacker        10.0.4.30] ─── wlan0→mon0   ─┘   WEP-40: AABBCCDDEE           HTTP:80, FTP:21
                               └── wlan1 (Evil Twin con hostapd)
"""

from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import OVSKernelSwitch
import os
import time
import shutil

# ---------------------------------------------------------------------------
# Configuración del escenario
# ---------------------------------------------------------------------------
SSID       = "RedInsegura"
WEP_KEY    = "AABBCCDDEE"    # Clave WEP-40 en hexadecimal (40 bits = 5 bytes)
CHANNEL    = "6"
WIFI_MODE  = "g"             # 802.11g

SUBNET      = "10.0.4"
AP_IP       = "%s.1"   % SUBNET
STA1_IP     = "%s.10"  % SUBNET
STA2_IP     = "%s.20"  % SUBNET
ATTACKER_IP = "%s.30"  % SUBNET
SERVER_IP   = "%s.100" % SUBNET


# ---------------------------------------------------------------------------
def setup_server(server):
    """Levanta servicios en el servidor cableado."""
    info('  Creando página web en servidor...\n')
    server.cmd('mkdir -p /tmp/wifi_web')
    server.cmd('echo "<html><body><h1>Servidor Legítimo</h1>'
               '<p>IP: %s - Banco Online</p></body></html>"'
               ' > /tmp/wifi_web/index.html' % SERVER_IP)
    server.cmd('cd /tmp/wifi_web && python3 -m http.server 80 '
               '> /tmp/wifi_server.log 2>&1 &')
    # Puerto FTP simulado
    server.cmd('while true; do nc -lkp 21 2>/dev/null; done &')
    time.sleep(1)

    # Verificar HTTP
    result = server.cmd('curl -s http://localhost/ 2>/dev/null | grep -c Legítimo || echo 0')
    if result.strip() != '0':
        info('  [OK] HTTP activo en %s:80\n' % SERVER_IP)
    else:
        info('  [WARN] HTTP no respondió en %s:80\n' % SERVER_IP)


def setup_attacker_monitor(attacker):
    """Crea interfaz de monitor en wlan0 del atacante."""
    info('  Configurando modo monitor (mon0) en atacante...\n')
    attacker.cmd('iw dev attacker-wlan0 interface add mon0 type monitor 2>/dev/null || true')
    attacker.cmd('ip link set mon0 up 2>/dev/null || true')
    time.sleep(0.5)
    result = attacker.cmd('iw dev 2>/dev/null | grep -A2 "Interface mon0" | grep type || echo ""')
    if 'monitor' in result:
        info('  [OK] Interfaz monitor mon0 activa\n')
    else:
        info('  [INFO] mon0 no confirmado; usar attacker-wlan0 directamente si es necesario\n')


def generate_traffic(sta1, sta2):
    """Genera tráfico continuo para acumular IVs WEP captureables."""
    info('  Generando tráfico de fondo (para captura de IVs WEP)...\n')
    sta1.cmd('ping -i 0.2 %s > /dev/null 2>&1 &' % SERVER_IP)
    sta2.cmd('ping -i 0.3 %s > /dev/null 2>&1 &' % SERVER_IP)
    sta1.cmd('while true; do curl -s http://%s > /dev/null 2>&1; sleep 1; done &' % SERVER_IP)
    sta2.cmd('while true; do curl -s http://%s > /dev/null 2>&1; sleep 2; done &' % SERVER_IP)


def copy_attack_scripts():
    """Copia los scripts de ataque a /tmp/ para uso desde la CLI de Mininet."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scripts = ['deauth_attack.py', 'evil_twin.py', 'wifi_attack.py']
    for script in scripts:
        src = os.path.join(script_dir, script)
        dst = '/tmp/' + script
        if os.path.exists(src):
            shutil.copy(src, dst)
            os.chmod(dst, 0o755)
            info('  [OK] /tmp/%s\n' % script)
        else:
            info('  [WARN] No encontrado: %s\n' % src)


def get_ap_radio_iface(ap):
    """Devuelve el nombre de la interfaz radio del AP (la que tiene type AP en iw dev).
    En mininet-wifi 2.x el AP puede recibir wlan1 en lugar de wlan0."""
    for suffix in ['wlan0', 'wlan1']:
        iface = '%s-%s' % (ap.name, suffix)
        result = ap.cmd('iw dev %s info 2>/dev/null | grep "type AP" || echo ""' % iface)
        if 'AP' in result:
            return iface
    # Fallback: devolver el primero que exista
    for suffix in ['wlan1', 'wlan0']:
        iface = '%s-%s' % (ap.name, suffix)
        result = ap.cmd('test -d /sys/class/net/%s && echo ok || echo ""' % iface)
        if 'ok' in result:
            return iface
    return '%s-wlan0' % ap.name


def get_mac(node, iface_suffix='wlan0'):
    """Obtiene la MAC de una interfaz WiFi de un nodo."""
    for suffix in [iface_suffix, 'wlan0', 'wlan1']:
        try:
            iface = '%s-%s' % (node.name, suffix)
            result = node.cmd('cat /sys/class/net/%s/address 2>/dev/null || echo ""' % iface)
            mac = result.strip().upper()
            if len(mac) == 17:
                return mac
        except Exception:
            pass
    return 'XX:XX:XX:XX:XX:XX'


def print_scenario_info(ap1, sta1, sta2, attacker):
    """Muestra el banner informativo del escenario con IPs, MACs y comandos."""
    ap_radio = get_ap_radio_iface(ap1)
    ap_mac   = get_mac(ap1,      'wlan0')
    s1_mac   = get_mac(sta1,     'wlan0')
    s2_mac   = get_mac(sta2,     'wlan0')
    att_mac  = get_mac(attacker, 'wlan0')

    info('\n' + '='*72 + '\n')
    info('  ESCENARIO WIFI 802.11 - LISTO\n')
    info('='*72 + '\n')
    info('  Red:      SSID=%-20s  Canal=%s (802.11%s)\n' % (SSID, CHANNEL, WIFI_MODE))
    info('  Cifrado:  WEP-40\n')
    info('  Clave:    %s (hex)  ->  ASCII equiv: "\\xAA\\xBB\\xCC\\xDD\\xEE"\n' % WEP_KEY)
    info('-'*72 + '\n')
    info('  Host         IP               MAC\n')
    info('  %-12s %-16s %s  (radio: %s)\n' % ('ap1 (AP)', AP_IP, ap_mac, ap_radio))
    info('  %-12s %-16s %s\n' % ('sta1',       STA1_IP,     s1_mac))
    info('  %-12s %-16s %s\n' % ('sta2',       STA2_IP,     s2_mac))
    info('  %-12s %-16s %s  (mon0 activa / wlan1 libre)\n' % ('attacker', ATTACKER_IP, att_mac))
    info('  %-12s %-16s HTTP:80 FTP:21\n' % ('server', SERVER_IP))
    info('-'*72 + '\n')
    info('  Verificar asociacion del AP:\n')
    info('      mininet> ap1 iw dev %s station dump\n' % ap_radio)
    info('      mininet> sh cat /sys/class/net/%s/address\n' % ap_radio)
    info('  Verificar conectividad (usar IPs, no nombres de nodo):\n')
    info('      mininet> sta1 ping -c3 %s\n' % AP_IP)
    info('='*72 + '\n')
    info('  ATAQUES DISPONIBLES\n')
    info('-'*72 + '\n')
    info('  [1] Deauth flood (desconectar victima del AP)\n')
    info('      mininet> xterm sta1                          (en xterm: ping -i 0.5 %s)\n' % SERVER_IP)
    info('      mininet> attacker python3 /tmp/deauth_attack.py \\\n')
    info('                 --bssid %s --client %s --hwsim\n' % (ap_mac, s1_mac))
    info('      # Reconectar tras el ataque:\n')
    info('      mininet> sta1 iw dev sta1-wlan0 connect %s 2437 %s key d:0:%s\n' % (SSID, ap_mac, WEP_KEY))
    info('\n')
    info('  [2] Evil Twin (AP falso mismo SSID + phishing)\n')
    info('      mininet> attacker python3 /tmp/evil_twin.py \\\n')
    info('                 --ssid %s --iface attacker-wlan1 --phishing\n' % SSID)
    info('\n')
    info('  [3] WEP Cracking (pipeline completo: captura -> replay -> crack)\n')
    info('      mininet> attacker python3 /tmp/wifi_attack.py \\\n')
    info('                 --bssid %s --channel %s --client %s\n' % (ap_mac, CHANNEL, s1_mac))
    info('='*72 + '\n')
    info('  Logs y capturas: /tmp/wep_capture-01.cap\n')
    info('='*72 + '\n\n')


# ---------------------------------------------------------------------------
def create_wifi_topology():
    setLogLevel('info')

    info('*** Limpiando configuración previa\n')
    os.system('sudo mn -c > /dev/null 2>&1')
    os.system('sudo pkill -9 hostapd     2>/dev/null; true')
    os.system('sudo pkill -9 wpa_supplicant 2>/dev/null; true')
    os.system('sudo pkill -9 airodump-ng 2>/dev/null; true')
    os.system('sudo pkill -9 aireplay-ng 2>/dev/null; true')
    os.system('sudo pkill -9 dnsmasq     2>/dev/null; true')
    os.system('rm -f /tmp/wep_capture* /tmp/evil_twin_hostapd.conf /tmp/evil_twin_dnsmasq.conf')

    info('*** Preparando módulo mac80211_hwsim\n')
    # Descargar el módulo para que mininet-wifi lo cargue en modo radios=0
    # y use hwsim_mgmt para crear interfaces dinámicamente (evita conflicto
    # con interfaces preexistentes si se carga con radios=N aquí)
    os.system('rmmod mac80211_hwsim 2>/dev/null; true')
    time.sleep(0.5)

    info('*** Creando topología Mininet-WiFi\n')

    net = Mininet_wifi()
    info('  [INFO] Mininet-WiFi en modo básico\n')

    info('*** Creando nodos\n')

    # Access Point con WEP-40
    ap1 = net.addAccessPoint(
        'ap1',
        ssid=SSID,
        mode=WIFI_MODE,
        channel=CHANNEL,
        encrypt='wep',
        passwd=WEP_KEY,
        failMode='standalone',
        position='50,50,0'
    )

    # Estaciones legítimas con WEP
    sta1 = net.addStation(
        'sta1',
        ip='%s/24' % STA1_IP,
        passwd=WEP_KEY,
        encrypt='wep',
        wlans=1,
        position='20,50,0'
    )
    sta2 = net.addStation(
        'sta2',
        ip='%s/24' % STA2_IP,
        passwd=WEP_KEY,
        encrypt='wep',
        wlans=1,
        position='50,20,0'
    )

    # Atacante con 2 interfaces WiFi:
    #   wlan0 → modo monitor (mon0) para captura y deauth
    #   wlan1 → Evil Twin AP (hostapd)
    attacker = net.addStation(
        'attacker',
        ip='%s/24' % ATTACKER_IP,
        wlans=2,
        position='80,50,0'
    )

    # Servidor cableado y switch
    server  = net.addHost('server',  ip='%s/24' % SERVER_IP)
    s1      = net.addSwitch('s1', cls=OVSKernelSwitch, failMode='standalone')

    info('*** Configurando modelo de propagación\n')
    net.setPropagationModel(model="logDistance", exp=3)

    info('*** Configurando nodos WiFi\n')
    net.configureWifiNodes()

    # Conexión del servidor al AP vía switch cableado
    net.addLink(ap1, s1)
    net.addLink(server, s1)

    info('*** Construyendo e iniciando red\n')
    net.build()
    s1.start([])
    net.start()
    time.sleep(2)

    # Asignar IP de gestion al AP (necesaria para que las estaciones puedan pingarlo)
    ap1_radio = get_ap_radio_iface(ap1)
    ap1.cmd('ip addr add %s/24 dev %s 2>/dev/null || true' % (AP_IP, ap1_radio))

    # Routing básico
    server.cmd('ip route add default via %s 2>/dev/null || true' % AP_IP)
    ap1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Setup
    info('*** Configurando escenario\n')
    setup_server(server)
    setup_attacker_monitor(attacker)
    generate_traffic(sta1, sta2)

    info('*** Copiando scripts de ataque a /tmp/\n')
    copy_attack_scripts()

    print_scenario_info(ap1, sta1, sta2, attacker)

    CLI(net)

    # Limpieza al salir
    info('*** Deteniendo servicios\n')
    os.system('sudo pkill -9 hostapd     2>/dev/null; true')
    os.system('sudo pkill -9 airodump-ng 2>/dev/null; true')
    os.system('sudo pkill -9 aireplay-ng 2>/dev/null; true')
    os.system('sudo pkill -9 dnsmasq     2>/dev/null; true')
    net.stop()


if __name__ == '__main__':
    create_wifi_topology()
