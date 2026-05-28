#!/bin/bash
# =============================================================================
# Script de instalación para el escenario WiFi 802.11
# Instala: mininet-wifi, aircrack-ng, hostapd, dnsmasq, python3-scapy
# Carga el módulo mac80211_hwsim para interfaces WiFi virtuales
# =============================================================================

set -e

echo "======================================================================="
echo "  CONFIGURACIÓN DEL ESCENARIO WIFI 802.11 — DEAUTH + EVIL TWIN + WEP"
echo "======================================================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Ejecutar como root: sudo ./setup_wifi_scenario.sh"
    exit 1
fi

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

# Función para instalar si el binario no está disponible
install_if_missing() {
    local pkg=$1
    local bin=${2:-$1}
    if command -v "$bin" &>/dev/null; then
        echo "  [OK] $pkg ya instalado"
    else
        echo "  [INSTALANDO] $pkg..."
        apt-get install -y "$pkg" -qq
        echo "  [OK] $pkg instalado"
    fi
}

# --------------------------------------------------------------------------
echo "[1/6] Actualizando repositorios..."
apt-get update -qq
echo "  [OK] Repositorios actualizados"

# --------------------------------------------------------------------------
echo ""
echo "[2/6] Instalando dependencias base del sistema..."

install_if_missing python3-pip pip3
install_if_missing python3-scapy
install_if_missing aircrack-ng aircrack-ng
install_if_missing hostapd
install_if_missing dnsmasq
install_if_missing tcpdump
install_if_missing iw
install_if_missing wireless-tools iwconfig
install_if_missing net-tools ifconfig
install_if_missing curl
install_if_missing python3-requests
# Dependencias de compilación para hwsim_mgmt y wmediumd
install_if_missing libnl-3-dev    pkg-config
install_if_missing libnl-genl-3-dev pkg-config
install_if_missing libssl-dev     pkg-config
install_if_missing libconfig-dev  pkg-config
install_if_missing libevent-dev   pkg-config

# --------------------------------------------------------------------------
echo ""
echo "[3/6] Instalando mininet-wifi..."

# Dependencias Python requeridas por mn_wifi (numpy, scipy, matplotlib)
echo "  Instalando dependencias Python (numpy, scipy, matplotlib)..."
pip3 install numpy scipy matplotlib 2>/dev/null | grep -E "^(Successfully|Requirement)" | sed 's/^/  /' || true

if python3 -c "from mn_wifi.net import Mininet_wifi" 2>/dev/null; then
    echo "  [OK] mininet-wifi ya instalado"
else
    echo "  [INSTALANDO] mininet-wifi 2.3 (compatible con mininet 2.3.0)..."

    # Dependencias para la instalación desde fuente
    apt-get install -y git python3-dev build-essential -qq

    MNWIFI_TMP=$(mktemp -d)

    # Usar el tag 2.3 — compatible con mininet 2.3.0 instalado en el sistema
    # (main/HEAD requiere fmtBps y FlightRadar24 que no existen en mininet 2.3.0)
    git clone --depth=1 --branch 2.3 \
        https://github.com/intrig-unicamp/mininet-wifi.git "$MNWIFI_TMP/mininet-wifi" 2>&1 | \
        grep -v "^hint:" || {
        echo "  [WARN] No se pudo clonar mininet-wifi (sin internet)."
        echo "         Instala manualmente:"
        echo "           git clone --branch 2.3 https://github.com/intrig-unicamp/mininet-wifi"
        echo "           cd mininet-wifi && pip3 install ."
        rm -rf "$MNWIFI_TMP"
    }

    if [ -d "$MNWIFI_TMP/mininet-wifi" ]; then
        cd "$MNWIFI_TMP/mininet-wifi"
        pip3 install . 2>/dev/null | grep -E "^(Successfully|Requirement|Installing)" | sed 's/^/  /' || \
            python3 setup.py install --quiet
        cd "$SCRIPT_DIR"
        rm -rf "$MNWIFI_TMP"
        echo "  [OK] mininet-wifi 2.3 instalado"
    fi

    # Verificar instalación
    if python3 -c "from mn_wifi.net import Mininet_wifi" 2>/dev/null; then
        echo "  [OK] mininet-wifi verificado"
    else
        echo "  [WARN] mininet-wifi no disponible. El escenario no funcionará sin él."
        echo "         Ver: https://github.com/intrig-unicamp/mininet-wifi"
    fi
fi

# --------------------------------------------------------------------------
echo ""
echo "[4/6] Instalando hwsim_mgmt y wmediumd (herramientas WiFi virtual)..."

# hwsim_mgmt — crea radios virtuales mac80211_hwsim dinámicamente (necesario para mn_wifi)
if command -v hwsim_mgmt &>/dev/null; then
    echo "  [OK] hwsim_mgmt ya instalado"
else
    echo "  [INSTALANDO] hwsim_mgmt..."
    apt-get install -y git build-essential -qq
    HW_TMP=$(mktemp -d)
    git clone --depth=1 https://github.com/ramonfontes/mac80211_hwsim_mgmt.git "$HW_TMP/hwsim_mgmt" 2>/dev/null && \
        cd "$HW_TMP/hwsim_mgmt" && make 2>/dev/null && make install && \
        echo "  [OK] hwsim_mgmt instalado" || \
        echo "  [WARN] No se pudo instalar hwsim_mgmt"
    cd "$SCRIPT_DIR"; rm -rf "$HW_TMP"
fi

# wmediumd — simulador de medio inalámbrico (opcional pero recomendado)
if command -v wmediumd &>/dev/null; then
    echo "  [OK] wmediumd ya instalado"
else
    echo "  [INSTALANDO] wmediumd..."
    WMD_TMP=$(mktemp -d)
    git clone --depth=1 https://github.com/ramonfontes/wmediumd.git "$WMD_TMP/wmediumd" 2>/dev/null && \
        cd "$WMD_TMP/wmediumd" && make 2>/dev/null && \
        cp wmediumd/wmediumd /usr/local/bin/ && \
        echo "  [OK] wmediumd instalado" || \
        echo "  [WARN] No se pudo instalar wmediumd (no crítico)"
    cd "$SCRIPT_DIR"; rm -rf "$WMD_TMP"
fi

# Cargar módulo con radios=0 — mininet-wifi añade radios dinámicamente con hwsim_mgmt
if lsmod | grep -q mac80211_hwsim; then
    echo "  [OK] mac80211_hwsim ya cargado"
else
    modprobe mac80211_hwsim radios=0 2>/dev/null && \
        echo "  [OK] mac80211_hwsim cargado (radios=0, mn_wifi los creara dinamicamente)" || \
        echo "  [WARN] No se pudo cargar mac80211_hwsim. Requiere kernel >=3.8 con soporte CFG80211."
fi

# Asegurarse de que se cargue en el siguiente arranque (sin radios fijos)
if ! grep -q mac80211_hwsim /etc/modules 2>/dev/null; then
    echo "mac80211_hwsim" >> /etc/modules
    echo "  [OK] mac80211_hwsim añadido a /etc/modules"
fi

# --------------------------------------------------------------------------
echo ""
echo "[5/6] Copiando scripts a /tmp/..."

for script in wifi_scenario.py deauth_attack.py evil_twin.py wifi_attack.py; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        cp "$SCRIPT_DIR/$script" "/tmp/$script"
        chmod +x "/tmp/$script"
        echo "  [OK] /tmp/$script"
    else
        echo "  [WARN] $script no encontrado en $SCRIPT_DIR"
    fi
done

# --------------------------------------------------------------------------
echo ""
echo "[6/6] Verificando instalación..."

STATUS_OK=true

check_tool() {
    local name=$1
    local bin=$2
    if command -v "$bin" &>/dev/null; then
        echo "  [OK] $name"
    else
        echo "  [FAIL] $name — no encontrado"
        STATUS_OK=false
    fi
}

check_tool "aircrack-ng"   aircrack-ng
check_tool "airodump-ng"   airodump-ng
check_tool "aireplay-ng"   aireplay-ng
check_tool "airmon-ng"     airmon-ng
check_tool "hostapd"       hostapd
check_tool "dnsmasq"       dnsmasq
check_tool "iw"            iw
check_tool "tcpdump"       tcpdump
check_tool "python3-scapy" python3 && python3 -c "from scapy.layers.dot11 import Dot11" 2>/dev/null && \
    echo "  [OK] scapy Dot11 (frames 802.11)" || echo "  [FAIL] scapy sin soporte Dot11"

if python3 -c "from mn_wifi.net import Mininet_wifi" 2>/dev/null; then
    echo "  [OK] mininet-wifi"
else
    echo "  [FAIL] mininet-wifi — no instalado"
    STATUS_OK=false
fi

if lsmod | grep -q mac80211_hwsim; then
    echo "  [OK] mac80211_hwsim (módulo kernel)"
else
    echo "  [WARN] mac80211_hwsim no cargado — ejecutar: sudo modprobe mac80211_hwsim radios=5"
fi

# --------------------------------------------------------------------------
echo ""
cat > /tmp/wifi_quickstart.txt << 'EOF'
=======================================================================
  GUÍA RÁPIDA — ESCENARIO WIFI 802.11
=======================================================================

PASO 1: Limpiar y lanzar topología
  sudo mn -c
  cd /home/mininet/entornos-tfm/wifi-attacks
  sudo python3 wifi_scenario.py

PASO 2: Verificar conectividad WiFi
  mininet> sta1 ping -c2 10.0.4.100
  mininet> sta1 iw dev sta1-wlan0 link    # Ver AP asociado

PASO 3: Obtener MACs del AP y estaciones
  mininet> sh iw dev | grep addr
  mininet> attacker iw dev | grep addr

PASO 4: Ataque Deauth (desconectar víctima)
  # Monitor de sta1 en otra terminal:
  mininet> sta1 iw event &
  # Lanzar deauth desde atacante:
  mininet> attacker python3 /tmp/deauth_attack.py \
             --bssid <MAC_AP> --client <MAC_STA1>

PASO 5: Evil Twin (AP falso)
  # En otra terminal de mininet:
  mininet> attacker python3 /tmp/evil_twin.py \
             --ssid RedInsegura --iface attacker-wlan1 --phishing
  # Lanzar deauth para forzar reconexión al AP falso:
  mininet> attacker python3 /tmp/deauth_attack.py --bssid <MAC_AP_REAL> \
             --client <MAC_STA1> --continuous

PASO 6: Ataque WEP completo
  mininet> attacker python3 /tmp/wifi_attack.py \
             --bssid <MAC_AP> --channel 6 --client <MAC_STA1>

PASO 7: Salir
  mininet> exit
  sudo mn -c

=======================================================================
EOF

echo "  [OK] Guía rápida en /tmp/wifi_quickstart.txt"
echo ""

if [ "$STATUS_OK" = true ]; then
    echo "======================================================================="
    echo "  INSTALACIÓN COMPLETADA — Entorno listo"
    echo "======================================================================="
else
    echo "======================================================================="
    echo "  INSTALACIÓN COMPLETADA CON ADVERTENCIAS"
    echo "  Revisar los [FAIL] anteriores antes de ejecutar el escenario"
    echo "======================================================================="
fi

echo ""
echo "  Siguiente paso:"
echo "    sudo python3 $SCRIPT_DIR/wifi_scenario.py"
echo ""
