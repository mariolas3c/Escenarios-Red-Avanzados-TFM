#!/bin/bash
# =============================================================================
# Script de instalacion para el escenario Port Scanning + Suricata
# =============================================================================

set -e

echo "======================================================================="
echo "  CONFIGURACION DEL ESCENARIO PORT SCANNING + SURICATA"
echo "======================================================================="
echo ""

# Verificar root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Este script debe ejecutarse como root."
    echo "        sudo ./setup_portscan_scenario.sh"
    exit 1
fi

# --------------------------------------------------------------------------
echo "[1/5] Actualizando repositorios..."
apt-get update -qq
echo "  [OK] Repositorios actualizados"

# --------------------------------------------------------------------------
echo ""
echo "[2/5] Instalando herramientas de red..."

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

install_if_missing nmap
install_if_missing hping3
install_if_missing tcpdump
install_if_missing netcat-openbsd nc
install_if_missing python3-scapy python3

# Verificar scapy de Python
if python3 -c "from scapy.all import IP, TCP" 2>/dev/null; then
    echo "  [OK] Python3 Scapy disponible"
else
    echo "  [INSTALANDO] python3-scapy..."
    apt-get install -y python3-scapy -qq
fi

# --------------------------------------------------------------------------
echo ""
echo "[3/5] Instalando Suricata..."

if command -v suricata &>/dev/null; then
    SURICATA_VER=$(suricata --build-info 2>/dev/null | grep "Version" | head -1 || echo "instalado")
    echo "  [OK] Suricata ya instalado: $SURICATA_VER"
else
    echo "  Agregando repositorio OISF (Suricata oficial)..."

    # Dependencias para el PPA
    apt-get install -y software-properties-common -qq

    # Agregar PPA de OISF
    add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || {
        echo "  [WARN] No se pudo agregar el PPA OISF. Intentando repositorio principal..."
    }

    apt-get update -qq

    if apt-cache show suricata &>/dev/null; then
        apt-get install -y suricata
        echo "  [OK] Suricata instalado"
    else
        echo "  [ERROR] Suricata no disponible en los repositorios."
        echo "  [INFO]  Instalacion manual:"
        echo "          1. add-apt-repository ppa:oisf/suricata-stable"
        echo "          2. apt-get update && apt-get install suricata"
        echo "  El escenario continuara pero sin deteccion IDS."
    fi
fi

# --------------------------------------------------------------------------
echo ""
echo "[4/5] Copiando scripts al directorio /tmp..."

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

for script in port_scan_attack.py; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        cp "$SCRIPT_DIR/$script" /tmp/
        chmod +x "/tmp/$script"
        echo "  [OK] $script -> /tmp/"
    else
        echo "  [WARN] No se encontro $script en $SCRIPT_DIR"
    fi
done

# --------------------------------------------------------------------------
echo ""
echo "[5/5] Creando guia de uso rapido..."

cat > /tmp/portscan_quickstart.txt << 'EOF'
==========================================================
GUIA RAPIDA - ESCENARIO PORT SCANNING + SURICATA
==========================================================

TOPOLOGIA:
  victim   10.0.1.10  (servicios abiertos: 21,22,23,25,80,3306,8080)
  attacker 10.0.1.20  (realiza escaneos)
  monitor  10.0.1.100 (Suricata IDS)

PASO 1: Iniciar la topologia
  sudo python3 port_scan_scenario.py

PASO 2: Verificar conectividad
  mininet> victim ping -c2 10.0.1.20
  mininet> attacker curl http://10.0.1.10

PASO 3: Monitorear alertas Suricata (en monitor)
  mininet> monitor tail -f /tmp/suricata-logs/fast.log

PASO 4: Ejecutar escaneos (desde attacker)

  === CON SCRIPT SCAPY ===
  mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan syn
  mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan fin
  mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan xmas
  mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan null
  mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan all

  === CON NMAP (si esta instalado) ===
  mininet> attacker nmap -sS 10.0.1.10          # SYN Scan
  mininet> attacker nmap -sF 10.0.1.10          # FIN Scan
  mininet> attacker nmap -sX 10.0.1.10          # XMAS Scan
  mininet> attacker nmap -sN 10.0.1.10          # NULL Scan
  mininet> attacker nmap -sA 10.0.1.10          # ACK Scan
  mininet> attacker nmap -sU --top-ports 20 10.0.1.10  # UDP Scan
  mininet> attacker nmap -A  10.0.1.10          # Agresivo

PASO 5: Ver deteccion
  mininet> monitor cat /tmp/suricata-logs/fast.log
  mininet> monitor grep SCAN /tmp/suricata-logs/fast.log | wc -l

PASO 6: Ver estado de Suricata
  mininet> monitor cat /tmp/suricata.pid
  mininet> monitor kill -USR2 $(cat /tmp/suricata.pid)

LOGS:
  /tmp/suricata-logs/fast.log    Alertas en texto
  /tmp/suricata-logs/eve.json    Alertas en JSON
  /tmp/suricata-logs/suricata.log Log del motor
==========================================================
EOF

echo "  [OK] Guia en /tmp/portscan_quickstart.txt"

# --------------------------------------------------------------------------
echo ""
echo "======================================================================="
echo "  INSTALACION COMPLETADA"
echo "======================================================================="
echo ""
echo "Herramientas verificadas:"
command -v nmap &>/dev/null      && echo "  [OK] nmap"      || echo "  [--] nmap (no instalado)"
command -v hping3 &>/dev/null    && echo "  [OK] hping3"    || echo "  [--] hping3"
command -v suricata &>/dev/null  && echo "  [OK] suricata"  || echo "  [--] suricata (REQUERIDO para IDS)"
command -v tcpdump &>/dev/null   && echo "  [OK] tcpdump"   || echo "  [--] tcpdump"
echo ""
echo "Para iniciar el escenario:"
echo "  sudo python3 port_scan_scenario.py"
echo ""
echo "Ver guia rapida:"
echo "  cat /tmp/portscan_quickstart.txt"
echo ""
echo "======================================================================="
