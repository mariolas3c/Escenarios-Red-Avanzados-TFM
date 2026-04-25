#!/bin/bash
# =============================================================================
# Script de instalacion para el escenario SDN + Ryu + OpenFlow
# =============================================================================

set -e

echo "======================================================================="
echo "  CONFIGURACION DEL ESCENARIO SDN + RYU + OPENFLOW 1.3"
echo "======================================================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Ejecutar como root: sudo ./setup_sdn_scenario.sh"
    exit 1
fi

# --------------------------------------------------------------------------
echo "[1/5] Actualizando repositorios..."
apt-get update -qq
echo "  [OK] Repositorios actualizados"

# --------------------------------------------------------------------------
echo ""
echo "[2/5] Instalando dependencias del sistema..."

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

install_if_missing python3-pip pip3
install_if_missing python3-scapy
install_if_missing curl
install_if_missing nmap
install_if_missing tcpdump
install_if_missing netcat-openbsd nc

# --------------------------------------------------------------------------
echo ""
echo "[3/5] Instalando Ryu SDN Framework..."

if command -v ryu-manager &>/dev/null; then
    RYU_VER=$(python3 -c "import ryu; print(ryu.__version__)" 2>/dev/null || echo "instalado")
    echo "  [OK] Ryu ya instalado: $RYU_VER"
else
    echo "  Instalando Ryu y dependencias..."

    # Ryu requiere eventlet con version compatible
    pip3 install "eventlet==0.30.2" --quiet 2>/dev/null || pip3 install eventlet --quiet

    # Dependencias de Ryu para REST API
    pip3 install webob --quiet 2>/dev/null || true
    pip3 install routes --quiet 2>/dev/null || true

    # Instalar Ryu
    if pip3 install ryu --quiet 2>/dev/null; then
        echo "  [OK] Ryu instalado"
    else
        echo ""
        echo "  [WARN] pip3 install ryu fallo. Intentando alternativas..."
        pip3 install ryu 2>&1 | tail -5
        echo ""
        echo "  [INFO] Si el error persiste, intentar:"
        echo "         pip3 install eventlet==0.30.2 && pip3 install ryu"
        echo "  El escenario requiere Ryu para funcionar."
    fi
fi

# Verificar instalacion de Ryu
if ! command -v ryu-manager &>/dev/null; then
    echo "  [WARN] ryu-manager no encontrado en PATH"
    echo "  [INFO] Puede estar en: ~/.local/bin/ryu-manager"
    echo "  [INFO] Añadir al PATH: export PATH=\$HOME/.local/bin:\$PATH"
fi

# --------------------------------------------------------------------------
echo ""
echo "[4/5] Verificando Mininet y Open vSwitch..."

if command -v mn &>/dev/null; then
    echo "  [OK] mininet instalado"
else
    echo "  [INSTALANDO] mininet..."
    apt-get install -y mininet -qq
fi

if command -v ovs-vsctl &>/dev/null; then
    echo "  [OK] openvswitch instalado"
else
    echo "  [INSTALANDO] openvswitch-switch..."
    apt-get install -y openvswitch-switch -qq
fi

# --------------------------------------------------------------------------
echo ""
echo "[5/5] Preparando scripts y guia rapida..."

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

for script in ryu_controller.py sdn_demo.py; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        cp "$SCRIPT_DIR/$script" /tmp/
        chmod +x "/tmp/$script"
        echo "  [OK] $script -> /tmp/"
    else
        echo "  [WARN] $script no encontrado en $SCRIPT_DIR"
    fi
done

cat > /tmp/sdn_quickstart.txt << 'EOF'
==========================================================
GUIA RAPIDA - ESCENARIO SDN + RYU + OPENFLOW 1.3
==========================================================

TOPOLOGIA:
  cliente1  10.0.0.10   (usuario normal)
  cliente2  10.0.0.20   (segundo usuario)
  atacante  10.0.0.30   (host sospechoso)
  servidor  10.0.0.100  (HTTP:80, FTP:21, SSH:22, 8080)
  s1        OVS (OpenFlow 1.3) -> Ryu @ 127.0.0.1:6633

REST API: http://127.0.0.1:8080

PASO 1: Iniciar escenario
  sudo python3 sdn_scenario.py

PASO 2: Verificar conectividad
  mininet> pingall
  mininet> cliente1 curl http://10.0.0.100

PASO 3: Ver estado del controlador
  mininet> sh curl -s http://127.0.0.1:8080/sdn/topology | python3 -m json.tool
  mininet> sh curl -s http://127.0.0.1:8080/sdn/stats    | python3 -m json.tool

PASO 4: Firewall dinamico (bloquear flujo)
  mininet> sh curl -X POST http://127.0.0.1:8080/sdn/firewall/rules \
    -H 'Content-Type: application/json' \
    -d '{"src_ip":"10.0.0.30","dst_ip":"10.0.0.100","protocol":"tcp","dst_port":80,"action":"block"}'

  mininet> atacante curl http://10.0.0.100   # debe fallar
  mininet> cliente1 curl http://10.0.0.100   # sigue funcionando

PASO 5: Bloqueo completo de IP
  mininet> sh curl -X POST http://127.0.0.1:8080/sdn/block/10.0.0.30
  mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200

  # Desbloquear:
  mininet> sh curl -X DELETE http://127.0.0.1:8080/sdn/block/10.0.0.30

PASO 6: Deteccion automatica de port scan
  mininet> atacante python3 /tmp/sdn_demo.py --mode portscan --target 10.0.0.100
  mininet> sh tail -10 /tmp/ryu_controller.log

PASO 7: Demo automatica completa
  mininet> sh python3 /tmp/sdn_demo.py --mode demo

LOGS:
  tail -f /tmp/ryu_controller.log

FLUJOS OVS:
  ovs-ofctl -O OpenFlow13 dump-flows s1

==========================================================
EOF

echo "  [OK] Guia en /tmp/sdn_quickstart.txt"

# --------------------------------------------------------------------------
echo ""
echo "======================================================================="
echo "  INSTALACION COMPLETADA"
echo "======================================================================="
echo ""
echo "Herramientas verificadas:"
command -v ryu-manager &>/dev/null && echo "  [OK] ryu-manager" || echo "  [--] ryu-manager (REQUERIDO)"
command -v mn          &>/dev/null && echo "  [OK] mininet"     || echo "  [--] mininet"
command -v ovs-vsctl   &>/dev/null && echo "  [OK] openvswitch" || echo "  [--] openvswitch"
command -v nmap        &>/dev/null && echo "  [OK] nmap"        || echo "  [--] nmap (opcional)"
command -v curl        &>/dev/null && echo "  [OK] curl"        || echo "  [--] curl"
echo ""
echo "Para iniciar el escenario:"
echo "  sudo python3 sdn_scenario.py"
echo ""
echo "Guia rapida:"
echo "  cat /tmp/sdn_quickstart.txt"
echo ""
echo "======================================================================="
