#!/bin/bash
# Script de instalacion para el escenario WAF + ModSecurity (Flask + Nginx)

set -e

echo "======================================================================="
echo "  CONFIGURACION DEL ESCENARIO WAF + MODSECURITY"
echo "  Aplicacion Flask protegida por Nginx + ModSecurity (simulado)"
echo "======================================================================="

# Comprobar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "[ERROR] Este script debe ejecutarse como root."
    echo "        Usa: sudo bash setup_waf_scenario.sh"
    exit 1
fi

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

# -----------------------------------------------------------------------
echo ""
echo "[1/6] Actualizando repositorios..."
apt-get update -qq
echo "  [OK] Repositorios actualizados"

# -----------------------------------------------------------------------
echo ""
echo "[2/6] Instalando dependencias del sistema..."

install_if_missing() {
    local pkg=$1
    local bin=${2:-$1}
    if command -v "$bin" &>/dev/null; then
        echo "  [OK] $pkg ya instalado"
    else
        echo "  [INSTALANDO] $pkg..."
        apt-get install -y "$pkg" -qq 2>/dev/null
        echo "  [OK] $pkg instalado"
    fi
}

install_if_missing python3        "python3"
install_if_missing python3-pip    "pip3"
install_if_missing curl           "curl"
install_if_missing wget           "wget"
install_if_missing net-tools      "ifconfig"
install_if_missing iproute2       "ss"
install_if_missing openvswitch-switch "ovs-vsctl"

# -----------------------------------------------------------------------
echo ""
echo "[3/6] Instalando librerias Python..."

install_python_pkg() {
    local pkg=$1
    local import_name=${2:-$1}
    if python3 -c "import $import_name" &>/dev/null; then
        echo "  [OK] $pkg ya disponible"
    else
        echo "  [INSTALANDO] $pkg..."
        pip3 install "$pkg" -q 2>/dev/null || apt-get install -y "python3-$pkg" -qq 2>/dev/null || true
        if python3 -c "import $import_name" &>/dev/null; then
            echo "  [OK] $pkg instalado"
        else
            echo "  [WARN] $pkg no pudo instalarse (el escenario usara fallback)"
        fi
    fi
}

install_python_pkg "flask"   "flask"

# Verificar mininet
if python3 -c "from mininet.net import Mininet" &>/dev/null; then
    echo "  [OK] mininet disponible"
else
    echo "  [WARN] mininet no encontrado. Instalando..."
    apt-get install -y mininet -qq 2>/dev/null || true
fi

# -----------------------------------------------------------------------
echo ""
echo "[4/6] Copiando scripts al directorio /tmp/..."

SCRIPTS=(
    "waf_scenario.py"
    "flask_app.py"
    "waf_proxy.py"
    "web_attacker.py"
    "waf_monitor.py"
)

for script in "${SCRIPTS[@]}"; do
    if [ -f "$SCRIPT_DIR/$script" ]; then
        cp "$SCRIPT_DIR/$script" /tmp/
        chmod +x "/tmp/$script"
        echo "  [OK] $script -> /tmp/"
    else
        echo "  [WARN] $script no encontrado en $SCRIPT_DIR"
    fi
done

# -----------------------------------------------------------------------
echo ""
echo "[5/6] Limpiando instancias previas de Mininet..."
mn -c > /dev/null 2>&1 || true
pkill -f waf_proxy.py  2>/dev/null || true
pkill -f flask_app.py  2>/dev/null || true
pkill -f waf_monitor.py 2>/dev/null || true
echo "  [OK] Entorno limpiado"

# -----------------------------------------------------------------------
echo ""
echo "[6/6] Creando guia de uso rapido..."

cat > /tmp/waf_quickstart.txt << 'EOF'
==========================================================================
GUIA RAPIDA - ESCENARIO WAF + MODSECURITY (Flask + Nginx)
==========================================================================

TOPOLOGIA:
  10.0.2.10   cliente    - Usuario legitimo
  10.0.2.20   atacante   - Atacante web
  10.0.2.80   waf        - Proxy WAF: Nginx + ModSecurity (:80)
  10.0.2.90   webserver  - Backend Flask vulnerable (:5000)
  10.0.2.100  monitor    - Analizador de logs WAF

PASO 1 - Iniciar el escenario
  sudo python3 waf_scenario.py

PASO 2 - Verificar conectividad
  mininet> pingall
  mininet> cliente curl http://10.0.2.80/

PASO 3 - Peticiones legitimas (deben PASAR el WAF)
  mininet> cliente curl "http://10.0.2.80/buscar?q=python+tutorial"
  mininet> cliente curl -X POST http://10.0.2.80/login -d "user=admin&pass=admin123"

PASO 4 - Ataques (deben ser BLOQUEADOS por el WAF)
  mininet> atacante curl "http://10.0.2.80/login?user=admin'+OR+'1'='1"
  mininet> atacante curl "http://10.0.2.80/buscar?q=<script>alert(1)</script>"
  mininet> atacante curl "http://10.0.2.80/archivo?f=../../../etc/passwd"
  mininet> atacante curl "http://10.0.2.80/ping?host=127.0.0.1;id"

PASO 5 - Comparar SIN WAF (mismo ataque al backend directo)
  mininet> atacante curl "http://10.0.2.90:5000/login?user=admin'+OR+'1'='1"

PASO 6 - Script automatizado de ataques
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --all
  mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.90 --port 5000 --all

PASO 7 - Ver logs del WAF
  mininet> sh cat /tmp/waf_attack_log.txt
  mininet> sh tail -f /tmp/waf_attack_log.txt

LOGS GENERADOS:
  /tmp/flask_app.log       - Backend Flask
  /tmp/waf_proxy.log       - Proxy WAF
  /tmp/waf_attack_log.txt  - Ataques bloqueados
  /tmp/waf_access_log.txt  - Accesos permitidos
==========================================================================
EOF

echo "  [OK] Guia en /tmp/waf_quickstart.txt"

# -----------------------------------------------------------------------
echo ""
echo "======================================================================="
echo "  INSTALACION COMPLETADA"
echo "======================================================================="
echo ""
echo "  Herramientas verificadas:"
command -v python3   &>/dev/null && echo "  [OK] python3"   || echo "  [--] python3"
command -v curl      &>/dev/null && echo "  [OK] curl"      || echo "  [--] curl"
command -v ovs-vsctl &>/dev/null && echo "  [OK] openvswitch" || echo "  [--] openvswitch"
python3 -c "from mininet.net import Mininet" &>/dev/null \
    && echo "  [OK] mininet" || echo "  [--] mininet"
python3 -c "import flask" &>/dev/null \
    && echo "  [OK] flask"   || echo "  [--] flask (se usara fallback http.server)"
echo ""
echo "  Para iniciar el escenario:"
echo "    cd $(realpath "$SCRIPT_DIR")"
echo "    sudo python3 waf_scenario.py"
echo ""
echo "  Guia rapida: cat /tmp/waf_quickstart.txt"
echo ""
