#!/bin/bash
# =============================================================================
# Script de instalacion para el escenario BGP Hijacking + FRR
# =============================================================================

set -e

echo "======================================================================="
echo "  CONFIGURACION DEL ESCENARIO BGP HIJACKING + FRR"
echo "======================================================================="
echo ""

# Verificar root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Este script debe ejecutarse como root."
    echo "        sudo ./setup_bgp_scenario.sh"
    exit 1
fi

# --------------------------------------------------------------------------
echo "[1/6] Actualizando repositorios..."
apt-get update -qq
echo "  [OK] Repositorios actualizados"

# --------------------------------------------------------------------------
echo ""
echo "[2/6] Instalando herramientas auxiliares..."

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

install_if_missing tcpdump
install_if_missing tshark
install_if_missing curl
install_if_missing python3-scapy python3

# Verificar Scapy
if python3 -c "from scapy.contrib import bgp" 2>/dev/null; then
    echo "  [OK] Scapy + contrib BGP disponibles"
else
    echo "  [WARN] scapy.contrib.bgp no disponible (no critico para FRR)"
fi

# --------------------------------------------------------------------------
echo ""
echo "[3/6] Instalando FRR (Free Range Routing)..."

# FRR instala los daemons en /usr/lib/frr/ en Ubuntu/Debian (fuera del PATH)
find_frr_bin() {
    local name=$1
    for path in /usr/lib/frr/$name /usr/sbin/$name /usr/bin/$name; do
        [ -x "$path" ] && { echo "$path"; return 0; }
    done
    return 1
}

ZEBRA_BIN=$(find_frr_bin zebra || true)
BGPD_BIN=$(find_frr_bin bgpd || true)

if command -v vtysh &>/dev/null && [ -n "$ZEBRA_BIN" ] && [ -n "$BGPD_BIN" ]; then
    FRR_VER=$("$BGPD_BIN" --version 2>&1 | head -1 || echo "instalado")
    echo "  [OK] FRR ya instalado: $FRR_VER"
    echo "  [OK] zebra: $ZEBRA_BIN"
    echo "  [OK] bgpd:  $BGPD_BIN"
else
    echo "  Instalando paquete frr desde repositorios oficiales..."
    apt-get install -y frr frr-pythontools -qq || {
        echo "  [WARN] frr no disponible en repos por defecto."
        echo "  [INFO] Anadir repositorio oficial FRR:"
        echo "         curl -s https://deb.frrouting.org/frr/keys.asc | apt-key add -"
        echo "         echo 'deb https://deb.frrouting.org/frr \$(lsb_release -s -c) frr-stable' \\"
        echo "             > /etc/apt/sources.list.d/frr.list"
        echo "         apt-get update && apt-get install frr frr-pythontools"
        exit 1
    }
    ZEBRA_BIN=$(find_frr_bin zebra || true)
    BGPD_BIN=$(find_frr_bin bgpd || true)
    echo "  [OK] FRR instalado"
    [ -n "$ZEBRA_BIN" ] && echo "  [OK] zebra: $ZEBRA_BIN"
    [ -n "$BGPD_BIN" ]  && echo "  [OK] bgpd:  $BGPD_BIN"
fi

# --------------------------------------------------------------------------
echo ""
echo "[4/6] Desactivando servicio frr del host (evita conflicto con namespaces)..."

if systemctl is-active --quiet frr 2>/dev/null; then
    systemctl stop frr || true
    echo "  [OK] frr.service detenido"
fi

if systemctl is-enabled --quiet frr 2>/dev/null; then
    systemctl disable frr || true
    echo "  [OK] frr.service deshabilitado al arranque"
else
    echo "  [OK] frr.service ya estaba deshabilitado"
fi

# FRR 7.x comprueba pertenencia al grupo frrvty incluso si se ejecuta como root.
# El escenario usa --skip_runas para saltarse esto, pero anadimos root al grupo
# como respaldo por si alguna build ignora ese flag.
if getent group frrvty >/dev/null; then
    if ! id -nG root | grep -qw frrvty; then
        usermod -aG frrvty root || true
        echo "  [OK] usuario root anadido al grupo frrvty"
    else
        echo "  [OK] root ya pertenece al grupo frrvty"
    fi
fi

# AppArmor: permitir que FRR lea/escriba en /tmp/r*
if command -v aa-complain &>/dev/null; then
    echo "  Configurando AppArmor en modo complain para zebra/bgpd..."
    aa-complain /usr/lib/frr/zebra  2>/dev/null || true
    aa-complain /usr/lib/frr/bgpd   2>/dev/null || true
    echo "  [OK] AppArmor en complain mode para FRR"
elif [ -d /etc/apparmor.d ]; then
    echo "  [WARN] aa-complain no disponible; instalando apparmor-utils..."
    apt-get install -y apparmor-utils -qq || true
    aa-complain /usr/lib/frr/zebra  2>/dev/null || true
    aa-complain /usr/lib/frr/bgpd   2>/dev/null || true
else
    echo "  [OK] AppArmor no presente (no aplica)"
fi

# --------------------------------------------------------------------------
echo ""
echo "[5/6] Copiando scripts al directorio /tmp..."

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

for script in bgp_hijack_attack.py; do
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
echo "[6/6] Creando guia de uso rapido..."

cat > /tmp/bgp_quickstart.txt << 'EOF'
==========================================================
GUIA RAPIDA - ESCENARIO BGP HIJACKING + FRR
==========================================================

TOPOLOGIA (4 sistemas autonomos en malla eBGP via IXP 100.64.0.0/24):

  AS65001 r1 100.64.0.1  + LAN 10.0.10.1   -> h_victima  10.0.10.10
  AS65002 r2 100.64.0.2  (transito, sin host)
  AS65003 r3 100.64.0.3  + LAN 10.0.30.1   -> h_atacante 10.0.30.10
  AS65004 r4 100.64.0.4  + LAN 10.0.40.1   -> h_cliente  10.0.40.10
  monitor    100.64.0.100  (port mirror del IXP)

PASO 1: Iniciar la topologia
  sudo python3 bgp_scenario.py

PASO 2: Verificar peerings BGP
  mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp summary"
  # Los 3 vecinos deben estar Established

PASO 3: Trafico legitimo (antes del hijack)
  mininet> h_cliente curl -s http://10.0.10.10
  # Debe responder con "Servidor LEGITIMO AS65001"

PASO 4: Lanzar prefix-hijack (mismo prefijo)
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode prefix-hijack

PASO 5: Verificar redireccion
  mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp 10.0.10.0/24"
  mininet> h_cliente curl -s http://10.0.10.10
  # Debe responder con "!!! HIJACKED por AS65003 !!!"

PASO 6: Sub-prefix hijack (longest-prefix match siempre gana)
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode subprefix-hijack

PASO 7: Inspeccion de mensajes BGP UPDATE
  mininet> monitor tshark -i monitor-eth0 -Y bgp -O bgp -c 20

PASO 8: Defensa con prefix-list
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode defend

PASO 9: Retirar el hijack
  mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode withdraw

LOGS:
  /tmp/r1/bgpd.log    /tmp/r1/zebra.log   (igual para r2, r3, r4)
  /tmp/victima_http.log   /tmp/atacante_http.log

LIMPIEZA (entre ejecuciones):
  sudo mn -c
  sudo pkill -9 bgpd zebra
  sudo rm -rf /tmp/r1 /tmp/r2 /tmp/r3 /tmp/r4
==========================================================
EOF

echo "  [OK] Guia en /tmp/bgp_quickstart.txt"

# --------------------------------------------------------------------------
echo ""
echo "======================================================================="
echo "  INSTALACION COMPLETADA"
echo "======================================================================="
echo ""
ZEBRA_BIN=$(find_frr_bin zebra || true)
BGPD_BIN=$(find_frr_bin bgpd || true)
echo "Herramientas verificadas:"
command -v vtysh   &>/dev/null && echo "  [OK] vtysh"        || echo "  [--] vtysh (REQUERIDO)"
[ -n "$BGPD_BIN"  ]            && echo "  [OK] bgpd ($BGPD_BIN)"   || echo "  [--] bgpd (REQUERIDO)"
[ -n "$ZEBRA_BIN" ]            && echo "  [OK] zebra ($ZEBRA_BIN)" || echo "  [--] zebra (REQUERIDO)"
command -v tshark  &>/dev/null && echo "  [OK] tshark"       || echo "  [--] tshark"
command -v tcpdump &>/dev/null && echo "  [OK] tcpdump"      || echo "  [--] tcpdump"
if [ -n "$BGPD_BIN" ]; then
    FRR_VER=$("$BGPD_BIN" --version 2>&1 | head -1)
    echo "  Version FRR: $FRR_VER"
fi
echo ""
echo "Para iniciar el escenario:"
echo "  sudo mn -c"
echo "  sudo python3 bgp_scenario.py"
echo ""
echo "Ver guia rapida:"
echo "  cat /tmp/bgp_quickstart.txt"
echo ""
echo "======================================================================="
