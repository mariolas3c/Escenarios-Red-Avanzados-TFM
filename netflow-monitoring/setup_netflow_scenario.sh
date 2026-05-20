#!/bin/bash
# =============================================================================
#  Setup Script — NetFlow Monitoring Scenario
#  Instala dependencias, arranca servicios Docker y prepara el entorno.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC}  $1"; }
info() { echo -e "      $1"; }

echo "======================================================================="
echo "  SETUP: NETFLOW MONITORING SCENARIO"
echo "======================================================================="
echo

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Este script necesita ejecutarse como root (sudo)."
    exit 1
fi

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/6] Instalando paquetes del sistema..."

apt-get update -qq

install_pkg() {
    if dpkg -l "$1" &>/dev/null; then
        ok "$1 ya instalado"
    else
        info "Instalando $1..."
        apt-get install -y -qq "$1" && ok "$1 instalado" || warn "No se pudo instalar $1"
    fi
}

install_pkg softflowd
install_pkg python3-pip
install_pkg curl
install_pkg netcat-openbsd
install_pkg iproute2

# ── 2. Python dependencies ────────────────────────────────────────────────────
echo
echo "[2/6] Instalando dependencias Python..."

pip3_install() {
    if python3 -c "import $1" &>/dev/null 2>&1; then
        ok "python3: $1 disponible"
    else
        info "Instalando $1 via pip3..."
        pip3 install --quiet "$2" && ok "pip3: $2 instalado" || warn "No se pudo instalar $2"
    fi
}

pip3_install opensearchpy opensearch-py
pip3_install mininet    mininet      2>/dev/null || true   # ya debería estar instalado

# ── 3. Docker ─────────────────────────────────────────────────────────────────
echo
echo "[3/6] Verificando Docker..."

install_docker=false

if ! command -v docker &>/dev/null; then
    warn "Docker no instalado — instalando docker.io..."
    apt-get install -y -qq docker.io && ok "docker.io instalado" || {
        err "No se pudo instalar Docker. Instálalo manualmente."
        install_docker=false
    }
fi

# Check docker compose (v2 plugin or v1 standalone)
if docker compose version &>/dev/null 2>&1; then
    ok "docker compose (v2) disponible"
elif command -v docker-compose &>/dev/null; then
    ok "docker-compose (v1) disponible"
else
    warn "docker-compose no encontrado — instalando..."
    apt-get install -y -qq docker-compose && ok "docker-compose instalado" || {
        warn "No se pudo instalar docker-compose. Instalando docker-compose-plugin..."
        apt-get install -y -qq docker-compose-plugin 2>/dev/null || true
    }
fi

# Ensure Docker daemon is running
if ! systemctl is-active --quiet docker; then
    info "Iniciando servicio Docker..."
    systemctl start docker && ok "Docker daemon iniciado"
fi

# ── 4. Start Docker services ──────────────────────────────────────────────────
echo
echo "[4/6] Iniciando OpenSearch + Grafana (Docker Compose)..."

cd "$SCRIPT_DIR"

if docker compose version &>/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Pull images (ignore errors — they'll be pulled on first run)
info "Descargando imágenes Docker (puede tardar en la primera ejecución)..."
$COMPOSE_CMD pull 2>&1 | grep -E "Pull|pull|already|Pulling" || true

$COMPOSE_CMD up -d 2>&1
ok "Contenedores iniciados"

# Wait for OpenSearch
info "Esperando OpenSearch (hasta 90s)..."
for i in $(seq 1 45); do
    if curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        ok "OpenSearch listo (${i}s)"
        break
    fi
    sleep 2
    if [[ $i -eq 45 ]]; then
        warn "OpenSearch no respondió a tiempo. Comprueba: docker logs netflow-opensearch"
    fi
done

# Wait for Grafana
info "Esperando Grafana (hasta 60s)..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:3000/api/health 2>/dev/null | grep -q '"database":"ok"'; then
        ok "Grafana listo (${i}s)"
        break
    fi
    sleep 2
done

# ── 5. Configure Grafana ──────────────────────────────────────────────────────
echo
echo "[5/6] Configurando Grafana (datasource + dashboard)..."

sleep 3
python3 "$SCRIPT_DIR/grafana_setup.py" \
    --grafana http://localhost:3000 \
    --es http://opensearch:9200 \
    2>&1 | grep -E "OK|ERR|WARN|ready|Dashboard|datasource|Grafana" || true

# ── 6. Copy scripts + quickstart ──────────────────────────────────────────────
echo
echo "[6/6] Copiando scripts y creando guía rápida..."

for script in netflow_scenario.py netflow_collector.py traffic_generator.py grafana_setup.py; do
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        cp "$SCRIPT_DIR/$script" "/tmp/$script"
        chmod +x "/tmp/$script"
        ok "Copiado: /tmp/$script"
    fi
done

cat > /tmp/netflow_quickstart.txt << 'QUICKSTART'
═══════════════════════════════════════════════════════════════════════
  NETFLOW MONITORING — GUÍA RÁPIDA
═══════════════════════════════════════════════════════════════════════

ARRANCAR EL ESCENARIO:
  sudo python3 netflow_scenario.py

DENTRO DE MININET (xterm o comandos directos):

  1. Generar tráfico desde h1:
     mininet> xterm h1
     h1> python3 /tmp/traffic_generator.py --mode continuous
     h1> python3 /tmp/traffic_generator.py --mode burst
     h1> python3 /tmp/traffic_generator.py --mode scan
     h1> python3 /tmp/traffic_generator.py --mode mix --duration 120

  2. Generar tráfico mixto desde varios hosts:
     mininet> h1 python3 /tmp/traffic_generator.py --mode burst &
     mininet> h2 python3 /tmp/traffic_generator.py --mode continuous &

  3. Ver NetFlow en tiempo real:
     mininet> collector tail -f /tmp/netflow_collector.log

  4. Verificar que softflowd exporta:
     mininet> monitor cat /tmp/softflowd.log

  5. Reiniciar colector sin OpenSearch (solo terminal):
     mininet> collector pkill -f netflow_collector
     mininet> collector python3 /tmp/netflow_collector.py --no-es

GRAFANA:
  URL     : http://localhost:3000
  Login   : admin / password
  Dashboard: NetFlow — Network Traffic Overview (auto-refresh 30s)

OPENSEARCH:
  URL     : http://localhost:9200
  Index   : netflow-flows*
  Cluster : curl http://localhost:9200/_cluster/health
  Flows   : curl http://localhost:9200/netflow-flows*/_count

COMANDOS ÚTILES:
  # Estadísticas del exporter:
  sudo softflowd -c /tmp/softflowd.pid show all

  # Parar servicios Docker:
  docker compose -f netflow-monitoring/docker-compose.yml down

  # Borrar datos de OpenSearch:
  curl -X DELETE http://localhost:9200/netflow-flows*

ARQUITECTURA:
  h1..h5 (generadores) → [s1 OVS] → mirror → monitor (softflowd)
                                                     │ NetFlow v5 UDP:2055
                                               collector (netflow_collector.py)
                                                     │ HTTP bulk
                                               OpenSearch :9200
                                                     │
                                               Grafana :3000

═══════════════════════════════════════════════════════════════════════
QUICKSTART

ok "Guía creada: /tmp/netflow_quickstart.txt"
cat /tmp/netflow_quickstart.txt

echo
echo "======================================================================="
echo "  SETUP COMPLETADO"
echo "======================================================================="
echo
ok "softflowd instalado (exporter NetFlow v5)"
ok "opensearch-py instalado (Python client)"
ok "OpenSearch en http://localhost:9200"
ok "Grafana en http://localhost:3000 (admin/password)"
ok "Scripts copiados a /tmp/"
echo
info "Siguiente paso:"
info "  sudo python3 ${SCRIPT_DIR}/netflow_scenario.py"
echo
