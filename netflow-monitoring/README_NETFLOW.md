# NetFlow Monitoring Scenario

Monitorización completa de tráfico de red usando **NetFlow v5/v9**, **OpenSearch** y **Grafana**.

---

## Arquitectura

```
┌─────────────────────────────── Mininet ────────────────────────────────────┐
│                                                                            │
│  h1 (10.0.3.10)  ─┐                                                        │
│  h2 (10.0.3.20)   │                                                        │
│  h3 (10.0.3.30)   ├──── [s1 OVS] ──── monitor (10.0.3.100)                 │
│  h4 (10.0.3.40)   │        │mirror      softflowd (exporter NetFlow v5)    │
│  h5 (10.0.3.50)  ─┘        │                    │ UDP:2055                 │
│                             └───── collector (10.0.3.200)                  │
│                                    netflow_collector.py                    │
│                                            │ HTTP bulk                     │
└────────────────────────────────────────────┼───────────────────────────────┘
                                             │
                                    10.0.3.254 (host via OVS bridge)
                                             │
                           ┌─────────────────┴───────────────-───┐
                           │           Docker Compose            │
                           │                                     │
                           │  OpenSearch    :9200                │
                           │  Grafana       :3000                │
                           └─────────────────────────────────────┘
```

### Hosts

| Host      | IP           | Rol                                      |
|-----------|--------------|------------------------------------------|
| h1        | 10.0.3.10    | Generador de tráfico                     |
| h2        | 10.0.3.20    | Generador de tráfico                     |
| h3        | 10.0.3.30    | Servidor web (HTTP :80, :8080)           |
| h4        | 10.0.3.40    | Servidor SSH/FTP (sim :22, :21)          |
| h5        | 10.0.3.50    | Servidor DB (sim :3306, :5432, :6379)    |
| monitor   | 10.0.3.100   | Exporter NetFlow (softflowd)             |
| collector | 10.0.3.200   | Colector NetFlow (netflow_collector.py)  |
| host      | 10.0.3.254   | OpenSearch :9200 + Grafana :3000         |

---

## Componentes

### softflowd (Exporter)
- Lee tráfico del interfaz `monitor-eth0` en modo promiscuo
- El switch OVS refleja (mirror) todo el tráfico a ese interfaz
- Exporta registros **NetFlow v5** vía UDP al colector
- Parámetros: `-t maxlife=60` (exporta flows cada 60s máx.)

### netflow_collector.py (Colector)
- Escucha UDP en el puerto 2055
- Parsea NetFlow **v5** y **v9** de forma nativa (sin dependencias externas)
- Muestra flows en tiempo real en terminal
- Indexa a OpenSearch via bulk API en batches de 2s

### traffic_generator.py (Generador)
Modos disponibles:

| Modo         | Descripción                                               |
|--------------|-----------------------------------------------------------|
| `continuous` | Tráfico continuo aleatorio entre todos los patrones       |
| `burst`      | Envío simultáneo a todos los destinos/puertos             |
| `http`       | Peticiones HTTP GET repetidas                             |
| `scan`       | Simulación de port scan (patrón reconocible en flows)     |
| `flood`      | Flood TCP/UDP a un destino concreto                       |
| `mix`        | Mezcla de todos los tipos durante N segundos              |

### OpenSearch
- Índice: `netflow-flows`
- Campos clave: `@timestamp`, `netflow.src_ip`, `netflow.dst_ip`, `netflow.protocol`, `netflow.bytes`, `netflow.packets`, `netflow.dst_port`

### Grafana (Dashboard: *NetFlow — Network Traffic Overview*)
Paneles incluidos:
- **Total Flows / Bytes / Packets / IPs únicos** (KPIs en tiempo real)
- **Flow Rate** (flows/min en serie temporal)
- **Throughput** (bytes/min en serie temporal)
- **Top Source IPs** (tabla con flows y bytes)
- **Top Destination IPs** (tabla)
- **Top Destination Ports / Services** (tabla con nombre de servicio)
- **Protocol Distribution** (donut chart)
- **Traffic by Protocol over time** (stacked time series)
- **TCP Flags Distribution** (pie chart)
- **Bytes per Packet** (gauge)
- **Flows by Exporter** (time series, útil con múltiples exporters)

---

## Instalación y uso rápido

### 1. Instalar dependencias

```bash
cd netflow-monitoring/
sudo bash setup_netflow_scenario.sh
```

El script instala automáticamente:
- `softflowd` (exporter)
- `opensearch-py` Python client (`pip3 install opensearch-py`)
- Docker + Docker Compose
- Lanza OpenSearch y Grafana vía Docker Compose
- Crea el datasource y dashboard en Grafana

### 2. Arrancar el escenario

```bash
sudo python3 netflow_scenario.py
```

### 3. Generar tráfico (dentro de Mininet)

```
mininet> xterm h1 h2
```

En la terminal de h1:
```bash
# Tráfico continuo (recomendado para ver el dashboard)
python3 /tmp/traffic_generator.py --mode continuous

# Burst único (prueba rápida)
python3 /tmp/traffic_generator.py --mode burst

# Port scan simulation
python3 /tmp/traffic_generator.py --mode scan

# Mix 2 minutos
python3 /tmp/traffic_generator.py --mode mix --duration 120
```

Desde la CLI de Mininet también puedes hacer:
```
mininet> h1 ping h3 -c 100 &
mininet> h2 python3 /tmp/traffic_generator.py --mode continuous &
```

### 4. Ver los datos

```
# Logs del colector en tiempo real
mininet> collector tail -f /tmp/netflow_collector.log

# Contar flows indexados en OpenSearch
curl http://localhost:9200/netflow-flows*/_count

# Ver últimos flows indexados
curl "http://localhost:9200/netflow-flows*/_search?size=5&sort=@timestamp:desc&pretty"
```

### 5. Abrir Grafana

URL: **http://localhost:3000**  
Login: `admin` / `admin`  
Dashboard: *NetFlow — Network Traffic Overview*

---

## Verificación y troubleshooting

### softflowd no arranca
```bash
# Verificar instalación
which softflowd && softflowd -h

# Instalar manualmente
sudo apt-get install -y softflowd

# Arrancar manualmente dentro de Mininet
mininet> monitor softflowd -i monitor-eth0 -n 10.0.3.200:2055 -v 5 -t maxlife=30
```

### El colector no recibe flows
```bash
# Verificar puerto mirroring en OVS
sudo ovs-vsctl list Mirror

# Verificar que monitor-eth0 está en modo promiscuo
mininet> monitor ip link show monitor-eth0 | grep PROMISC

# Capturar en el colector para ver si llega tráfico UDP
mininet> collector tcpdump -i collector-eth0 -n udp port 2055
```

### OpenSearch no responde
```bash
# Ver estado del contenedor
docker ps | grep elasticsearch
docker logs netflow-elasticsearch --tail 30

# Verificar health
curl http://localhost:9200/_cluster/health?pretty
```

### Grafana no carga el datasource
```bash
# Re-ejecutar grafana_setup.py
python3 grafana_setup.py --grafana http://localhost:3000 --es http://elasticsearch:9200

# Ver logs de Grafana
docker logs netflow-grafana --tail 30
```

### Reiniciar servicios Docker
```bash
cd netflow-monitoring/
docker compose down && docker compose up -d
```

---

## Extensiones posibles

- **NetFlow v9 / IPFIX**: cambiar `-v 5` por `-v 9` en softflowd para exportar NetFlow v9 (el colector ya lo soporta)
- **Múltiples exporters**: añadir softflowd en h1..h5 para ver el dashboard con varios exporters distinguibles
- **Alertas Grafana**: crear alertas cuando `bytes/min > umbral` o cuando aparece un protocolo inesperado
- **GeoIP**: enriquecer IPs con geolocalización usando el pipeline de ingest de OpenSearch
- **Detección de anomalías**: correlacionar flows con patrones de port scan (picos en `dst_port` único con `src_ip` único)

---

## Conceptos de NetFlow

**NetFlow** es un protocolo de Cisco (RFC 3954 para v9) que registra metadatos de flujos IP:
- Un **flow** = conjunto de paquetes con misma 5-tupla (src_ip, dst_ip, src_port, dst_port, protocol)
- El **exporter** (softflowd) genera los registros a partir del tráfico observado
- El **colector** recibe y almacena los registros UDP
- No captura el payload (a diferencia de tcpdump) → privacidad + rendimiento

**NetFlow v5**: registros de tamaño fijo (48 bytes/flow), solo IPv4.  
**NetFlow v9**: basado en plantillas, extensible, soporta IPv6, MPLS, VLAN.  
**IPFIX** (RFC 7011): estándar IETF basado en NetFlow v9.

**Autor:** Mario Gil Martinez