# Escenario SDN con Controlador Ryu + OpenFlow 1.3

## Descripción General

Este escenario implementa una demostración completa de redes definidas por software (SDN):

- **Controlador Ryu** con OpenFlow 1.3 que gestiona un switch OVS
- **L2 switch con aprendizaje de MACs** en el plano de control
- **Firewall dinámico** gestionado en tiempo real via REST API (sin reconfigurar hardware)
- **Bloqueo de IP** con reglas DROP instaladas directamente en el plano de datos del switch
- **Estadísticas de flujo** OpenFlow consultables via REST
- **Detección automática de port scans** con bloqueo automático del atacante

El objetivo es demostrar la separación entre **plano de control** (Ryu) y **plano de datos** (OVS), y cómo SDN permite aplicar políticas de red de forma centralizada y programática.

---

## Topología de Red

```
         ┌──────────────────────────────┐
         │   Controlador Ryu            │
         │   OpenFlow: 127.0.0.1:6633   │
         │   REST API: 127.0.0.1:8080   │
         └──────────────┬───────────────┘
                        │ OpenFlow 1.3
              ┌─────────┴─────────┐
              │    Switch s1      │
              │ (OVS + OF 1.3)    │
              └──┬──┬──┬──┬───────┘
                 │  │  │  │
        ┌────────┘  │  │  └────────────┐
        │           │  │               │
┌───────┴──────┐ ┌──┴──┴───┐ ┌─────────┴────┐
│  cliente1    │ │cliente2 │ │  atacante    │
│  10.0.0.10   │ │10.0.0.20│ │  10.0.0.30   │
│  (normal)    │ │(normal) │ │  (sospechoso)│
└──────────────┘ └─────────┘ └──────────────┘
                                  
              ┌──────────────────────┐
              │      servidor        │
              │     10.0.0.100       │
              │  HTTP:80, FTP:21     │
              │  SSH:22, 8080        │
              └──────────────────────┘
```

---

## Hosts y Configuración

| Host | IP | Rol | Servicios |
|------|----|-----|-----------|
| cliente1 | 10.0.0.10 | Usuario normal | — |
| cliente2 | 10.0.0.20 | Segundo usuario | — |
| atacante | 10.0.0.30 | Host sospechoso | — |
| servidor | 10.0.0.100 | Objetivo | HTTP:80, FTP:21, SSH:22, 8080 |

El **controlador Ryu** corre en el host anfitrión (fuera de Mininet) y se conecta al switch OVS via el protocolo OpenFlow 1.3 en el puerto 6633.

---

## Archivos del Proyecto

| Archivo | Descripción |
|---------|-------------|
| `sdn_scenario.py` | Topología Mininet + arranque del controlador Ryu |
| `ryu_controller.py` | Aplicación Ryu: switch L2, firewall, estadísticas, detección de anomalías |
| `sdn_demo.py` | Script de demostración con modos: `demo`, `stats`, `portscan` |
| `setup_sdn_scenario.sh` | Instala Ryu, dependencias y genera `/tmp/sdn_quickstart.txt` |

---

## Requisitos Previos

### Dependencias del sistema

```bash
# Mininet y Open vSwitch (normalmente ya instalados)
sudo apt-get install mininet openvswitch-switch

# Python Scapy (para el modo portscan de la demo)
sudo apt-get install python3-scapy

# Herramientas de red opcionales
sudo apt-get install curl nmap tcpdump
```

### Instalar Ryu SDN Framework

Ryu requiere una versión compatible de `eventlet`. La instalación recomendada:

```bash
pip3 install eventlet==0.30.2
pip3 install ryu
```

O usando el script de setup incluido (gestiona todo automáticamente):

```bash
sudo ./setup_sdn_scenario.sh
```

Verificar que la instalación es correcta:

```bash
ryu-manager --version
```

---

## Arquitectura SDN Implementada

### Plano de control (Ryu)

El controlador implementa las siguientes funcionalidades sobre OpenFlow 1.3:

#### 1. L2 Switch con aprendizaje de MACs

Cuando un paquete llega al switch y no existe un flujo para él, el switch lo envía al controlador (**Packet-In**). El controlador:
1. Aprende la dirección MAC fuente y el puerto de entrada
2. Decide el puerto de salida (lookup en tabla MAC, o flood si desconocido)
3. Instala un flujo en el switch para ese tráfico (`idle_timeout=30s`)
4. Reenvía el paquete actual

Una vez instalado el flujo, el switch procesa el tráfico subsiguiente **sin consultar al controlador** (plano de datos).

#### 2. Firewall dinámico (software, en el controlador)

Las reglas de firewall se almacenan en el controlador. Para cada **Packet-In** de tráfico IPv4, el controlador comprueba si el paquete coincide con alguna regla de bloqueo antes de reenviarlo. Si coincide, descarta el paquete silenciosamente.

Las reglas se gestionan via REST API en tiempo real, sin reiniciar nada.

#### 3. Bloqueo de IP (hardware, en el switch)

Para bloqueos totales de una IP, el controlador instala una **regla DROP de prioridad 200** directamente en el switch OVS via `OFPFlowMod`. Esta regla se aplica en el **plano de datos**, lo que significa que el switch descarta los paquetes de esa IP sin siquiera enviarlos al controlador. Es mucho más eficiente que el firewall software.

#### 4. Detección de port scan y bloqueo automático

El controlador monitoriza los paquetes TCP SYN que recibe. Mantiene un contador de puertos únicos contactados por cada IP origen en una ventana de 5 segundos. Si una IP supera 15 puertos únicos en esa ventana, el controlador:
1. Registra una alerta en el log
2. Llama automáticamente a `block_ip()`, instalando una regla DROP en el switch

#### 5. Estadísticas de flujo

Cada 5 segundos el controlador envía `OFPFlowStatsRequest` al switch y recibe `OFPFlowStatsReply` con contadores de paquetes y bytes por flujo. Estas estadísticas son consultables via REST API.

### Plano de datos (OVS)

El switch OVS opera en modo OpenFlow 1.3. Las tablas de flujos tienen la siguiente estructura de prioridades:

| Prioridad | Tipo de regla | Instalada por |
|-----------|--------------|---------------|
| 0 | Table-miss (enviar al controlador) | Ryu al conectar |
| 10 | Reenvío unicast IP por flujo | Ryu tras Packet-In |
| 200 | DROP de IP bloqueada | Ryu vía `block_ip()` |

### REST API del controlador

El controlador expone una API REST en `http://127.0.0.1:8080`:

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| GET | `/sdn/stats` | Estado global: switches, IPs bloqueadas, flujos |
| GET | `/sdn/topology` | Tabla MAC aprendida por switch |
| GET | `/sdn/firewall/rules` | Lista de reglas de firewall activas |
| POST | `/sdn/firewall/rules` | Añadir regla de firewall |
| DELETE | `/sdn/firewall/rules/{id}` | Eliminar regla por ID |
| POST | `/sdn/block/{ip}` | Bloquear IP (regla DROP en switch) |
| DELETE | `/sdn/block/{ip}` | Desbloquear IP (elimina regla DROP) |

Cuerpo JSON para crear regla de firewall:
```json
{
  "src_ip":   "10.0.0.30",
  "dst_ip":   "10.0.0.100",
  "protocol": "tcp",
  "dst_port": 80,
  "action":   "block"
}
```
Cualquier campo puede ser `"*"` para indicar "cualquier valor". `dst_port` puede omitirse para bloquear todo el protocolo.

---

## Guía de Uso Paso a Paso

### PASO 1: Instalar dependencias

```bash
cd /home/mininet/entornos-tfm/sdn-openflow
sudo ./setup_sdn_scenario.sh
```

Verifica que al final aparezca `[OK] ryu-manager`.

### PASO 2: Iniciar el escenario

```bash
sudo python3 sdn_scenario.py
```

Durante el arranque verás:

```
*** Limpiando configuracion previa
*** Iniciando controlador Ryu...
  Esperando controlador... (1/20)
  [OK] Controlador Ryu activo (REST en :8080)
*** Creando hosts
*** Creando switch OpenFlow 1.3
*** Iniciando red
*** Configurando escenario
  [OK] HTTP activo en 10.0.0.100:80
>>> ESCENARIO SDN - CONTROLADOR RYU + OPENFLOW 1.3 <<<
```

### PASO 3: Verificar conectividad inicial

```
mininet> pingall
```

**Salida esperada:** todos los hosts se alcanzan (`0% dropped`). El controlador aprende las MACs e instala flujos de reenvío.

```
mininet> cliente1 curl http://10.0.0.100
```

**Salida esperada:** `<h1>Servidor SDN</h1>...`

### PASO 4: Ver estado del controlador (REST API)

```
mininet> sh curl -s http://127.0.0.1:8080/sdn/topology | python3 -m json.tool
```

**Salida esperada:**
```json
{
  "switches": [
    {
      "dpid": "1",
      "mac_table": {
        "00:00:00:00:00:10": 1,
        "00:00:00:00:00:20": 2,
        "00:00:00:00:00:30": 3,
        "00:00:00:00:00:aa": 4
      }
    }
  ]
}
```

```
mininet> sh curl -s http://127.0.0.1:8080/sdn/firewall/rules | python3 -m json.tool
```

**Salida esperada:** `[]` (sin reglas activas al inicio)

### PASO 5: Firewall dinámico

#### 5.1 Bloquear flujo específico (atacante → servidor:80)

```
mininet> sh curl -s -X POST http://127.0.0.1:8080/sdn/firewall/rules \
  -H 'Content-Type: application/json' \
  -d '{"src_ip":"10.0.0.30","dst_ip":"10.0.0.100","protocol":"tcp","dst_port":80,"action":"block"}'
```

**Respuesta:**
```json
{"id": 1, "src_ip": "10.0.0.30", "dst_ip": "10.0.0.100", "protocol": "tcp", "dst_port": 80, "action": "block"}
```

Verificar el bloqueo:

```
mininet> atacante curl --max-time 3 http://10.0.0.100
# El controlador descarta los paquetes -> timeout

mininet> cliente1 curl http://10.0.0.100
# Los clientes normales siguen accediendo -> OK
```

Eliminar la regla (usar el ID devuelto):

```
mininet> sh curl -X DELETE http://127.0.0.1:8080/sdn/firewall/rules/1
```

#### 5.2 Bloquear protocolo completo (ICMP desde atacante)

```
mininet> sh curl -s -X POST http://127.0.0.1:8080/sdn/firewall/rules \
  -H 'Content-Type: application/json' \
  -d '{"src_ip":"10.0.0.30","protocol":"icmp","action":"block"}'

mininet> atacante ping -c3 10.0.0.100    # no recibe respuesta
mininet> cliente1 ping -c3 10.0.0.100   # funciona
```

### PASO 6: Bloqueo completo de IP (regla DROP en switch)

```
mininet> sh curl -X POST http://127.0.0.1:8080/sdn/block/10.0.0.30
```

El switch instala una regla DROP de prioridad 200. Verificar:

```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200
```

**Salida esperada:**
```
priority=200,ip,nw_src=10.0.0.30 actions=drop
```

El atacante queda completamente aislado:

```
mininet> atacante ping -c3 10.0.0.100      # falla (DROP en switch)
mininet> atacante curl http://10.0.0.100   # falla (DROP en switch)
```

Desbloquear:

```
mininet> sh curl -X DELETE http://127.0.0.1:8080/sdn/block/10.0.0.30
```

### PASO 7: Detección automática de port scan

```
# Asegurar que el atacante no está bloqueado
mininet> sh curl -X DELETE http://127.0.0.1:8080/sdn/block/10.0.0.30

# Lanzar port scan (script Scapy incluido)
mininet> atacante python3 /tmp/sdn_demo.py --mode portscan --target 10.0.0.100
```

El controlador detecta automáticamente el escaneo cuando el atacante supera 15 puertos únicos en 5 segundos y lo bloquea:

```
mininet> sh tail -10 /tmp/ryu_controller.log
```

**Salida esperada en el log:**
```
WARNING:ryu.app.ryu_controller:PORT SCAN DETECTADO: 10.0.0.30 (15 puertos unicos en 5s) -> BLOQUEANDO
WARNING:ryu.app.ryu_controller:IP BLOQUEADA: 10.0.0.30 (razon: port_scan_auto)
```

Verificar el bloqueo automático:

```
mininet> sh curl -s http://127.0.0.1:8080/sdn/stats | python3 -m json.tool
# "blocked_ips": ["10.0.0.30"]

mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=200
# priority=200,ip,nw_src=10.0.0.30 actions=drop
```

### PASO 8: Estadísticas de flujo

```
# Generar tráfico
mininet> cliente1 ping -c5 10.0.0.100
mininet> cliente2 curl http://10.0.0.100

# Ver estadísticas tras unos segundos (el controlador las actualiza cada 5s)
mininet> sh curl -s http://127.0.0.1:8080/sdn/stats | python3 -m json.tool
```

**Salida esperada (fragmento):**
```json
{
  "flow_stats": {
    "1": [
      {
        "priority": 10,
        "match": "OFPMatch(oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.10', 'ipv4_dst': '10.0.0.100'})",
        "packets": 10,
        "bytes": 980,
        "duration_sec": 8
      }
    ]
  }
}
```

Ver los flujos directamente en el switch:

```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

### PASO 9: Demo automática completa

```
mininet> sh python3 /tmp/sdn_demo.py --mode demo
```

Ejecuta en secuencia: consulta de estado, creación de regla de firewall, bloqueo de IP, visualización de stats y limpieza.

### PASO 10: Salir y limpiar

```
mininet> exit
```

El escenario detiene automáticamente el controlador Ryu y los servicios. Para limpiar manualmente:

```bash
sudo mn -c
pkill -f ryu-manager
```

---

## Diferencias entre Firewall Software y Bloqueo Hardware

| Característica | Firewall software (reglas REST) | Bloqueo IP (regla DROP switch) |
|----------------|--------------------------------|-------------------------------|
| Dónde actúa | Controlador Ryu (software) | Switch OVS (plano de datos) |
| Granularidad | Por IP, protocolo, puerto | Por IP origen |
| Eficiencia | Cada paquete llega al controlador | El switch descarta sin consultar |
| Visible en `dump-flows` | No | Sí (priority=200) |
| Persistencia | Hasta eliminar via API | Hasta desbloquear via API |
| Uso recomendado | Reglas específicas de servicio | Aislar hosts maliciosos |

---

## Conceptos SDN Demostrados

| Concepto | Descripción |
|----------|-------------|
| **Separación plano control/datos** | Ryu decide, OVS ejecuta; el controlador puede cambiar el comportamiento sin tocar el hardware |
| **OpenFlow Packet-In** | El switch envía al controlador los paquetes sin flujo instalado |
| **OpenFlow Flow-Mod** | El controlador instala/elimina reglas en el switch de forma programática |
| **Prioridad de flujos** | Flujos DROP (prioridad 200) tienen precedencia sobre flujos de reenvío (prioridad 10) |
| **Idle timeout** | Los flujos de reenvío expiran tras 30s de inactividad, evitando que la tabla crezca indefinidamente |
| **REST API de red** | Política de red gestionada como un servicio HTTP, sin CLI ni configuración estática |
| **Detección en tiempo real** | El controlador analiza el tráfico y reacciona automáticamente ante anomalías |

---

## Logs Generados

| Fichero | Contenido |
|---------|-----------|
| `/tmp/ryu_controller.log` | Log completo del controlador Ryu (Packet-In, flujos, bloqueos, anomalías) |
| `/tmp/servidor_http.log` | Log del servidor HTTP de la víctima |

---

## Troubleshooting

### Ryu no inicia

```bash
# Ver el log completo
tail -50 /tmp/ryu_controller.log

# Verificar que ryu-manager está en el PATH
which ryu-manager
ryu-manager --version

# Si no está en PATH:
export PATH=$HOME/.local/bin:$PATH
```

Error común con eventlet:
```
AttributeError: module 'eventlet.green.select' has no attribute 'poll'
```
Solución: `pip3 install eventlet==0.30.2 && pip3 install --force-reinstall ryu`

### El switch no conecta al controlador

```bash
# Verificar que el proceso Ryu está escuchando en el puerto 6633
ss -tlnp | grep 6633

# Ver estado de la conexión OVS -> controlador
mininet> sh ovs-vsctl show
# Debe aparecer: Controller "tcp:127.0.0.1:6633" is_connected: true
```

Si `is_connected: false`:
1. Comprobar que Ryu está corriendo: `pgrep -f ryu-manager`
2. Revisar el log: `tail -20 /tmp/ryu_controller.log`
3. Verificar que el puerto 6633 no está ocupado: `ss -tlnp | grep 6633`

### La REST API no responde

```bash
curl -v http://127.0.0.1:8080/sdn/stats
```

Si no responde, el controlador puede estar iniciando aún (esperar hasta 20s). Si falla, revisar el log por errores de `wsgi` o `webob`.

### pingall falla después de instalar reglas

Las reglas de firewall del controlador solo afectan a tráfico IPv4. El tráfico ARP y los pings entre hosts no afectados deberían funcionar. Si pingall falla completamente:

```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
# Verificar que existe la regla table-miss (priority=0)
```

Si no existe la regla table-miss, el switch desconoce qué hacer con los paquetes. Reiniciar el escenario.

### El port scan no dispara la detección automática

El controlador solo ve los paquetes que llegan vía **Packet-In** (sin flujo instalado). Para que la detección funcione, el scan debe tocar puertos únicos a velocidad suficiente:

```
# Asegurar que el atacante no tiene flujos previos en el switch
mininet> sh ovs-ofctl -O OpenFlow13 del-flows s1

# Lanzar el scan inmediatamente después
mininet> atacante python3 /tmp/sdn_demo.py --mode portscan --target 10.0.0.100
```

Umbral configurable en `ryu_controller.py`: `ANOMALY_PORT_THRESHOLD` (default: 15 puertos) y `ANOMALY_TIME_WINDOW` (default: 5 segundos).

---

## Comparación SDN vs Red Tradicional

| Aspecto | Red tradicional | SDN con Ryu |
|---------|----------------|-------------|
| Configuración de firewall | CLI en cada switch/router | REST API centralizada |
| Cambio de política | Reconfigurar dispositivos uno a uno | Un POST a la API |
| Visibilidad del tráfico | Estadísticas por dispositivo | Vista global en el controlador |
| Reacción a anomalías | Manual o con agentes distribuidos | Automática, en milisegundos |
| Actualizaciones de política | Disruptivas (reboot) | En caliente, sin cortar servicio |

---

## Advertencia Legal

> **ADVERTENCIA:** Este escenario es únicamente para fines educativos en entornos controlados y aislados.
> Las técnicas de detección y bloqueo aquí demostradas deben aplicarse únicamente en redes bajo administración propia.

---

**Versión:** 1.0
**Fecha:** 2026-04-19
**Autor:** Mario Gil
