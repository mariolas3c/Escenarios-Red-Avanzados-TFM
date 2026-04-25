# Escenario de Escaneo de Puertos con Detección mediante Suricata IDS

## Descripción General

Este escenario implementa una demostración completa de:

- **Escaneo de puertos** con múltiples técnicas (SYN, FIN, XMAS, NULL, ACK, UDP)
- **Detección en tiempo real** mediante **Suricata IDS** con reglas personalizadas
- **Port mirroring** con Open vSwitch para que el monitor reciba todo el tráfico
- **Script de ataque propio** basado en Scapy (no requiere nmap)

El objetivo es mostrar cómo un atacante descubre qué servicios están expuestos en un host, y cómo un sistema IDS puede detectarlo analizando los patrones de tráfico.

---

## Topología de Red

```
                    +-----------------+
                    |   Switch s1     |  (OVS con port mirroring)
                    +--+--+--------+--+
                       |  |        |
             +---------+  +------+ +----------+
             |                  |             |
    +--------+-------+  +-------+------+  +---+----------+
    |    victim       |  |   attacker   |  |   monitor    |
    |   10.0.1.10     |  |  10.0.1.20   |  |  10.0.1.100  |
    | Servicios       |  | Escaner de   |  | Suricata IDS |
    | abiertos        |  | puertos      |  | (pasivo)     |
    +-----------------+  +--------------+  +--------------+
```

Todo el tráfico del switch es replicado hacia `monitor` mediante un **mirror OVS**, de forma que Suricata puede analizar los paquetes sin estar en línea (modo pasivo/IDS).

---

## Hosts y Configuración

| Host | IP | Rol | Servicios |
|------|----|-----|-----------|
| victim | 10.0.1.10 | Objetivo del escaneo | HTTP:80, SSH:22, FTP:21, Telnet:23, SMTP:25, MySQL:3306, HTTP-alt:8080 |
| attacker | 10.0.1.20 | Realiza los escaneos | — |
| monitor | 10.0.1.100 | IDS con Suricata | Escucha en modo promiscuo |

---

## Archivos del Proyecto

| Archivo | Descripción |
|---------|-------------|
| `port_scan_scenario.py` | Topología Mininet, configura servicios, port mirroring y lanza Suricata |
| `port_scan_attack.py` | Escáner de puertos con Scapy: SYN, FIN, XMAS, NULL, ACK y UDP |
| `setup_portscan_scenario.sh` | Instala dependencias (nmap, hping3, Suricata vía PPA OISF) y genera `/tmp/portscan_quickstart.txt` |

---

## Requisitos Previos

### Dependencias del sistema

```bash
# Mininet y Open vSwitch (normalmente ya instalados)
sudo apt-get install mininet openvswitch-switch

# Python Scapy (usado por el script de ataque)
sudo apt-get install python3-scapy

# Herramientas opcionales
sudo apt-get install nmap hping3 tcpdump
```

### Instalar Suricata

Suricata no está en los repositorios estándar de Ubuntu 20.04. Se instala desde el PPA oficial de OISF:

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
```

O usando el script de setup incluido (hace todo lo anterior automáticamente):

```bash
sudo ./setup_portscan_scenario.sh
```

---

## Cómo Funciona el Escenario

### 1. Configuración de servicios en la víctima

Al iniciar el escenario, `victim` levanta varios servicios que quedan escuchando en puertos TCP:

- **Puerto 80**: servidor HTTP con Python (`python3 -m http.server 80`)
- **Puertos 21, 22, 23, 25, 3306, 8080**: simulados con `netcat` en modo escucha persistente

Esto permite que los escaneos encuentren puertos realmente abiertos y que Suricata tenga tráfico real que analizar.

### 2. Port mirroring con Open vSwitch

El switch `s1` está configurado con un **mirror** que copia todos los paquetes hacia el puerto de `monitor`. El escenario primero añade una flow rule de flooding para garantizar conectividad L2:

```
ovs-ofctl add-flow s1 priority=1,action=flood
```

A continuación crea el mirror. El nombre del puerto OVS hacia `monitor` se **autodetecta** inspeccionando los enlaces de Mininet (con fallback a `s1-eth3` si no se encuentra):

```
ovs-vsctl -- set Bridge s1 mirrors=@m \
  -- --id=@mon get Port <puerto-monitor-autodetectado> \
  -- --id=@m create Mirror name=scan_mirror select-all=true output-port=@mon
```

Finalmente activa el modo promiscuo en la interfaz del monitor:

```
ifconfig monitor-eth0 promisc
```

Esto significa que `monitor` ve absolutamente todo el tráfico de la red sin interferir en él (modo pasivo).

### 3. Reglas de detección en Suricata

Se generan 8 reglas personalizadas en `/tmp/suricata_portscan.rules`:

| SID | Tipo de escaneo | Técnica de detección |
|-----|-----------------|----------------------|
| 1000001 | SYN Scan | 5+ paquetes SYN-only (`flow:to_server`) en 10 segundos desde la misma IP |
| 1000002 | NULL Scan | Paquete TCP sin ninguna flag (primera coincidencia) |
| 1000003 | FIN Scan | Paquete TCP con solo flag FIN activa (primera coincidencia) |
| 1000004 | XMAS Scan | Paquete TCP con flags FIN+PSH+URG activas (primera coincidencia) |
| 1000005 | ACK Scan | 5+ paquetes ACK-only (`flow:to_server`) en 10 segundos desde la misma IP |
| 1000006 | UDP Scan | 5+ paquetes UDP (`flow:to_server`) en 10 segundos desde la misma IP |
| 1000007 | nmap NSE HTTP | User-Agent `Nmap Scripting Engine` en cabeceras HTTP |
| 1000008 | Connect Scan | 20+ paquetes SYN-only (`flow:to_server`) en 5 segundos (nmap -sT es mucho más rápido que el script Scapy) |

Las reglas con `threshold` usan el motor de umbrales de Suricata para no disparar una alerta por cada paquete, sino cuando se supera un volumen indicativo de escaneo activo. Todas las reglas con threshold incluyen `flow:to_server` para contar únicamente paquetes del atacante hacia la víctima, evitando que las respuestas (SYN-ACK, etc.) inflen artificialmente los contadores.

### 4. Suricata en modo IDS pasivo

Suricata arranca en el `monitor` escuchando sobre `monitor-eth0` en modo af-packet:

```
suricata -c /tmp/suricata_min.yaml --af-packet=monitor-eth0 -l /tmp/suricata-logs/ -D
```

Genera dos ficheros de log:
- **`fast.log`**: una línea por alerta, legible directamente
- **`eve.json`**: formato JSON enriquecido con metadatos del paquete

---

## Guía de Uso Paso a Paso

### PASO 1: Instalar dependencias

```bash
cd /home/mininet/entornos-tfm/port-scanning
sudo ./setup_portscan_scenario.sh
```

Verifica que al final aparezca `[OK] suricata`. El script también genera una guía rápida en `/tmp/portscan_quickstart.txt` que puedes consultar en cualquier momento con `cat /tmp/portscan_quickstart.txt`.

### PASO 2: Iniciar la topología

```bash
sudo python3 port_scan_scenario.py
```

Durante el arranque verás:

```
*** Creando hosts
*** Creando switch
*** Configurando escenario
  Levantando servicios en la victima (10.0.1.10)...
  [OK] HTTP activo en 10.0.1.10:80
  Configurando port mirroring hacia el monitor...
  [OK] Port mirroring activo
  Escribiendo reglas Suricata...
  Iniciando Suricata en monitor (10.0.1.100)...
  [OK] Suricata iniciado (PID: XXXX)
  [INFO] Alertas en: /tmp/suricata-logs/fast.log
```

### PASO 3: Verificar conectividad

Desde la CLI de Mininet:

```
mininet> victim ping -c2 10.0.1.20
mininet> attacker curl http://10.0.1.10
```

**Salida esperada del curl:**
```html
<h1>Servidor Victima</h1>
```

Verificar puertos abiertos en la víctima:

```
mininet> victim ss -tlnp
```

**Salida esperada:**
```
State  Recv-Q  Send-Q  Local Address:Port
LISTEN 0       5       *:80
LISTEN 0       1       *:22
LISTEN 0       1       *:21
...
```

### PASO 4: Monitorear las alertas de Suricata

Abre una terminal para el monitor y deja el log en seguimiento:

```
mininet> monitor tail -f /tmp/suricata-logs/fast.log
```

El fichero aparecerá vacío hasta que se ejecute algún escaneo. Déjalo abierto.

### PASO 5: Ejecutar escaneos de puertos

#### 5.1 Usando el script Scapy incluido (recomendado)

El script `port_scan_attack.py` está copiado en `/tmp/` al iniciar el escenario.

```
# SYN Scan (más común, stealth)
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan syn

# FIN Scan
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan fin

# XMAS Scan (FIN+PSH+URG)
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan xmas

# NULL Scan (sin flags)
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan null

# ACK Scan (mapeo de firewall)
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan ack

# UDP Scan
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan udp

# Todos los tipos en secuencia
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan all
```

Opciones adicionales del script:

```
# Escanear solo puertos específicos
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan syn --ports 20-25,80,443,3306

# Ajustar timeout por puerto en segundos (default: 0.5)
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan syn --timeout 1.0

# Forzar interfaz de red específica
mininet> attacker python3 /tmp/port_scan_attack.py --target 10.0.1.10 --scan syn --iface attacker-eth0
```

**Salida esperada del escáner (SYN Scan):**

```
=================================================================
  ESCANEO DE PUERTOS - SYN SCAN (STEALTH / HALF-OPEN)
=================================================================
Objetivo:   10.0.1.10
Tipo:       syn
Puertos:    20 puertos
Timestamp:  14:32:01
-----------------------------------------------------------------
  PUERTO  ESTADO      SERVICIO         DETALLE
-----------------------------------------------------------------
[+] 21      abierto     ftp              SYN-ACK recibido
[+] 22      abierto     ssh              SYN-ACK recibido
[+] 23      abierto     telnet           SYN-ACK recibido
[+] 25      abierto     smtp             SYN-ACK recibido
[+] 80      abierto     http             SYN-ACK recibido
[+] 3306    abierto     mysql            SYN-ACK recibido
[+] 8080    abierto     http-alt         SYN-ACK recibido
[?] 53      filtrado    dns              no response
...

=================================================================
  RESUMEN DEL ESCANEO
=================================================================
Puertos abiertos:    7
Puertos cerrados:    0
Puertos filtrados:   13
Paquetes enviados:   34
=================================================================
```

#### 5.2 Usando nmap (si está instalado)

```
# SYN Scan (requiere root)
mininet> attacker nmap -sS 10.0.1.10

# TCP Connect Scan
mininet> attacker nmap -sT 10.0.1.10

# FIN Scan
mininet> attacker nmap -sF 10.0.1.10

# XMAS Scan
mininet> attacker nmap -sX 10.0.1.10

# NULL Scan
mininet> attacker nmap -sN 10.0.1.10

# ACK Scan (detecta firewall)
mininet> attacker nmap -sA 10.0.1.10

# UDP Scan (top 20 puertos UDP)
mininet> attacker nmap -sU --top-ports 20 10.0.1.10

# Escaneo agresivo: OS + versiones + scripts NSE
mininet> attacker nmap -A 10.0.1.10
```

### PASO 6: Verificar la detección de Suricata

#### Ver alertas en tiempo real (fast.log)

```
mininet> monitor cat /tmp/suricata-logs/fast.log
```

**Salida esperada tras un SYN Scan:**

```
04/08/2026-14:32:05.123456  [**] [1:1000001:1] SCAN SYN Port Scan Detectado [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.1.20:45123 -> 10.0.1.10:21
04/08/2026-14:32:05.234567  [**] [1:1000001:1] SCAN SYN Port Scan Detectado [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.1.20:45124 -> 10.0.1.10:22
04/08/2026-14:32:05.345678  [**] [1:1000008:1] SCAN TCP Connect Scan Detectado [**] ...
```

#### Contar alertas por tipo de escaneo

```
mininet> monitor grep "SYN Port Scan" /tmp/suricata-logs/fast.log | wc -l
mininet> monitor grep "NULL Scan" /tmp/suricata-logs/fast.log | wc -l
mininet> monitor grep "XMAS Scan" /tmp/suricata-logs/fast.log | wc -l
mininet> monitor grep "FIN Scan" /tmp/suricata-logs/fast.log | wc -l
```

#### Analizar el EVE JSON (formato enriquecido)

```
mininet> monitor python3 -c "
import json
with open('/tmp/suricata-logs/eve.json') as f:
    for line in f:
        try:
            e = json.loads(line)
            if e.get('event_type') == 'alert':
                a = e['alert']
                print('[%s] SID:%s - %s | %s -> %s' % (
                    e['timestamp'], a['signature_id'],
                    a['signature'], e['src_ip'], e['dest_ip']))
        except:
            pass
"
```

#### Ver el log de inicio de Suricata

```
mininet> monitor cat /tmp/suricata-logs/suricata_init.log
```

### PASO 7: Experimentos adicionales

#### Capturar tráfico en el monitor durante el escaneo

```
mininet> monitor tcpdump -i monitor-eth0 -n tcp and host 10.0.1.20 -c 50
```

#### Ver si el escaneo genera RSTs en la víctima

```
mininet> victim tcpdump -i victim-eth0 -n tcp and host 10.0.1.20
```

#### Comparar comportamiento por tipo de scan

```
# Ver solo los paquetes SYN sin completar (SYN scan)
mininet> monitor tcpdump -i monitor-eth0 -n "tcp[tcpflags] == tcp-syn"

# Ver paquetes con flags FIN+PSH+URG (XMAS)
mininet> monitor tcpdump -i monitor-eth0 -n "tcp[tcpflags] == 0x29"

# Ver paquetes sin flags (NULL scan)
mininet> monitor tcpdump -i monitor-eth0 -n "tcp[tcpflags] == 0"
```

#### Recargar alertas tras múltiples escaneos

```
mininet> monitor grep "SCAN" /tmp/suricata-logs/fast.log | sort | uniq -c | sort -rn
```

### PASO 8: Limpiar y salir

```
mininet> exit
```

El escenario detiene automáticamente los servicios de la víctima y Suricata al salir.

Para limpiar el entorno Mininet manualmente:

```bash
sudo mn -c
sudo pkill suricata
```

---

## Cómo Funciona Cada Tipo de Escaneo

### SYN Scan (Half-Open / Stealth)

El más común. El atacante envía un paquete `SYN` y:
- Si recibe `SYN-ACK` → puerto **abierto** (envía `RST` para no completar la conexión)
- Si recibe `RST` → puerto **cerrado**
- Sin respuesta → puerto **filtrado** (firewall)

No genera entradas en los logs de la aplicación porque nunca se completa el handshake TCP.

```
Atacante         Víctima
   |---- SYN ----->|
   |<-- SYN-ACK ---|   (puerto abierto)
   |---- RST ----->|   (aborta antes de completar)
```

### FIN Scan

Explota el comportamiento del RFC 793. Envía solo `FIN`:
- Sistemas **cerrados** responden con `RST`
- Sistemas **abiertos** o **filtrados** ignoran el paquete

No funciona en Windows (responde RST siempre), pero sí en Linux/Unix.

### XMAS Scan

Envía `FIN+PSH+URG` activos (como un árbol de Navidad iluminado). Mismo principio que FIN scan pero más fácil de detectar por su firma tan llamativa.

### NULL Scan

Envía un paquete TCP con **ninguna flag** activa. Comportamiento idéntico al FIN scan.

### ACK Scan

No detecta puertos abiertos, sino **reglas de firewall**:
- `RST` recibido → el puerto **no está filtrado** (paquete llegó al host)
- Sin respuesta → el puerto **está filtrado** (firewall descarta el paquete)

### UDP Scan

Más lento porque UDP no tiene handshake. El indicador de puerto cerrado es un mensaje ICMP `port-unreachable`. Sin respuesta significa abierto o filtrado.

---

## Conceptos de Seguridad Demostrados

| Concepto | Descripción |
|----------|-------------|
| **Reconocimiento activo** | El escaneo de puertos es la primera fase de un ataque (fase 2 del ciclo de vida) |
| **TCP Flag manipulation** | Diferentes combinaciones de flags evaden distintos sistemas de detección |
| **IDS basado en firmas** | Suricata compara tráfico contra reglas predefinidas |
| **Detección por umbral** | Agrupa eventos individuales para detectar comportamiento masivo |
| **Port mirroring** | Técnica de monitoreo pasivo sin interferir en el tráfico |
| **EVE JSON** | Formato estándar de alertas de Suricata, integrable con SIEM |

---

## Logs Generados

| Fichero | Contenido |
|---------|-----------|
| `/tmp/suricata-logs/fast.log` | Alertas en formato texto, una línea por alerta |
| `/tmp/suricata-logs/eve.json` | Alertas en JSON con contexto completo del paquete |
| `/tmp/suricata-logs/suricata.log` | Log del motor Suricata (errores, inicio, stats) |
| `/tmp/suricata_portscan.rules` | Reglas generadas por el escenario |
| `/tmp/suricata_min.yaml` | Configuración Suricata mínima generada por el escenario |

---

## Mitigaciones en Redes Reales

### Detección

- **IDS/IPS** (Suricata, Snort) con reglas de detección de escaneos
- **Firewall con estado** que registra intentos de conexión fallidos
- **Rate limiting** de nuevas conexiones TCP por origen
- **Honeypots** en puertos no utilizados para detectar reconocimiento

### Defensa

- **Firewall restrictivo**: solo exponer los puertos estrictamente necesarios
- **Port knocking**: los puertos están cerrados hasta recibir una secuencia secreta
- **TCP wrappers**: control de acceso a servicios por IP
- **Fail2Ban**: bloqueo automático de IPs que generan demasiados errores

### En el protocolo

- Los escaneos FIN/NULL/XMAS **no funcionan en Windows** (responde RST siempre)
- Un **stateful firewall** filtra paquetes fuera de estado (FIN sin conexión previa)
- **NIDS distribuidos** correlacionan escaneos lentos que evaden umbrales por sensor

---

## Troubleshooting

### Suricata no inicia

```bash
# Ver el log de inicio completo
mininet> monitor cat /tmp/suricata-logs/suricata_init.log

# Verificar que el binario existe
which suricata

# Comprobar la configuración manualmente
suricata -c /tmp/suricata_min.yaml --af-packet=lo -T
```

Si el problema es que Suricata no está instalado, ejecutar:

```bash
sudo ./setup_portscan_scenario.sh
```

### No aparecen alertas en fast.log

**Causa 1: Port mirroring no activo.** Verificar con:

```
mininet> sh ovs-vsctl list Mirror
```

Debe aparecer un mirror con `select-all=true`. Si no existe, primero averigua el puerto del switch que conecta al monitor (suele ser `s1-eth3` pero puede variar):

```
mininet> sh ovs-vsctl show
```

Luego recrea el mirror y la regla de flooding:

```
mininet> sh ovs-ofctl add-flow s1 priority=1,action=flood
mininet> sh ovs-vsctl -- set Bridge s1 mirrors=@m -- --id=@mon get Port s1-eth3 -- --id=@m create Mirror name=scan_mirror select-all=true output-port=@mon
mininet> monitor ifconfig monitor-eth0 promisc
```

> Sustituye `s1-eth3` por el puerto real si `ovs-vsctl show` indica otro nombre.

**Causa 2: Checksums inválidos en interfaces virtuales.** En Mininet los paquetes capturados por af-packet pueden tener checksums incorrectos (sin offloading real). Suricata los descarta silenciosamente antes de aplicar reglas. La configuración generada ya incluye `checksum-checks: no` en la sección `af-packet` para evitar esto.

**Causa 3: Los umbrales no se alcanzan.** Las reglas SYN/ACK/UDP requieren 10+ paquetes en 2 segundos. El script Scapy escanea 20 puertos por defecto, lo que debería ser suficiente. Con nmap añadir `-p 1-100` para escanear más puertos.

**Causa 4: Suricata terminó.** Verificar:

```
mininet> monitor cat /tmp/suricata.pid
mininet> monitor kill -0 $(cat /tmp/suricata.pid) && echo "vivo" || echo "muerto"
```

### El script de ataque falla con error de permisos

Scapy requiere root para enviar paquetes raw. Los hosts de Mininet ya corren como root, pero si ejecutas el script fuera de Mininet:

```bash
sudo python3 port_scan_attack.py --target 10.0.1.10 --scan syn
```

### nmap no encuentra puertos abiertos

En Mininet los hosts están en namespaces de red distintos. Si nmap se ejecuta en el host anfitrión (fuera de Mininet) no verá las IPs del escenario. Ejecutar siempre desde la CLI de Mininet:

```
mininet> attacker nmap -sS 10.0.1.10
```

---

## Comparación de Técnicas de Escaneo

| Tipo | Flags TCP | Detectado por firewall | Detectado por IDS | Funciona en Windows |
|------|-----------|------------------------|-------------------|---------------------|
| SYN | S | Parcial | Sí (umbral) | Sí |
| Connect | S + ACK + ... | Sí (conexión completa) | Sí | Sí |
| FIN | F | No (stateless) | Sí (firma) | No |
| XMAS | F+P+U | No (stateless) | Sí (firma) | No |
| NULL | ninguna | No (stateless) | Sí (firma) | No |
| ACK | A | Parcial | Sí (umbral) | Sí |
| UDP | — | Parcial | Sí (umbral) | Sí |

---

## Advertencia Legal

> **ADVERTENCIA:** Este escenario es únicamente para fines educativos en entornos controlados y aislados.
> Realizar escaneos de puertos en sistemas sin autorización expresa del propietario es **ilegal** en la mayoría de jurisdicciones y puede acarrear responsabilidades penales y civiles.

---

**Versión:** 1.3  
**Fecha:** 2026-04-19
