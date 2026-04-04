# Escenario de ARP Spoofing con Sistema de Detección

## Descripción General

Este escenario implementa una demostración completa de:
- **Ataque ARP Spoofing** (Man-in-the-Middle)
- **Sistema de Detección** (IDS) que identifica el ataque
- **Sistema de Defensa Activa** que contrarresta el ataque

## Topología de Red

```
                    +---------------+
                    |   Gateway     |
                    | 192.168.1.1   |
                    | (Router)      |
                    +-------+-------+
                            |
                    +-------+-------+
                    |   Switch s1   |
                    +-------+-------+
                            |
        +-------------------+-------------------+-------------------+
        |                   |                   |                   |
+-------+-------+   +-------+-------+   +-------+-------+   +-------+-------+
|    Victim     |   |   Attacker    |   |    Server     |   |    Monitor    |
| 192.168.1.10  |   | 192.168.1.100 |   | 192.168.1.50  |   | 192.168.1.200 |
| (Cliente)     |   | (Atacante)    |   | (Web Server)  |   | (IDS)         |
+---------------+   +---------------+   +---------------+   +---------------+
```

## Hosts y Configuración

| Host | IP | MAC | Descripción |
|------|----|----|-------------|
| gateway | 192.168.1.1 | 00:00:00:00:00:01 | Router/Gateway de la red |
| victim | 192.168.1.10 | 00:00:00:00:00:10 | Cliente víctima del ataque |
| attacker | 192.168.1.100 | 00:00:00:00:00:99 | Host atacante (MITM) |
| server | 192.168.1.50 | 00:00:00:00:00:50 | Servidor web HTTP |
| monitor | 192.168.1.200 | 00:00:00:00:00:AA | Sistema IDS/IPS |

## Archivos del Proyecto

1. **arp_spoofing_scenario.py** - Topología de Mininet
2. **arp_spoof_attack.py** - Script de ataque ARP spoofing
3. **arp_detector.py** - Sistema de detección (IDS pasivo)
4. **arp_defender.py** - Sistema de defensa activa (IPS)
5. **setup_arp_scenario.sh** - Script de instalación

## Requisitos Previos

### Instalación de Dependencias

```bash
# Instalar Mininet
sudo apt-get install mininet

# Instalar Scapy (para Python 3)
sudo apt-get install python3-scapy

# Instalar herramientas de red (opcional)
sudo apt-get install tcpdump arping dsniff net-tools
```

### Configuración

```bash
# Dar permisos de ejecución
chmod +x *.py *.sh

# Ejecutar script de setup
./setup_arp_scenario.sh
```

## Guía de Uso Paso a Paso

### PASO 1: Iniciar la Topología

```bash
# Limpiar configuración previa
sudo mn -c

# Iniciar el escenario
sudo python3 arp_spoofing_scenario.py
```

### PASO 2: Verificar Estado Normal de la Red

#### 2.1 Verificar conectividad

```bash
# Desde Mininet CLI:
mininet> victim ping -c 3 gateway
mininet> victim ping -c 3 server
```

#### 2.2 Ver tabla ARP inicial (NORMAL)

```bash
mininet> victim arp -n
```

**Salida esperada:**
```
Address          HWtype  HWaddress           Flags Mask  Iface
192.168.1.1      ether   00:00:00:00:00:01   C           victim-eth0
192.168.1.50     ether   00:00:00:00:00:50   C           victim-eth0
```

#### 2.3 Acceder al servidor web

```bash
mininet> victim curl http://192.168.1.50
```

### PASO 3: Iniciar el Sistema de Detección (IDS)

#### Usando xterm

```bash
# Abrir terminal para el monitor
mininet> xterm monitor

# En la ventana del monitor:
monitor# python3 /tmp/arp_detector.py
```


**El IDS mostrará:**
```
======================================================================
  SISTEMA DE DETECCION DE ARP SPOOFING (IDS)
======================================================================

Interfaz de monitoreo: monitor-eth0
Umbral de alerta: 3 cambios de MAC

Estado: MONITOREANDO...
----------------------------------------------------------------------
TIMESTAMP            TIPO       IP              MAC
----------------------------------------------------------------------
```

### PASO 4: Ejecutar el Ataque ARP Spoofing

#### Con nuestro script

```bash
# Abrir terminal para el atacante
mininet> xterm attacker

# En la ventana del atacante:
attacker# python3 /tmp/arp_spoof_attack.py
```



**El script de ataque mostrará:**
```
============================================================
  ATAQUE ARP SPOOFING - MAN IN THE MIDDLE
============================================================

[!] Objetivo: 192.168.1.10
[!] Gateway: 192.168.1.1
[!] Interfaz: attacker-eth0
[*] MAC del atacante: 00:00:00:00:00:99

[*] Iniciando ARP spoofing...
[*] Presiona Ctrl+C para detener el ataque

[+] Paquetes ARP enviados: 10
```

### PASO 5: Observar la Detección del Ataque

**En la ventana del IDS (monitor), verás:**

```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!!!] ALERTA DE SEGURIDAD - POSIBLE ARP SPOOFING [!!!]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Timestamp: 2026-03-28 15:30:45
IP:        192.168.1.1
MAC Anterior: 00:00:00:00:00:01
MAC Nueva:    00:00:00:00:00:99 <-- SOSPECHOSO
Tipo de paquete: ARP Reply
Numero de cambios detectados: 1

[CRITICO] Umbral de 3 cambios superado!
[CRITICO] Alta probabilidad de ataque ARP SPOOFING activo
[ACCION RECOMENDADA] Investigar inmediatamente el host 00:00:00:00:00:99
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### PASO 6: Verificar que el Ataque Funcionó

#### 6.1 Ver tabla ARP de la víctima (COMPROMETIDA)

```bash
mininet> victim arp -n
```

**Salida comprometida:**
```
Address          HWtype  HWaddress           Flags Mask  Iface
192.168.1.1      ether   00:00:00:00:00:99   C           victim-eth0  <-- FALSO!
192.168.1.50     ether   00:00:00:00:00:50   C           victim-eth0
```

**NOTA:** La MAC del gateway ahora es `00:00:00:00:00:99` (del atacante) en lugar de `00:00:00:00:00:01`

#### 6.2 Capturar tráfico interceptado

```bash
# En el atacante, el tráfico de la víctima ahora pasa por él
attacker# tcpdump -i attacker-eth0 -n host 192.168.1.10
```

### PASO 7: Activar Sistema de Defensa (Opcional)

```bash
# Abrir terminal para defensa
mininet> xterm monitor

# Ejecutar sistema de defensa activa
monitor# python3 /tmp/arp_defender.py
```

**El sistema de defensa:**
- Detecta automáticamente ARPs maliciosos
- Envía ARPs correctivos a toda la red
- Bloquea el ataque en tiempo real

**Salida del defensor:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[ATAQUE DETECTADO Y BLOQUEADO #1]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Timestamp: 2026-03-28 15:31:00
IP suplantada: 192.168.1.1
MAC legitima:  00:00:00:00:00:01
MAC atacante:  00:00:00:00:00:99 <-- BLOQUEADO

[ACCION] Enviando ARP correctivo a la red...
[OK] ARP correctivo enviado (5 paquetes broadcast)
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### PASO 8: Limpiar y Restaurar

#### 8.1 Detener el ataque

Presiona `Ctrl+C` en la terminal del atacante.

#### 8.2 Limpiar cache ARP de la víctima

```bash
# Limpiar toda la cache ARP
mininet> victim ip -s -s neigh flush all

# O limpiar entrada específica
mininet> victim arp -d 192.168.1.1

# Regenerar cache ARP correcta
mininet> victim ping -c 1 192.168.1.1
mininet> victim arp -n
```

**Ahora debería mostrar la MAC correcta:**
```
Address          HWtype  HWaddress           Flags Mask  Iface
192.168.1.1      ether   00:00:00:00:00:01   C           victim-eth0  <-- CORRECTO
```

## Experimentos Adicionales

### Experimento 1: Interceptar Tráfico HTTP

```bash
# En el atacante (mientras el MITM está activo):
attacker# tcpdump -i attacker-eth0 -A -s 0 'tcp port 80'

# En la víctima:
mininet> victim curl http://192.168.1.50

# El atacante verá todo el tráfico HTTP en texto plano
```

### Experimento 2: Comparar con y sin Defensa

**Sin defensa activa:**
- El ataque persiste
- La tabla ARP permanece envenenada

**Con defensa activa:**
- El sistema envía ARPs correctivos constantemente
- La tabla ARP se restaura automáticamente
- El ataque es neutralizado

### Experimento 3: Múltiples Víctimas

Modificar el script de ataque para envenenar múltiples hosts:

```python
VICTIMS = ["192.168.1.10", "192.168.1.50"]
```

## Análisis de Resultados

### Indicadores de Ataque Exitoso

1. ✅ Tabla ARP de la víctima muestra MAC incorrecta
2. ✅ IDS detecta y alerta sobre cambios de MAC
3. ✅ Tráfico de la víctima pasa por el atacante
4. ✅ El atacante puede interceptar/modificar tráfico

### Indicadores de Defensa Exitosa

1. ✅ Detección inmediata del ataque
2. ✅ ARPs correctivos enviados automáticamente
3. ✅ Tabla ARP restaurada en segundos
4. ✅ Log de ataques bloqueados

## Logs Generados

- `/tmp/arp_attack_log.txt` - Ataques detectados por el IDS
- `/tmp/arp_defense_log.txt` - Ataques bloqueados por el IPS

## Conceptos de Seguridad Demostrados

1. **ARP Spoofing** - Envenenamiento de cache ARP
2. **Man-in-the-Middle (MITM)** - Interceptación de tráfico
3. **Detección basada en anomalías** - Cambios inesperados de MAC
4. **Defensa activa** - Contramedidas automáticas
5. **Importancia de cifrado** - HTTPS vs HTTP

## Mitigaciones en Redes Reales

1. **ARP Estático** - Configurar entradas ARP manualmente
2. **Dynamic ARP Inspection (DAI)** - Feature de switches gestionados
3. **Port Security** - Limitar MACs por puerto
4. **802.1X** - Autenticación de red
5. **VLANs** - Segmentación de red
6. **IPSec/VPN** - Cifrado de tráfico

## Troubleshooting

### Problema: IDS no detecta el ataque

**Solución:**
```bash
# Verificar que el monitor está en la misma red
mininet> monitor ping -c 1 192.168.1.10

# Verificar interfaz correcta
monitor# ifconfig
```

### Problema: Ataque no funciona

**Solución:**
```bash
# Verificar IP forwarding en atacante
attacker# sysctl net.ipv4.ip_forward
# Debe ser = 1

# Si no:
attacker# sysctl -w net.ipv4.ip_forward=1
```

### Problema: Scapy no instalado

**Solución:**
```bash
sudo apt-get install python3-scapy
# o
sudo pip3 install scapy
```

## Referencias

- [ARP Spoofing - Wikipedia](https://en.wikipedia.org/wiki/ARP_spoofing)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [RFC 826 - ARP Protocol](https://tools.ietf.org/html/rfc826)

## Advertencia Legal

⚠️ **ADVERTENCIA:** Este escenario es solo para propósitos educativos en entornos controlados. 
Realizar ARP spoofing en redes sin autorización es **ILEGAL** y puede resultar en consecuencias legales graves.

---

**Autor:** Mario Gil
**Versión:** 1.0  
**Fecha:** 2026
