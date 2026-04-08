# Escenario de DNS Spoofing con Sistema de Detección

## Descripción General

Este escenario implementa una demostración completa de:
- **Ataque DNS Spoofing** (envenenamiento de respuestas DNS)
- **Sistema de Detección** (IDS) que identifica respuestas DNS falsas
- **Sistema de Defensa Activa** que bloquea y corrige ataques
- **Servidor web falso** (phishing) para demostrar el impacto

## Topología de Red

```
                    +---------------+
                    |   Gateway     |
                    |   10.0.0.1    |
                    +-------+-------+
                            |
                    +-------+-------+
                    |   Switch s1   |
                    +-------+-------+
                            |
        +---+---+---+---+---+---+---+
        |   |   |   |   |   |   |   |
      DNS Client Att Web Fake Mon
```

## Hosts y Configuración

| Host | IP | Puerto | Descripción |
|------|-------|--------|-------------|
| gateway | 10.0.0.1 | - | Router/Gateway |
| dns | 10.0.0.53 | 53 | Servidor DNS legítimo |
| client | 10.0.0.10 | - | Cliente víctima |
| attacker | 10.0.0.66 | - | Atacante DNS spoofing |
| webserver | 10.0.0.80 | 80 | Servidor web LEGÍTIMO (fondo verde) |
| fakeserver | 10.0.0.99 | 80 | Servidor web FALSO (fondo rojo) |
| monitor | 10.0.0.100 | - | Sistema IDS/IPS |

## Dominios Configurados

| Dominio | IP Legítima | IP Falsa (ataque) |
|---------|-------------|-------------------|
| www.banco.com | 10.0.0.80 | 10.0.0.99 |
| banco.com | 10.0.0.80 | 10.0.0.99 |
| www.example.com | 10.0.0.80 | 10.0.0.99 |
| legitimo.com | 10.0.0.80 | 10.0.0.99 |

## Archivos del Proyecto

1. **dns_spoofing_scenario.py** - Topología de Mininet
2. **dns_spoof_attack.py** - Script de ataque DNS spoofing
3. **dns_detector.py** - Sistema de detección (IDS)
4. **dns_defender.py** - Sistema de defensa activa (IPS)
5. **setup_dns_scenario.sh** - Script de instalación
6. **test_dns_spoofing.sh** - Script de prueba automático ⭐ NUEVO
7. **verify_dns_setup.sh** - Script de verificación
8. **TROUBLESHOOTING_DNS.md** - Guía de solución de problemas

## Requisitos Previos

### Instalación de Dependencias

```bash
# Instalar Mininet
sudo apt-get install mininet

# Instalar Scapy
sudo apt-get install python3-scapy

# Instalar dnsmasq (servidor DNS)
sudo apt-get install dnsmasq

# Instalar herramientas (opcional)
sudo apt-get install dsniff tcpdump
```

## Guía de Uso Paso a Paso

### PASO 1: Iniciar la Topología

```bash
# Limpiar configuración previa
sudo mn -c

# Iniciar el escenario
sudo python3 dns_spoofing_scenario.py
```

**IMPORTANTE:** El escenario configura:
- Servidor DNS en 10.0.0.53
- Cliente SIN entradas en /etc/hosts (para que el DNS spoofing funcione)
- Dos servidores web: LEGÍTIMO (10.0.0.80) y FALSO (10.0.0.99)

### PASO 2: Verificar Funcionamiento Normal

#### 2.1 Probar resolución DNS normal

```bash
# Desde Mininet CLI:
mininet> client nslookup www.banco.com 10.0.0.53
```

**Salida esperada:**
```
Server:    10.0.0.53
Address:   10.0.0.53#53

Name:      www.banco.com
Address:   10.0.0.80
```

#### 2.2 Probar con dig (más rápido)

```bash
mininet> client dig @10.0.0.53 www.banco.com +short
```

**Debe mostrar:** `10.0.0.80`

#### 2.3 Acceder a los servidores web

```bash
# Servidor LEGÍTIMO (por IP)
mininet> client curl http://10.0.0.80

# Servidor FALSO (por IP)
mininet> client curl http://10.0.0.99

# Por nombre de dominio (antes del ataque)
mininet> client curl http://www.banco.com
```

**El servidor legítimo muestra:**
```html
<h1>BANCO LEGITIMO</h1>
<p>IP: 10.0.0.80</p>
<p>SITIO LEGITIMO</p>
```

**El servidor falso muestra:**
```html
<h1>BANCO - Ingrese sus datos</h1>
<p>IP: 10.0.0.99 (SERVIDOR FALSO)</p>
<p>*** SITIO PHISHING ***</p>
```

### PASO 3: Iniciar el Sistema de Detección (IDS)

```bash
# Abrir terminal para el monitor
mininet> xterm monitor

# En la ventana del monitor:
monitor# python3 /tmp/dns_detector.py
```

**El IDS mostrará:**
```
======================================================================
  SISTEMA DE DETECCION DE DNS SPOOFING (IDS)
======================================================================

Interfaz de monitoreo: monitor-eth0
Servidor DNS legitimo: 10.0.0.53

Registros DNS legitimos conocidos:
  www.banco.com             -> 10.0.0.80
  ...

[*] Iniciando captura de trafico DNS...
----------------------------------------------------------------------
TIMESTAMP    TIPO       DOMINIO                   IP              ESTADO
----------------------------------------------------------------------
```

### PASO 4: Ejecutar el Ataque DNS Spoofing

```bash
# Abrir terminal para el atacante
mininet> xterm attacker

# En la ventana del atacante:
attacker# python3 /tmp/dns_spoof_attack.py
```

**El atacante mostrará:**
```
======================================================================
  ATAQUE DNS SPOOFING
======================================================================

Interfaz: attacker-eth0
Servidor DNS legitimo: 10.0.0.53
Servidor web falso: 10.0.0.99

Dominios a suplantar:
  www.banco.com             -> 10.0.0.99
  ...

[*] Iniciando ataque DNS spoofing...
[*] Escuchando consultas DNS en attacker-eth0...
```

### PASO 5: Generar Tráfico DNS y Verificar el Ataque

⚠️ **IMPORTANTE - ENTENDER LA RACE CONDITION:**

El DNS spoofing es una **competencia de velocidad** entre:
- El **ATACANTE** que responde con IP falsa (10.0.0.99)
- El **DNS REAL** que responde con IP correcta (10.0.0.80)

El cliente acepta **LA PRIMERA RESPUESTA** que llegue.

#### 5.1 Hacer múltiples consultas DNS

```bash
# Hacer varias consultas (el ataque no siempre funciona al 100%)
mininet> client dig @10.0.0.53 www.banco.com +short
mininet> client dig @10.0.0.53 www.banco.com +short
mininet> client dig @10.0.0.53 www.banco.com +short
mininet> client dig @10.0.0.53 www.banco.com +short
mininet> client dig @10.0.0.53 www.banco.com +short
```

**Resultados posibles:**
- `10.0.0.99` → ✅ **ATAQUE EXITOSO** (atacante ganó la race)
- `10.0.0.80` → ⚠️ DNS real respondió primero (ataque falló esta vez)

#### 5.2 Observar en el ATACANTE

**Cuando intercepta una consulta:**
```
[INTERCEPTED] Consulta DNS para: www.banco.com
[SPOOFING]    Enviando respuesta falsa: 10.0.0.99
[SUCCESS]     Respuesta DNS falsa enviada x3 (3 paquetes totales)
[VICTIM]      Cliente deberia recibir IP: 10.0.0.99 (servidor FALSO)
[RACE]        Compitiendo con servidor DNS real en 10.0.0.53
```

#### 5.3 Observar en el IDS (MONITOR)

**El IDS detecta AMBAS respuestas:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!!!] ALERTA - DNS SPOOFING DETECTADO [!!!]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Timestamp:     2026-04-08 15:30:45
Dominio:       www.banco.com
IP Legitima:   10.0.0.80
IP Recibida:   10.0.0.99 <-- FALSA/MALICIOSA
Servidor DNS:  10.0.0.66

[CRITICO] Posible ataque DNS spoofing en progreso
[IMPACTO]  Cliente sera redirigido a servidor malicioso
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

O detecta respuestas duplicadas:
```
[*] ADVERTENCIA - Respuestas DNS conflictivas
Dominio: www.banco.com
IPs diferentes detectadas:
  - 10.0.0.80       desde 10.0.0.53
  - 10.0.0.99       desde 10.0.0.66

[SOSPECHOSO] Posible DNS spoofing o problema de cache
```

### PASO 6: Verificar el Impacto del Ataque

#### 6.1 Usar script de prueba automático

```bash
# Script que hace todas las pruebas
mininet> client bash /tmp/test_dns_spoofing.sh
```

Este script:
1. Verifica la configuración
2. Prueba DNS antes del ataque
3. Prueba DNS durante el ataque
4. Compara resultados
5. Muestra si el ataque funcionó

#### 6.2 Verificación manual

```bash
# Ver a qué IP resuelve ahora
mininet> client dig @10.0.0.53 www.banco.com +short

# Si muestra 10.0.0.99:
mininet> client curl http://www.banco.com | grep "FALSO\|PHISHING"
# Mostrará el sitio FALSO

# Comparación directa:
mininet> client curl http://10.0.0.80 | grep -i legitimo
mininet> client curl http://10.0.0.99 | grep -i falso
```

### PASO 7: Activar Sistema de Defensa (Opcional)

```bash
# En otra terminal del monitor
mininet> xterm monitor

# Ejecutar sistema de defensa
monitor# python3 /tmp/dns_defender.py
```

**El defensor detectará y BLOQUEARÁ ataques:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!!!] ATAQUE DNS BLOQUEADO #1 [!!!]
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Dominio:       www.banco.com
IP Legitima:   10.0.0.80
IP Falsa:      10.0.0.99 <-- BLOQUEADA

[ACCION] Enviando respuesta DNS correcta al cliente 10.0.0.10
[OK] Respuesta correctiva enviada
[PROTECCION] Cliente recibira IP correcta: 10.0.0.80
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

### PASO 8: Limpiar y Restaurar

```bash
# Detener el ataque (Ctrl+C en terminal del atacante)

# Limpiar cache DNS del cliente (si existe)
mininet> client systemd-resolve --flush-caches

# Verificar que vuelve a resolver correctamente
mininet> client dig @10.0.0.53 www.banco.com +short
# Debería mostrar: 10.0.0.80
```

## Cómo Funciona el Ataque

### Ataque DNS Spoofing - Paso a Paso

1. **Cliente envía consulta DNS**: `www.banco.com` a 10.0.0.53
2. **Atacante intercepta** la consulta (está escuchando en el switch con port mirroring)
3. **RACE CONDITION** - Dos respuestas simultáneas:
   - **Atacante envía respuesta FALSA**: `10.0.0.99` (x3 veces para aumentar probabilidad)
   - **DNS real envía respuesta CORRECTA**: `10.0.0.80`
4. **Cliente recibe** la primera respuesta que llegue
5. **Si el atacante gana**: Cliente va a `10.0.0.99` (servidor falso/phishing)
6. **Si el DNS real gana**: Cliente va a `10.0.0.80` (servidor legítimo)

### Diagrama del Ataque

```
Cliente (10.0.0.10)
    |
    | "¿Cuál es la IP de www.banco.com?"
    v
[Switch con Port Mirroring]
    |
    +---> DNS Real (10.0.0.53)
    |         |
    |         +---> Responde: 10.0.0.80 ⚡
    |
    +---> Atacante (10.0.0.66)
              |
              +---> Responde: 10.0.0.99 ⚡⚡⚡ (x3 veces)
    
Cliente acepta LA PRIMERA RESPUESTA que llegue
```

### ⚠️ Por Qué el Ataque NO Siempre Funciona al 100%

**Esto es REALISTA y EDUCATIVO:**

El DNS spoofing es una **race condition** (condición de carrera):
- 🏃 El atacante intenta ser más rápido
- 🏃 El DNS real también responde inmediatamente
- 🎲 Es probabilístico, no determinístico

**Factores que afectan el éxito:**
1. **Distancia de red**: El atacante está en la misma LAN (ventaja)
2. **Procesamiento**: Scapy puede ser más lento que dnsmasq nativo
3. **Múltiples respuestas**: El atacante envía x3 para aumentar probabilidad
4. **Switch flooding**: Port mirroring asegura que el atacante vea el tráfico

**Porcentaje de éxito típico:** 30-70% (varía)

### Técnicas Utilizadas

- **Race Condition**: Competencia de velocidad entre atacante y DNS real
- **Packet Spoofing**: El atacante falsifica la IP origen (10.0.0.53)
- **Transaction ID Matching**: Mismo ID que la consulta original
- **No hay autenticación**: DNS no verifica quién responde (sin DNSSEC)
- **Port Mirroring**: El monitor y atacante ven todo el tráfico
- **Multiple Responses**: Enviar 3 respuestas aumenta probabilidad de éxito

## Sistema de Detección - Métodos

### El IDS detecta:

1. **Respuestas con IPs incorrectas** (comparando con tabla de registros conocidos)
2. **Múltiples respuestas diferentes** para el mismo dominio
3. **Respuestas de servidores no autorizados**
4. **Tiempo de respuesta anómalo** (muy rápido = sospechoso)

### Ejemplo de Detección:

```
Consulta:  www.banco.com
Esperado:  10.0.0.80 (desde 10.0.0.53)
Recibido:  10.0.0.99 (desde 10.0.0.66) <- ALERTA!
```

## Sistema de Defensa - Contramedidas

### El IPS (defensor) hace:

1. **Detecta** respuestas DNS falsas
2. **Envía respuestas correctas** al cliente inmediatamente
3. **Registra** todos los ataques bloqueados
4. **Protege** al cliente en tiempo real

## Logs Generados

- `/tmp/dns_attack_log.txt` - Ataques detectados por el IDS
- `/tmp/dns_defense_log.txt` - Ataques bloqueados por el IPS  
- `/tmp/dns_legitimo.log` - Log del servidor DNS legítimo

## Experimentos Adicionales

### Experimento 1: Medir Tasa de Éxito del Ataque

```bash
# Script para probar 20 veces y contar éxitos
mininet> client bash -c 'for i in {1..20}; do dig @10.0.0.53 www.banco.com +short; sleep 0.5; done | sort | uniq -c'
```

**Resultado típico:**
```
     12 10.0.0.80   (DNS real ganó 12 veces - 60%)
      8 10.0.0.99   (Atacante ganó 8 veces - 40%)
```

### Experimento 2: Observar Respuestas Duplicadas

```bash
# Capturar en el cliente
mininet> client tcpdump -i client-eth0 -n port 53 -v

# En otra terminal:
mininet> client dig @10.0.0.53 www.banco.com
```

Verás **DOS respuestas** para la misma consulta.

### Experimento 3: Comparar Tiempos de Respuesta

```bash
# Ver qué tan rápido responde cada uno
mininet> client tcpdump -i client-eth0 -n port 53 -ttt -v

# Generar consulta:
mininet> client dig @10.0.0.53 www.banco.com
```

La respuesta que llegue primero (menor timestamp) es la que el cliente usa.

### Experimento 4: Ataque Sin IDS vs Con IDS

**Sin IDS activo:**
- El ataque ocurre silenciosamente
- Nadie detecta las respuestas duplicadas

**Con IDS activo:**
- Cada intento de spoofing genera una alerta
- Se registra en `/tmp/dns_attack_log.txt`
- Administrador puede tomar acción

### Experimento 5: Defensa Activa

```bash
# Con defensor activo
mininet> xterm monitor
monitor# python3 /tmp/dns_defender.py

# El defensor contrarresta enviando MUCHAS respuestas correctas
# Aumenta la probabilidad de que el cliente reciba la correcta
```

## Interpretación de Resultados

### ✅ Ataque Exitoso

**Síntomas:**
```bash
mininet> client dig @10.0.0.53 www.banco.com +short
10.0.0.99   # IP del servidor FALSO

mininet> client curl http://www.banco.com | grep FALSO
<p>IP: 10.0.0.99 (SERVIDOR FALSO)</p>
```

**Impacto:**
- ✅ Cliente fue redirigido al servidor malicioso
- ✅ Vulnerable a phishing
- ✅ Posible robo de credenciales
- ✅ IDS debería haber alertado

### ⚠️ Ataque Parcial (Común)

**Síntomas:**
```bash
# A veces resuelve correctamente, a veces incorrectamente
mininet> client dig @10.0.0.53 www.banco.com +short
10.0.0.80   # Correcto

mininet> client dig @10.0.0.53 www.banco.com +short
10.0.0.99   # Falso!

mininet> client dig @10.0.0.53 www.banco.com +short
10.0.0.80   # Correcto
```

**Interpretación:**
- ⚡ Race condition en acción
- 📊 Mide tasa de éxito con múltiples pruebas
- 🎯 Incluso 30% de éxito es peligroso en la realidad

### ❌ Ataque No Funciona

**Posibles causas:**

1. **Atacante no está capturando**
```bash
# Verificar:
attacker# tcpdump -i attacker-eth0 port 53 -c 5
# Si no ves paquetes, el port mirroring falló
```

2. **DNS real siempre gana**
```bash
# El servidor DNS real está optimizado y es muy rápido
# Esto es NORMAL - el ataque no garantiza 100% de éxito
# En la realidad: 30-50% de éxito ya es suficiente para el atacante
```

3. **Cliente tiene cache DNS**
```bash
# Limpiar cache:
mininet> client systemd-resolve --flush-caches
```

### 🔍 IDS Debe Detectar Siempre

**Incluso si el ataque falla, el IDS detecta:**

```bash
# IDS ve AMBAS respuestas (real y falsa)
[*] ADVERTENCIA - Respuestas DNS conflictivas
Dominio: www.banco.com
IPs diferentes detectadas:
  - 10.0.0.80       desde 10.0.0.53
  - 10.0.0.99       desde 10.0.0.66
```

**Esto es CLAVE:** El IDS no depende de quién gane la race, detecta el intento.

## Estadísticas Realistas

### Tasa de Éxito del Ataque

| Escenario | Tasa de Éxito | Observaciones |
|-----------|---------------|---------------|
| Sin defensa | 30-70% | Varía según latencia de red |
| Con IDS (solo detección) | 30-70% | IDS alerta pero no bloquea |
| Con IPS (defensa activa) | 5-20% | IPS contrarresta con múltiples respuestas |
| Con DNSSEC | 0% | Respuestas sin firma válida se rechazan |

### Detección por el IDS

| Condición | Detección IDS |
|-----------|---------------|
| Ataque exitoso | ✅ 100% (ve respuesta falsa) |
| Ataque fallido | ✅ 100% (ve respuestas duplicadas) |
| Sin ataque | ✅ 0% (no hay alertas falsas) |

## Troubleshooting

### Experimento 1: Ver Diferencia con/sin Ataque

```bash
# SIN ataque
mininet> client curl http://www.banco.com | grep LEGITIMO

# CON ataque
mininet> client curl http://www.banco.com | grep FALSO
```

### Experimento 2: Capturar Tráfico DNS

```bash
# En el cliente
mininet> client tcpdump -i client-eth0 -n port 53 -v
```

### Experimento 3: Múltiples Consultas

```bash
# Hacer varias consultas para ver cache poisoning
for i in {1..5}; do
  mininet> client nslookup www.banco.com
  sleep 1
done
```

## Conceptos de Seguridad Demostrados

1. **DNS Spoofing** - Envenenamiento de respuestas DNS
2. **Cache Poisoning** - Contaminación de cache DNS
3. **Phishing** - Sitio web falso para robar datos
4. **Man-in-the-Middle** - Interceptación de tráfico
5. **Race Condition** - Competencia de velocidad de respuesta
6. **Detección de Anomalías** - IDS basado en firmas
7. **Defensa Activa** - IPS que bloquea ataques

## Mitigaciones en Redes Reales

### Soluciones Técnicas:

1. **DNSSEC** - Firma criptográfica de respuestas DNS
2. **DNS over HTTPS (DoH)** - Cifrado de consultas DNS
3. **DNS over TLS (DoT)** - Consultas DNS en TLS
4. **Validación de respuestas** - Verificar múltiples servidores
5. **HTTPS obligatorio** - Certificados SSL/TLS
6. **HSTS** - HTTP Strict Transport Security
7. **Firewall DNS** - Filtrar respuestas sospechosas

### Mejores Prácticas:

- Usar servidores DNS confiables (Google 8.8.8.8, Cloudflare 1.1.1.1)
- Habilitar DNSSEC en el servidor y cliente
- Implementar monitoreo de tráfico DNS
- Educar a usuarios sobre phishing
- Usar certificados SSL/TLS válidos
- Implementar autenticación de dos factores

## Troubleshooting

### Problema: El ataque NO funciona (siempre resuelve a 10.0.0.80)

**Esto es NORMAL y ESPERADO** en muchos casos.

**¿Por qué?**
- El DNS spoofing es una **race condition**
- No garantiza 100% de éxito
- El DNS real puede ser más rápido

**Soluciones:**

1. **Hacer múltiples pruebas** (el ataque es probabilístico):
```bash
# Repetir 10-20 veces
for i in {1..10}; do 
  mininet> client dig @10.0.0.53 www.banco.com +short
done
```

2. **Verificar que el atacante está interceptando**:
```bash
attacker# tcpdump -i attacker-eth0 port 53 -n
# Debe ver consultas DNS pasando
```

3. **Verificar port mirroring**:
```bash
mininet> sh ovs-vsctl list mirror
# Debe mostrar configuración de mirroring
```

4. **Aceptar el resultado realista**:
- ✅ 30-50% de éxito = **Ataque realista y funcional**
- ✅ IDS detecta el 100% de los intentos
- ✅ Demuestra por qué DNSSEC es necesario

### Problema: IDS no detecta el ataque

**Verificar:**
```bash
# En el monitor, ver si hay tráfico DNS
monitor# tcpdump -i monitor-eth0 port 53 -n -c 10

# Generar tráfico desde el cliente:
mininet> client dig @10.0.0.53 www.banco.com
```

**Si el monitor NO ve tráfico:**
```bash
# Reconfigurar port mirroring
mininet> sh ovs-vsctl -- set Bridge s1 mirrors=@m -- \
  --id=@monitor-eth0 get Port monitor-eth0 -- \
  --id=@m create Mirror name=dns_mirror select-all=true output-port=@monitor-eth0
```

**IMPORTANTE:** Incluso si el ataque falla (DNS real gana), el IDS debe detectar respuestas duplicadas.

### Problema: "Could not resolve host"

Ver `TROUBLESHOOTING_DNS.md` para soluciones detalladas.

**Solución rápida:**
```bash
# Verificar DNS funciona:
mininet> client dig @10.0.0.53 www.banco.com +short

# Usar IP directamente (siempre funciona):
mininet> client curl http://10.0.0.80  # LEGÍTIMO
mininet> client curl http://10.0.0.99  # FALSO
```

## Comparación: ARP Spoofing vs DNS Spoofing

| Aspecto | ARP Spoofing | DNS Spoofing |
|---------|--------------|--------------|
| Capa OSI | Capa 2 (Enlace) | Capa 7 (Aplicación) |
| Objetivo | Tabla ARP | Cache DNS |
| Alcance | Red local (LAN) | Global (puede ser remoto) |
| Persistencia | Temporal (hasta timeout ARP) | Cache DNS (varios minutos/horas) |
| Detección | Cambios de MAC | IPs incorrectas para dominios |
| Mitigación | ARP estático, DAI | DNSSEC, DoH, DoT |

## Referencias

- [DNS Spoofing - Wikipedia](https://en.wikipedia.org/wiki/DNS_spoofing)
- [DNSSEC - RFC 4033](https://tools.ietf.org/html/rfc4033)
- [DNS over HTTPS - RFC 8484](https://tools.ietf.org/html/rfc8484)

## Advertencia Legal

⚠️ **ADVERTENCIA:** Este escenario es solo para propósitos educativos en entornos controlados.
Realizar DNS spoofing en redes sin autorización es **ILEGAL** y puede resultar en consecuencias legales graves.

---

**Autor:** Escenario educativo de seguridad de redes  
**Versión:** 1.0  
**Fecha:** 2026
