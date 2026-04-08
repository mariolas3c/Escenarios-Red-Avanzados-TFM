# Troubleshooting - Escenario DNS Spoofing

## Problema: "Could not resolve host: www.banco.com"

### Causa
El cliente no puede resolver nombres de dominio porque:
1. El servidor DNS no está funcionando
2. `/etc/resolv.conf` no está configurado correctamente
3. `systemd-resolved` está interfiriendo

### Solución 1: Acceder por IP directamente (más simple)

```bash
# En lugar de:
mininet> client curl http://www.banco.com

# Usar:
mininet> client curl http://10.0.0.80  # Servidor LEGITIMO
mininet> client curl http://10.0.0.99  # Servidor FALSO
```

**Ventaja**: No depende del DNS, siempre funciona.

### Solución 2: Verificar servidor DNS

```bash
# Verificar que dnsmasq está corriendo
mininet> dns ps aux | grep dnsmasq

# Si NO está corriendo, iniciarlo:
mininet> dns dnsmasq -C /tmp/dns_legitimo.conf &

# Probar DNS directamente:
mininet> client nslookup www.banco.com 10.0.0.53
```

### Solución 3: Usar /etc/hosts (respaldo)

```bash
# El escenario ya añade entradas en /etc/hosts
# Verificar:
mininet> client cat /etc/hosts | grep banco

# Debería mostrar:
# 10.0.0.80 www.banco.com banco.com
```

Con `/etc/hosts` configurado, `curl http://www.banco.com` debería funcionar.

### Solución 4: Verificar /etc/resolv.conf

```bash
# Verificar configuración DNS
mininet> client cat /etc/resolv.conf

# Debería mostrar:
# nameserver 10.0.0.53

# Si no, configurarlo:
mininet> client bash -c 'echo "nameserver 10.0.0.53" > /etc/resolv.conf'
```

---

## Problema: DNS funciona con nslookup pero NO con curl

### Causa
`curl` puede estar usando un cache DNS diferente o `systemd-resolved` está interfiriendo.

### Solución

```bash
# Opción A: Detener systemd-resolved
mininet> client systemctl stop systemd-resolved

# Opción B: Usar /etc/hosts (ya está configurado)
mininet> client cat /etc/hosts | grep banco

# Opción C: Usar IP directamente
mininet> client curl http://10.0.0.80
```

---

## Problema: Servidor DNS no responde

### Verificar el problema

```bash
# Ver si dnsmasq está corriendo
mininet> dns pgrep dnsmasq

# Ver logs
mininet> dns cat /tmp/dns_legitimo.log

# Ver si el puerto 53 está en uso
mininet> dns netstat -tulpn | grep :53
```

### Solución

```bash
# Matar procesos DNS anteriores
mininet> dns pkill -9 dnsmasq

# Reiniciar dnsmasq
mininet> dns dnsmasq -C /tmp/dns_legitimo.conf --log-facility=/tmp/dns_legitimo.log &

# Verificar
mininet> dns pgrep dnsmasq
```

---

## Problema: Servidor web no responde

### Verificar

```bash
# Ver si Python HTTP server está corriendo
mininet> webserver pgrep -f "http.server"

# Probar acceso directo por IP
mininet> client curl http://10.0.0.80
```

### Solución

```bash
# Reiniciar servidor web LEGITIMO
mininet> webserver pkill -f "http.server"
mininet> webserver cd /tmp/webserver && python3 -m http.server 80 &

# Reiniciar servidor web FALSO
mininet> fakeserver pkill -f "http.server"
mininet> fakeserver cd /tmp/fakeserver && python3 -m http.server 80 &

# Verificar
mininet> client curl http://10.0.0.80
mininet> client curl http://10.0.0.99
```

---

## Problema: Ataque DNS no funciona

### Causa
El atacante no está interceptando las consultas DNS.

### Verificar

```bash
# En el atacante, verificar que está capturando
attacker# tcpdump -i attacker-eth0 -n port 53

# Generar tráfico desde el cliente:
mininet> client nslookup www.banco.com 10.0.0.53
```

### Solución

```bash
# Asegurarse de que el script de ataque está corriendo
attacker# python3 /tmp/dns_spoof_attack.py

# Verificar interfaz correcta
attacker# ifconfig | grep attacker-eth0
```

---

## Problema: IDS no detecta el ataque

### Causa
Port mirroring no está configurado o el monitor no está capturando.

### Verificar

```bash
# Ver tráfico en el monitor
mininet> monitor tcpdump -i monitor-eth0 -n port 53 -c 10

# Generar tráfico:
mininet> client nslookup www.banco.com 10.0.0.53
```

### Solución

```bash
# Reconfigurar port mirroring
mininet> sh ovs-vsctl -- set Bridge s1 mirrors=@m -- \
  --id=@monitor-eth0 get Port monitor-eth0 -- \
  --id=@m create Mirror name=dns_mirror select-all=true output-port=@monitor-eth0

# Modo promiscuo
mininet> monitor ifconfig monitor-eth0 promisc
```

---

## Flujo de Prueba Completo (Paso a Paso)

### 1. Verificar servicios básicos

```bash
# DNS
mininet> dns pgrep dnsmasq

# Web servers
mininet> webserver pgrep -f http.server
mininet> fakeserver pgrep -f http.server
```

### 2. Probar acceso por IP (NO requiere DNS)

```bash
mininet> client curl http://10.0.0.80
# Debe mostrar: "BANCO LEGITIMO"

mininet> client curl http://10.0.0.99
# Debe mostrar: "SITIO PHISHING"
```

### 3. Probar DNS directamente

```bash
mininet> client nslookup www.banco.com 10.0.0.53
# Debe resolver a: 10.0.0.80
```

### 4. Probar acceso por nombre (requiere DNS O /etc/hosts)

```bash
mininet> client curl http://www.banco.com
# Debería funcionar gracias a /etc/hosts
```

### 5. Ejecutar ataque

```bash
# Terminal atacante:
attacker# python3 /tmp/dns_spoof_attack.py

# Generar consulta:
mininet> client nslookup www.banco.com 10.0.0.53
```

### 6. Verificar ataque funcionó

```bash
# Si el ataque funciona, puede resolver a 10.0.0.99
# Pero /etc/hosts tiene prioridad, así que puede seguir yendo a 10.0.0.80
```

---

## Comandos de Diagnóstico Útiles

```bash
# Ver configuración DNS
mininet> client cat /etc/resolv.conf

# Ver entradas estáticas
mininet> client cat /etc/hosts | grep banco

# Probar DNS manualmente
mininet> client dig @10.0.0.53 www.banco.com
mininet> client host www.banco.com 10.0.0.53

# Ver si hay respuestas DNS en la red
mininet> client tcpdump -i client-eth0 -n port 53 -c 5

# Ver logs del servidor DNS
mininet> dns cat /tmp/dns_legitimo.log | tail -20

# Verificar procesos
mininet> dns pgrep dnsmasq
mininet> webserver pgrep -f http
```

---

## Método Alternativo: Usar IPs en lugar de nombres

Si el DNS sigue sin funcionar, puedes simular el ataque de otra forma:

```bash
# Estado NORMAL:
mininet> client curl http://10.0.0.80
# Muestra sitio LEGITIMO

# Simulando ataque DNS (cambiar /etc/hosts):
mininet> client bash -c 'echo "10.0.0.99 www.banco.com" > /tmp/hosts_fake'
mininet> client bash -c 'cat /tmp/hosts_fake > /etc/hosts'

# Ahora:
mininet> client curl http://www.banco.com
# Muestra sitio FALSO (10.0.0.99)

# Restaurar:
mininet> client bash -c 'echo "10.0.0.80 www.banco.com" > /etc/hosts'
```

---

## Resumen de Soluciones Rápidas

| Problema | Solución Rápida |
|----------|----------------|
| No resuelve dominios | Usar IP: `curl http://10.0.0.80` |
| DNS no responde | `dns dnsmasq -C /tmp/dns_legitimo.conf &` |
| Web server caído | `webserver python3 -m http.server 80 &` |
| Ataque no funciona | Verificar con `tcpdump -i attacker-eth0 port 53` |
| IDS no detecta | Reconfigurar port mirroring |

---

**Recuerda**: Siempre puedes usar IPs directamente (`10.0.0.80` y `10.0.0.99`) para probar los servidores sin depender del DNS.
