# Escenario: BGP Hijacking multi-AS con FRR

## Descripción General

Este escenario reproduce un **BGP hijacking** sobre una internet en miniatura
montada con Mininet. Cuatro sistemas autónomos (AS) se interconectan mediante
un *Internet Exchange Point* (IXP) y mantienen sesiones eBGP en malla completa
gestionadas por **FRR** (`bgpd` + `zebra`).

El AS atacante (AS65003) anuncia el prefijo de la víctima (AS65001) y consigue
desviar el tráfico de un cliente (AS65004) hacia un servidor impostor. Se
demuestran dos variantes clásicas:

- **Prefix hijack idéntico** (10.0.10.0/24): el atacante anuncia el mismo
  prefijo y gana el desempate de selección de mejor ruta.
- **Sub-prefix hijack** (10.0.10.0/25): el atacante anuncia un prefijo
  *more-specific* y se lleva todo el tráfico por **longest-prefix match**.

Finalmente se aplica una mitigación clásica: una `prefix-list` en el AS cliente
que descarta los anuncios falsos del atacante (equivalente manual al filtrado
RPKI / IRR-based).

## Topología de Red

```
   AS65001                                AS65003
  [h_victima]                            [h_atacante]
  10.0.10.10                              10.0.30.10
       |                                      |
   [r1] 0.0.0.1                           [r3] 0.0.0.0  <- router-id menor
   100.64.0.1                              100.64.0.3
       |                                      |
       +---------- s1 (IXP 100.64.0.0/24) ----+
       |                                      |
   100.64.0.2                              100.64.0.4
   [r2] 0.0.0.2                           [r4] 0.0.0.4
   AS65002                                AS65004
   (transito,                                  |
    sin host)                              [h_cliente]
                                           10.0.40.10

                       [monitor] 100.64.0.100
                    (port mirror + tshark)
```

- Todos los routers son hosts Mininet con `net.ipv4.ip_forward=1` y dos
  interfaces (IXP + LAN cliente). `r2` solo tiene interfaz al IXP.
- Cada router corre `zebra` + `bgpd` en su propio namespace, con configuración
  aislada en `/tmp/r{1,2,3,4}/`.
- El `monitor` recibe una copia de todo el tráfico del IXP vía OVS port
  mirroring, permitiendo inspeccionar mensajes BGP con `tshark`/`tcpdump`.
- El atacante tiene la dirección secundaria `10.0.10.10/32` en su host
  `h_atacante` y sirve un HTTP impostor sobre ella; así, cuando el hijack
  redirige el tráfico, llega a `h_atacante` y responde con una bandera visible.

## Hosts y Configuración

| Host         | AS      | IP IXP        | IP LAN        | Rol                                           |
|--------------|---------|---------------|---------------|-----------------------------------------------|
| r1           | AS65001 | 100.64.0.1/24 | 10.0.10.1/24  | Router víctima (anuncia 10.0.10.0/24)         |
| r2           | AS65002 | 100.64.0.2/24 | —             | Router de tránsito                            |
| r3           | AS65003 | 100.64.0.3/24 | 10.0.30.1/24  | Router atacante (router-id 0.0.0.0)           |
| r4           | AS65004 | 100.64.0.4/24 | 10.0.40.1/24  | Router cliente / observador del hijack        |
| h_victima    | AS65001 | —             | 10.0.10.10/24 | HTTP legítimo (`Servidor LEGITIMO AS65001`)   |
| h_atacante   | AS65003 | —             | 10.0.30.10/24 | HTTP impostor en alias 10.0.10.10/32          |
| h_cliente    | AS65004 | —             | 10.0.40.10/24 | Origen del tráfico de prueba (`curl`)         |
| monitor      | —       | 100.64.0.100  | —             | Captura pasiva del IXP                        |

**Datos BGP relevantes** (todos con `timers 3 9` para convergencia rápida):

- `r1` anuncia `10.0.10.0/24`
- `r3` anuncia `10.0.30.0/24` inicialmente; el ataque añade `10.0.10.0/24` o `10.0.10.0/25`
- `r4` anuncia `10.0.40.0/24`
- `r2` no anuncia prefijos cliente (solo redistribuye)

## Archivos del Proyecto

| Archivo                          | Descripción                                                          |
|----------------------------------|----------------------------------------------------------------------|
| `bgp_scenario.py`                | Topología Mininet + arranque FRR + port mirroring + servicios HTTP   |
| `bgp_hijack_attack.py`           | Modos `status` / `prefix-hijack` / `subprefix-hijack` / `withdraw` / `defend` |
| `setup_bgp_scenario.sh`          | Instala FRR, deshabilita el servicio del host, AppArmor en complain  |
| `README_BGP_HIJACKING.md`        | Este documento                                                       |

## Requisitos Previos

- Ubuntu 20.04 o superior con kernel ≥ 5.x
- Mininet ≥ 2.3 (`apt install mininet`)
- Open vSwitch (incluido con Mininet)
- FRR ≥ 7.4 (instalado por `setup_bgp_scenario.sh`)
- `tshark` / `tcpdump` para inspección BGP
- Permisos `sudo` para todo

### Instalación

```bash
cd bgp-hijacking
sudo ./setup_bgp_scenario.sh
```

El script:

1. Instala `frr`, `frr-pythontools`, `tshark`, `tcpdump`, `curl`, `python3-scapy`.
2. Deshabilita y detiene `frr.service` del host (evita choques de puertos con
   los daemons que corren dentro de cada namespace Mininet).
3. Pone los perfiles AppArmor de `zebra` y `bgpd` en modo `complain` (sin esto
   FRR no puede leer/escribir en `/tmp/r*`).
4. Copia `bgp_hijack_attack.py` a `/tmp/`.
5. Genera `/tmp/bgp_quickstart.txt` como referencia rápida.

## Cómo Funciona el Escenario

1. **Limpieza** previa: `mn -c`, mata cualquier `bgpd`/`zebra` previo y borra
   `/tmp/r*`.
2. **Construcción** de la red Mininet con 4 routers, 3 hosts cliente, 1 monitor
   y un switch OVS (`s1`) actuando como IXP.
3. **Asignación de IPs** manual a cada interfaz; los hosts cliente obtienen
   ruta por defecto hacia su router AS.
4. **Generación dinámica** de `zebra.conf` y `bgpd.conf` por router. Puntos
   críticos de la config:
   - `no bgp ebgp-requires-policy` — sin esto, FRR ≥ 7.4 descarta todos los
     anuncios eBGP.
   - `no bgp network import-check` — permite anunciar redes aunque no estén
     conectadas localmente (necesario en el modo hijack).
   - `timers bgp 3 9` — keepalive/hold cortos para que los cambios converjan
     en segundos.
   - `bgp router-id 0.0.0.0` en `r3` — gana el desempate ante AS_PATH idéntico.
5. **Arranque** de `zebra` y `bgpd` con `-u root -g root` para conservar
   `CAP_NET_ADMIN` dentro del namespace; sockets y PIDs en `/tmp/r{1..4}/`.
6. **Port mirroring** en `s1` hacia el `monitor` (mismo patrón que
   `port-scanning/`).
7. **Servidores HTTP**: uno legítimo en `h_victima` y uno impostor en
   `h_atacante` bind a `10.0.10.10/32`. La página HTML actúa como bandera
   visible para demostrar el éxito o no del hijack.

## Fases de Uso

### FASE 1 - Verificar peers BGP

    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp summary"
    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp"
    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp 10.0.10.0/24"

Los 3 vecinos de `r4` (100.64.0.1, .2 y .3) deben aparecer en estado `Established`.

### FASE 2 - Tráfico legítimo (antes del hijack)

    mininet> h_cliente curl -s http://10.0.10.10

Salida esperada: `<h1>Servidor LEGITIMO AS65001</h1>`.

### FASE 3 - Hijack de prefijo idéntico

    mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode prefix-hijack

`r3` inyecta `network 10.0.10.0/24` en su BGP. La ruta llega a `r4`, que ahora
tiene dos candidatas con `AS_PATH` de igual longitud; el desempate cae en el
router-id menor (`r3 = 0.0.0.0 < r1 = 0.0.0.1`).

### FASE 4 - Verificar redirección

    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp 10.0.10.0/24"
    mininet> h_cliente curl -s http://10.0.10.10

Salida esperada: `<h1>!!! HIJACKED por AS65003 !!!</h1>`. La tabla BGP muestra
dos paths y el de AS65003 marcado con `*>` (best path).

### FASE 5 - Sub-prefix hijack

    mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode subprefix-hijack
    mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp 10.0.10.0/25"

`r3` anuncia `10.0.10.0/25`. Por **longest-prefix match**, cualquier
destinatario en `10.0.10.0-127` se enruta por `r3`, sin importar el desempate.

### FASE 6 - Inspección de mensajes BGP

    mininet> monitor tshark -i monitor-eth0 -Y bgp -O bgp -c 20

Para ver UPDATE/OPEN/KEEPALIVE en tiempo real. Tras lanzar el `tshark`, vuelve
a inyectar el hijack (o ejecuta `clear ip bgp *` en algún router) para
capturar mensajes nuevos.

### FASE 7 - Defensa con prefix-list

    mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode defend

Aplica en `r4` una `prefix-list` que deniega cualquier anuncio entrante desde
`100.64.0.3` que caiga dentro de `10.0.10.0/24 le 32`. Equivalente a un filtro
RPKI manual.

    mininet> h_cliente curl -s http://10.0.10.10

Debe volver a responder `Servidor LEGITIMO AS65001`.

### FASE 8 - Retirar el hijack

    mininet> r3 python3 /tmp/bgp_hijack_attack.py --mode withdraw

Elimina `network 10.0.10.0/24` y `network 10.0.10.0/25` de `r3`.

## Diagnóstico

```bash
# Estado de sesiones y rutas en cada router
mininet> r1 vtysh --vty_socket /tmp/r1 -c "show ip bgp summary"
mininet> r3 vtysh --vty_socket /tmp/r3 -c "show ip bgp"
mininet> r4 vtysh --vty_socket /tmp/r4 -c "show ip bgp 10.0.10.0/24"

# Tabla del kernel (ruta efectiva)
mininet> r4 ip route
mininet> r4 ip route get 10.0.10.10

# Logs de FRR
mininet> sh tail -f /tmp/r4/bgpd.log
mininet> sh tail -f /tmp/r3/bgpd.log

# Estado del port mirror
mininet> sh ovs-vsctl list mirror
mininet> sh ovs-vsctl list bridge s1

# Captura cruda de BGP
mininet> monitor tcpdump -i monitor-eth0 -nn tcp port 179 -c 30
```

### Problemas habituales

| Síntoma                                            | Causa probable / fix                                              |
|----------------------------------------------------|--------------------------------------------------------------------|
| `bgpd: Permission denied` en `/tmp/r*`             | AppArmor en enforce. Vuelve a ejecutar `setup_bgp_scenario.sh`.    |
| Peers nunca llegan a `Established`                 | `frr.service` del host está activo y bloquea TCP/179. `systemctl disable --now frr`. |
| Anuncios no se propagan                            | Falta `no bgp ebgp-requires-policy` (FRR ≥ 7.4).                   |
| `curl` cuelga aunque BGP esté correcto             | `rp_filter` activo. El escenario lo desactiva, comprueba con `sysctl net.ipv4.conf.all.rp_filter`. |
| `r3` no aparece como mejor ruta tras `prefix-hijack` | `r1` tiene un router-id menor que `r3`. Revisa `bgpd.conf` de ambos. |

## Limpieza entre ejecuciones

```bash
sudo mn -c
sudo pkill -9 bgpd
sudo pkill -9 zebra
sudo rm -rf /tmp/r1 /tmp/r2 /tmp/r3 /tmp/r4
sudo rm -f  /tmp/vtysh_r3.txt /tmp/vtysh_r4.txt
```

## Aviso legal

Este escenario es estrictamente educativo. Anunciar prefijos ajenos por BGP
sobre el Internet real constituye una infracción grave en muchas
jurisdicciones y vulnera los acuerdos de paz con los operadores de tránsito.
