l# Escenario de Segmentación con VLANs en Mininet

## Descripción del Escenario

Este escenario implementa una topología de red con segmentación VLAN que incluye:

- **3 VLANs diferentes** con aislamiento completo
- **Múltiples switches** configurados con puertos trunk y access
- **Servidor DHCP** para asignación automática de IPs
- **Demostración de dominios de broadcast** separados

## Topología de Red

```
                    Switch s1 (Trunk)
                    /      |      \
                   /       |       \
        (VLAN 10) s2    (VLAN 20) s3    (VLAN 30) s4
          /  |  \         /    \          /    \
         /   |   \       /      \        /      \
       h1   h2  dhcp   h3      h4      h5      h6
```

### Segmentos de Red

1. **VLAN 10 - Management** (10.0.10.0/24)
   - h1: 10.0.10.10
   - h2: 10.0.10.20
   - dhcp: 10.0.10.1 (Servidor DHCP)
   - Rango DHCP: 10.0.10.50 - 10.0.10.100

2. **VLAN 20 - Departamento A** (10.0.20.0/24)
   - h3: 10.0.20.10
   - h4: 10.0.20.20

3. **VLAN 30 - Departamento B** (10.0.30.0/24)
   - h5: 10.0.30.10
   - h6: 10.0.30.20


## Instalación y Ejecución

### 1. Preparar los archivos

```bash
# Dar permisos de ejecución
chmod +x vlan_topology.py
chmod +x test_vlans.sh

# Ver guía de pruebas
./test_vlans.sh
```

### 2. Ejecutar la topología

```bash
# Limpiar cualquier configuración previa
sudo mn -c

# Ejecutar la topología (requiere sudo)
sudo python vlan_topology.py
```

## Pruebas y Demostraciones

### Prueba 1: Conectividad Intra-VLAN

Verifica que los hosts dentro de la misma VLAN pueden comunicarse:

```bash
mininet> h1 ping -c 3 h2        # VLAN 10: Debe funcionar
mininet> h3 ping -c 3 h4        # VLAN 20: Debe funcionar
mininet> h5 ping -c 3 h6        # VLAN 30: Debe funcionar
```

**Resultado esperado:** Todas las pruebas deben tener éxito (0% packet loss)

### Prueba 2: Aislamiento Inter-VLAN

Verifica que los hosts en diferentes VLANs NO pueden comunicarse:

```bash
mininet> h1 ping -c 3 10.0.20.10    # VLAN 10 -> VLAN 20
mininet> h3 ping -c 3 10.0.30.10    # VLAN 20 -> VLAN 30
mininet> h5 ping -c 3 10.0.10.10    # VLAN 30 -> VLAN 10
```

**Resultado esperado:** Todas las pruebas deben fallar (100% packet loss)

### Prueba 3: Dominios de Broadcast Separados

Esta es la prueba más importante para demostrar la segmentación.

#### 3a. Capturar broadcasts dentro de la misma VLAN

```bash
# Terminal 1: Capturar tráfico ARP en h2 (VLAN 10)
mininet> xterm h2
mininet> h2 tcpdump -i h2-eth0 arp -n &

# Terminal 2: Generar broadcasts ARP desde h1 (VLAN 10)
mininet> h1 arping -c 5 10.0.10.20
```

**Resultado esperado:** h2 DEBE ver los ARP requests de h1

#### 3b. Verificar que otras VLANs NO ven los broadcasts

```bash
# Terminal 1: Capturar tráfico en h3 (VLAN 20)
mininet> xterm h3
mininet> h3 tcpdump -i h3-eth0 arp -n &

# Terminal 2: Generar broadcasts desde h1 (VLAN 10)
mininet> h1 arping -c 5 10.0.10.20
```

**Resultado esperado:** h3 NO debe ver ningún tráfico de VLAN 10

#### 3c. Broadcast dirigido en cada VLAN

```bash
# Broadcast en VLAN 10
mininet> h1 arping -c 3 -b -I h1-eth0 10.0.10.255

# Broadcast en VLAN 20
mininet> h3 arping -c 3 -b -I h3-eth0 10.0.20.255

# Broadcast en VLAN 30
mininet> h5 arping -c 3 -b -I h5-eth0 10.0.30.255
```

### Prueba 4: Servidor DHCP

```bash
# Liberar la IP estática de h1
mininet> h1 ip addr flush dev h1-eth0

# Solicitar IP por DHCP
mininet> h1 dhclient -v h1-eth0

# Verificar la IP asignada
mininet> h1 ip addr show h1-eth0
```

**Resultado esperado:** h1 debe recibir una IP en el rango 10.0.10.50-100

### Prueba 5: Inspección de Tablas ARP

```bash
# Ver tabla ARP de hosts en diferentes VLANs
mininet> h1 arp -n    # Solo debe mostrar hosts de VLAN 10
mininet> h3 arp -n    # Solo debe mostrar hosts de VLAN 20
mininet> h5 arp -n    # Solo debe mostrar hosts de VLAN 30
```

**Resultado esperado:** Cada host solo conoce las MACs de hosts en su propia VLAN

### Prueba 6: Configuración de VLANs en Switches

```bash
# Ver configuración general del switch
mininet> sh ovs-vsctl show

# Ver detalles de puertos en s2 (VLAN 10)
mininet> s2 ovs-vsctl list port

# Ver configuración de VLANs
mininet> s2 ovs-vsctl list port | grep tag
mininet> s3 ovs-vsctl list port | grep tag
```

## Análisis de Resultados

### Dominios de Broadcast Separados

Cada VLAN constituye un **dominio de broadcast independiente**:

| VLAN | Red | Dominio Broadcast | Hosts |
|------|-----|-------------------|-------|
| 10 | 10.0.10.0/24 | 10.0.10.255 | h1, h2, dhcp |
| 20 | 10.0.20.0/24 | 10.0.20.255 | h3, h4 |
| 30 | 10.0.30.0/24 | 10.0.30.255 | h5, h6 |

### Características de Segmentación

1. **Aislamiento de tráfico:** Los broadcasts ARP solo se propagan dentro de su VLAN
2. **Seguridad:** Los hosts no pueden comunicarse con otras VLANs
3. **Reducción de broadcasts:** Cada VLAN tiene su propio dominio de broadcast reducido
4. **Escalabilidad:** Fácil agregar nuevas VLANs sin afectar las existentes


## Estructura de Archivos

```
.
├── vlan_topology_v2.py    # Script principal de Mininet
└── README.md          # Este archivo
```

## Diagrama de Flujo de Tráfico

### Tráfico Intra-VLAN (Permitido)

```
h1 (VLAN 10) --> s2 --> s1 --> s2 --> h2 (VLAN 10)  ✓
```

### Tráfico Inter-VLAN (Bloqueado)

```
h1 (VLAN 10) --> s2 --> s1 -X- s3 --> h3 (VLAN 20)  ✗
                        (bloqueado por VLAN tag)
```

## Autor

Mario Gil
Escenario de segmentación VLAN para demostración educativa.
