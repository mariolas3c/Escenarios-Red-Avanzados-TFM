#!/bin/bash
# Script de instalacion y setup para el escenario de ARP Spoofing

echo "======================================================================="
echo "  CONFIGURACION DEL ESCENARIO DE ARP SPOOFING"
echo "======================================================================="
echo ""

echo "[1/4] Verificando dependencias..."

# Verificar si scapy esta instalado
if python3 -c "import scapy" 2>/dev/null; then
    echo "  [OK] Scapy instalado"
else
    echo "  [INSTALANDO] Scapy..."
    sudo apt-get update -qq
    sudo apt-get install -y python3-scapy
fi

# Verificar otras herramientas
for tool in tcpdump arping dsniff; do
    if command -v $tool &> /dev/null; then
        echo "  [OK] $tool instalado"
    else
        echo "  [INSTALANDO] $tool..."
        sudo apt-get install -y $tool 2>/dev/null || echo "  [SKIP] $tool no disponible en repos"
    fi
done

echo ""
echo "[2/4] Copiando scripts al directorio /tmp..."

# Copiar scripts de ataque y defensa
if [ -f "arp_spoof_attack.py" ]; then
    cp arp_spoof_attack.py /tmp/
    chmod +x /tmp/arp_spoof_attack.py
    echo "  [OK] arp_spoof_attack.py -> /tmp/"
fi

if [ -f "arp_detector.py" ]; then
    cp arp_detector.py /tmp/
    chmod +x /tmp/arp_detector.py
    echo "  [OK] arp_detector.py -> /tmp/"
fi

if [ -f "arp_detector_v2.py" ]; then
    cp arp_detector_v2.py /tmp/
    chmod +x /tmp/arp_detector_v2.py
    echo "  [OK] arp_detector_v2.py -> /tmp/ (MEJORADO)"
fi

if [ -f "arp_defender.py" ]; then
    cp arp_defender.py /tmp/
    chmod +x /tmp/arp_defender.py
    echo "  [OK] arp_defender.py -> /tmp/"
fi

echo ""
echo "[3/4] Verificando permisos..."
sudo chmod +x /tmp/arp_*.py
echo "  [OK] Permisos de ejecucion configurados"

echo ""
echo "[4/4] Creando guia de uso rapido..."

cat > /tmp/arp_spoofing_quickstart.txt << 'EOF'
==========================================
GUIA RAPIDA - ESCENARIO ARP SPOOFING
==========================================

PASO 1: Iniciar la topologia
-----------------------------
sudo python3 arp_spoofing_scenario.py

PASO 2: Verificar conectividad normal
--------------------------------------
mininet> victim ping -c 3 192.168.1.50
mininet> victim arp -n
# Anotar la MAC del gateway (deberia ser 00:00:00:00:00:01)

PASO 3: Iniciar el sistema de deteccion (IDS)
----------------------------------------------
# En una nueva terminal o usando xterm:
mininet> xterm monitor

# En la ventana del monitor:
monitor# python3 /tmp/arp_detector.py

PASO 4: Ejecutar el ataque
---------------------------
# En otra terminal:
mininet> xterm attacker

# En la ventana del atacante:
attacker# python3 /tmp/arp_spoof_attack.py

# O usando arpspoof (si esta instalado):
attacker# arpspoof -i attacker-eth0 -t 192.168.1.10 192.168.1.1

PASO 5: Observar el ataque
---------------------------
# En la ventana del monitor, veras alertas de ARP spoofing
# En la victima, verificar tabla ARP comprometida:
mininet> victim arp -n
# La MAC del gateway ahora sera 00:00:00:00:00:99 (atacante)

PASO 6: Activar defensa (opcional)
-----------------------------------
# En otra terminal:
mininet> xterm monitor

# Ejecutar sistema de defensa:
monitor# python3 /tmp/arp_defender.py

# El sistema de defensa enviara ARPs correctivos automaticamente

PASO 7: Limpiar
----------------
# Detener todos los procesos (Ctrl+C)
# Limpiar cache ARP:
mininet> victim ip -s -s neigh flush all

ARCHIVOS DE LOG:
- /tmp/arp_attack_log.txt  - Log de ataques detectados
- /tmp/arp_defense_log.txt - Log de ataques bloqueados

==========================================
EOF

echo "  [OK] Guia creada en /tmp/arp_spoofing_quickstart.txt"

echo ""
echo "======================================================================="
echo "  CONFIGURACION COMPLETADA"
echo "======================================================================="
echo ""
echo "Scripts disponibles en /tmp/:"
echo "  - arp_spoof_attack.py  (Script de ataque)"
echo "  - arp_detector.py      (Sistema de deteccion IDS)"
echo "  - arp_defender.py      (Sistema de defensa activa)"
echo ""
echo "Para ver la guia rapida:"
echo "  cat /tmp/arp_spoofing_quickstart.txt"
echo ""
echo "Para iniciar el escenario:"
echo "  sudo python3 arp_spoofing_scenario.py"
echo ""
echo "======================================================================="
