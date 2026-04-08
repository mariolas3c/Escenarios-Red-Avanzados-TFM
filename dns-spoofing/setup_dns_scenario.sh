#!/bin/bash
# Script de instalacion para el escenario de DNS Spoofing

echo "======================================================================="
echo "  CONFIGURACION DEL ESCENARIO DE DNS SPOOFING"
echo "======================================================================="
echo ""

echo "[1/4] Verificando dependencias..."

# Verificar scapy
if python3 -c "import scapy" 2>/dev/null; then
    echo "  [OK] Scapy instalado"
else
    echo "  [INSTALANDO] Scapy..."
    sudo apt-get update -qq
    sudo apt-get install -y python3-scapy
fi

# Verificar dnsmasq
if command -v dnsmasq &> /dev/null; then
    echo "  [OK] dnsmasq instalado"
else
    echo "  [INSTALANDO] dnsmasq..."
    sudo apt-get install -y dnsmasq
fi

# Verificar otras herramientas
for tool in tcpdump dig nslookup; do
    if command -v $tool &> /dev/null; then
        echo "  [OK] $tool instalado"
    else
        echo "  [INFO] $tool no instalado (opcional)"
    fi
done

echo ""
echo "[2/4] Copiando scripts al directorio /tmp..."

# Copiar scripts
for script in dns_spoof_attack.py dns_detector.py dns_defender.py; do
    if [ -f "$script" ]; then
        cp "$script" /tmp/
        chmod +x "/tmp/$script"
        echo "  [OK] $script -> /tmp/"
    fi
done

echo ""
echo "[3/4] Creando guia de uso rapido..."

cat > /tmp/dns_spoofing_quickstart.txt << 'EOF'
==========================================
GUIA RAPIDA - ESCENARIO DNS SPOOFING
==========================================

PASO 1: Iniciar la topologia
-----------------------------
sudo python3 dns_spoofing_scenario.py

PASO 2: Verificar DNS normal
-----------------------------
mininet> client nslookup www.banco.com 10.0.0.53
# Debe resolver a 10.0.0.80

mininet> client curl http://www.banco.com
# Debe mostrar "SITIO LEGITIMO"

PASO 3: Iniciar IDS
--------------------
mininet> xterm monitor
monitor# python3 /tmp/dns_detector.py

PASO 4: Ejecutar ataque
------------------------
mininet> xterm attacker
attacker# python3 /tmp/dns_spoof_attack.py

PASO 5: Probar desde cliente
-----------------------------
mininet> client nslookup www.banco.com 10.0.0.53
# Puede resolver a 10.0.0.99 (FALSO)

mininet> client curl http://www.banco.com
# Puede mostrar "SITIO FALSO"

PASO 6: Ver deteccion
----------------------
# El IDS mostrara alertas de DNS spoofing

PASO 7: Activar defensa (opcional)
-----------------------------------
mininet> xterm monitor
monitor# python3 /tmp/dns_defender.py

LOGS:
- /tmp/dns_attack_log.txt
- /tmp/dns_defense_log.txt
- /tmp/dns_legitimo.log

==========================================
EOF

echo "  [OK] Guia creada en /tmp/dns_spoofing_quickstart.txt"

echo ""
echo "[4/4] Verificando permisos..."
sudo chmod +x /tmp/dns_*.py 2>/dev/null
echo "  [OK] Permisos configurados"

echo ""
echo "======================================================================="
echo "  CONFIGURACION COMPLETADA"
echo "======================================================================="
echo ""
echo "Scripts disponibles en /tmp/:"
echo "  - dns_spoof_attack.py  (Script de ataque DNS spoofing)"
echo "  - dns_detector.py      (Sistema de deteccion IDS)"
echo "  - dns_defender.py      (Sistema de defensa IPS)"
echo ""
echo "Para ver la guia rapida:"
echo "  cat /tmp/dns_spoofing_quickstart.txt"
echo ""
echo "Para iniciar el escenario:"
echo "  sudo python3 dns_spoofing_scenario.py"
echo ""
echo "COMPARACION:"
echo "  Servidor LEGITIMO (10.0.0.80): Fondo VERDE"
echo "  Servidor FALSO (10.0.0.99):    Fondo ROJO"
echo ""
echo "======================================================================="
