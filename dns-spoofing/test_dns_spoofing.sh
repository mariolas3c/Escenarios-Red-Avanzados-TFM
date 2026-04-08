#!/bin/bash
# Script de prueba completa para DNS Spoofing

echo "======================================================================="
echo "  PRUEBA COMPLETA DE DNS SPOOFING"
echo "======================================================================="
echo ""

echo "Este script debe ejecutarse DENTRO de Mininet en el host 'client'"
echo "Uso: mininet> client bash /tmp/test_dns_spoofing.sh"
echo ""

echo "[FASE 1] Verificando configuracion inicial"
echo "============================================"
echo ""

echo "1.1 Verificando /etc/resolv.conf:"
cat /etc/resolv.conf
echo ""

echo "1.2 Verificando que NO hay entradas en /etc/hosts:"
cat /etc/hosts | grep -E "banco|example" || echo "  [OK] No hay entradas (correcto para el ataque)"
echo ""

echo "1.3 Probando resolucion DNS normal:"
echo "nslookup www.banco.com 10.0.0.53"
nslookup www.banco.com 10.0.0.53
echo ""

echo "1.4 Probando con dig:"
dig @10.0.0.53 www.banco.com +short
echo ""

echo "[FASE 2] Accediendo al servidor ANTES del ataque"
echo "=================================================="
echo ""

echo "2.1 Acceso por IP (servidor legitimo):"
curl -s http://10.0.0.80 | grep -i "LEGITIMO\|10.0.0.80" | head -3
echo ""

echo "2.2 Acceso por nombre de dominio:"
curl -s http://www.banco.com 2>&1 | grep -i "LEGITIMO\|10.0.0.80\|could not" | head -5
echo ""

echo "[FASE 3] Instrucciones para el ataque"
echo "======================================"
echo ""
echo "AHORA debes:"
echo "  1. Abrir terminal del atacante: mininet> xterm attacker"
echo "  2. Ejecutar: attacker# python3 /tmp/dns_spoof_attack.py"
echo "  3. Dejar corriendo el script"
echo ""
echo "Presiona ENTER cuando el atacante este listo..."
read

echo ""
echo "[FASE 4] Probando DNS DURANTE el ataque"
echo "========================================"
echo ""

echo "4.1 Limpiando cache DNS (si existe):"
systemd-resolve --flush-caches 2>/dev/null || echo "  (no systemd-resolved)"
echo ""

echo "4.2 Nueva consulta DNS a www.banco.com:"
nslookup www.banco.com 10.0.0.53
echo ""

echo "4.3 Consulta con dig:"
RESULT=$(dig @10.0.0.53 www.banco.com +short)
echo "Resultado: $RESULT"
echo ""

if [[ "$RESULT" == "10.0.0.99" ]]; then
    echo "[SUCCESS] DNS SPOOFING FUNCIONO - Resolvio a 10.0.0.99 (servidor falso)"
elif [[ "$RESULT" == "10.0.0.80" ]]; then
    echo "[FAILED] Aun resuelve a 10.0.0.80 (servidor legitimo)"
    echo "[INFO] El servidor DNS real respondio primero"
else
    echo "[UNKNOWN] Resultado inesperado: $RESULT"
fi
echo ""

echo "4.4 Probando acceso web por nombre:"
echo "curl http://www.banco.com"
CONTENT=$(curl -s http://www.banco.com 2>&1)

if echo "$CONTENT" | grep -q "10.0.0.99"; then
    echo "[SUCCESS] REDIRIGIDO AL SERVIDOR FALSO (10.0.0.99)"
    echo "$CONTENT" | grep -i "FALSO\|PHISHING\|10.0.0.99" | head -3
elif echo "$CONTENT" | grep -q "10.0.0.80"; then
    echo "[INFO] Aun conectado al servidor legitimo (10.0.0.80)"
    echo "$CONTENT" | grep -i "LEGITIMO\|10.0.0.80" | head -3
elif echo "$CONTENT" | grep -q "Could not resolve"; then
    echo "[ERROR] No se pudo resolver el dominio"
else
    echo "[UNKNOWN] Contenido inesperado"
    echo "$CONTENT" | head -10
fi
echo ""

echo "[FASE 5] Comparacion visual"
echo "============================"
echo ""

echo "5.1 Servidor LEGITIMO (10.0.0.80):"
curl -s http://10.0.0.80 | grep -o "LEGITIMO\|10.0.0.80\|Servidor Real" | head -3
echo ""

echo "5.2 Servidor FALSO (10.0.0.99):"
curl -s http://10.0.0.99 | grep -o "FALSO\|PHISHING\|10.0.0.99" | head -3
echo ""

echo "5.3 Acceso por nombre (www.banco.com):"
curl -s http://www.banco.com | grep -o "LEGITIMO\|FALSO\|10.0.0.80\|10.0.0.99" | head -3
echo ""

echo "======================================================================="
echo "  RESUMEN"
echo "======================================================================="
echo ""

# Verificar resultado final
FINAL_IP=$(dig @10.0.0.53 www.banco.com +short 2>/dev/null)

if [[ "$FINAL_IP" == "10.0.0.99" ]]; then
    echo "[EXITO] El ataque DNS Spoofing FUNCIONO correctamente"
    echo "        www.banco.com ahora resuelve a: $FINAL_IP (servidor FALSO)"
    echo ""
    echo "El cliente ha sido:"
    echo "  [X] Redirigido al servidor malicioso"
    echo "  [X] Vulnerable a phishing"
    echo "  [X] En riesgo de robo de credenciales"
elif [[ "$FINAL_IP" == "10.0.0.80" ]]; then
    echo "[PARCIAL] El servidor DNS legitimo respondio primero"
    echo "          www.banco.com resuelve a: $FINAL_IP (servidor LEGITIMO)"
    echo ""
    echo "Posibles causas:"
    echo "  - El servidor DNS real es mas rapido"
    echo "  - El atacante no intercepto la consulta"
    echo "  - Hay cache DNS activo"
    echo ""
    echo "Soluciones:"
    echo "  - Repetir la consulta varias veces"
    echo "  - Verificar que el atacante esta capturando (tcpdump)"
    echo "  - El IDS deberia detectar respuestas duplicadas"
else
    echo "[ERROR] No se pudo determinar el resultado"
    echo "        Resultado: $FINAL_IP"
fi

echo ""
echo "======================================================================="
