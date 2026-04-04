#!/usr/bin/env python3
"""
Sistema de Deteccion de ARP Spoofing (IDS) - VERSION MEJORADA
Monitorea trafico ARP y detecta intentos de envenenamiento
"""

from scapy.all import ARP, sniff, get_if_hwaddr, Ether
from datetime import datetime
import sys
import os
import time

# Configuracion
INTERFACE = "monitor-eth0"
ALERT_THRESHOLD = 2  # Numero de cambios de MAC antes de alertar

# Tabla de mapeo IP -> MAC legitimo (aprendida dinamicamente)
arp_table = {}

# Tabla de hosts conocidos estaticamente (para mejor deteccion)
KNOWN_HOSTS = {
    "192.168.1.1": "00:00:00:00:00:01",    # Gateway
    "192.168.1.10": "00:00:00:00:00:10",   # Victim
    "192.168.1.50": "00:00:00:00:00:50",   # Server
    "192.168.1.100": "00:00:00:00:00:99",  # Attacker
    "192.168.1.200": "00:00:00:00:00:aa",  # Monitor
}

# Contador de alertas por IP
alert_count = {}

# Estadisticas
stats = {
    'total_packets': 0,
    'arp_requests': 0,
    'arp_replies': 0,
    'attacks_detected': 0
}

def print_header():
    """
    Imprime el header del IDS
    """
    print("\n" + "="*70)
    print("  SISTEMA DE DETECCION DE ARP SPOOFING (IDS) - MEJORADO")
    print("="*70)
    print(f"\nInterfaz de monitoreo: {INTERFACE}")
    print(f"Umbral de alerta: {ALERT_THRESHOLD} cambios de MAC")
    print(f"Hosts conocidos configurados: {len(KNOWN_HOSTS)}")
    
    print("\n[MODO] Monitoreo pasivo - Deteccion de anomalias")
    print("\n[CONFIGURACION] Hosts legitimos conocidos:")
    for ip, mac in KNOWN_HOSTS.items():
        print(f"  {ip:<15} -> {mac}")
    
    print("\n[*] Iniciando captura de trafico ARP...")
    print("[*] Presiona Ctrl+C para detener y ver estadisticas")
    print("-"*70)
    print(f"{'TIMESTAMP':<20} {'TIPO':<12} {'IP':<15} {'MAC':<18} {'ESTADO':<15}")
    print("-"*70)

def get_timestamp():
    """
    Retorna timestamp formateado
    """
    return datetime.now().strftime("%H:%M:%S")

def check_arp_spoofing(packet):
    """
    Analiza paquetes ARP en busca de anomalias
    MEJORADO: Analiza tanto requests como replies
    """
    global stats
    
    # Verificar que sea un paquete ARP
    if not packet.haslayer(ARP):
        return
    
    stats['total_packets'] += 1
    
    arp_layer = packet[ARP]
    
    # Obtener informacion del paquete
    op = arp_layer.op
    src_ip = arp_layer.psrc
    src_mac = arp_layer.hwsrc
    dst_ip = arp_layer.pdst
    
    # Contar tipos de paquetes
    if op == 1:
        stats['arp_requests'] += 1
        pkt_type = "REQUEST"
    elif op == 2:
        stats['arp_replies'] += 1
        pkt_type = "REPLY"
    else:
        return
    
    # Ignorar 0.0.0.0 y direcciones multicast
    if src_ip == "0.0.0.0" or src_ip.startswith("224."):
        return
    
    timestamp = get_timestamp()
    
    # DETECCION 1: Verificar contra tabla de hosts conocidos
    if src_ip in KNOWN_HOSTS:
        legitimate_mac = KNOWN_HOSTS[src_ip].lower()
        actual_mac = src_mac.lower()
        
        if actual_mac != legitimate_mac:
            # ATAQUE DETECTADO!
            stats['attacks_detected'] += 1
            alert_count[src_ip] = alert_count.get(src_ip, 0) + 1
            
            print(f"\n{'!'*70}")
            print(f"[!!!] ALERTA DE SEGURIDAD - ARP SPOOFING DETECTADO [!!!]")
            print(f"{'!'*70}")
            print(f"Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Tipo:          ARP {pkt_type}")
            print(f"IP Suplantada: {src_ip}")
            print(f"MAC Legitima:  {legitimate_mac}")
            print(f"MAC Atacante:  {actual_mac} <-- FALSO/MALICIOSO")
            print(f"IP Destino:    {dst_ip}")
            print(f"Alertas:       #{alert_count[src_ip]}")
            
            if alert_count[src_ip] >= ALERT_THRESHOLD:
                print(f"\n[CRITICO] Umbral superado ({ALERT_THRESHOLD})!")
                print(f"[CRITICO] ATAQUE ARP SPOOFING CONFIRMADO")
                print(f"[ACCION]  Host atacante detectado: {actual_mac}")
                
                # Log de ataque
                with open("/tmp/arp_attack_log.txt", "a") as f:
                    f.write(f"{datetime.now()} - ATAQUE CONFIRMADO - "
                           f"IP: {src_ip}, MAC legit: {legitimate_mac}, "
                           f"MAC atacante: {actual_mac}\n")
            
            print(f"{'!'*70}\n")
            print(f"{timestamp:<20} {'[ATTACK]':<12} {src_ip:<15} {src_mac:<18} {'SPOOFING!':<15}")
            print("-"*70)
            return
    
    # DETECCION 2: Verificar contra tabla dinamica aprendida
    if src_ip in arp_table:
        stored_mac = arp_table[src_ip].lower()
        current_mac = src_mac.lower()
        
        if stored_mac != current_mac:
            # Cambio de MAC detectado
            alert_count[src_ip] = alert_count.get(src_ip, 0) + 1
            
            print(f"\n{'*'*70}")
            print(f"[*] ADVERTENCIA - Cambio de MAC detectado")
            print(f"{'*'*70}")
            print(f"Timestamp:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"IP:         {src_ip}")
            print(f"MAC vieja:  {stored_mac}")
            print(f"MAC nueva:  {current_mac}")
            print(f"Cambios:    #{alert_count[src_ip]}")
            
            if alert_count[src_ip] >= ALERT_THRESHOLD:
                print(f"\n[SOSPECHOSO] Multiples cambios de MAC detectados")
                print(f"[ACCION] Posible ataque ARP spoofing en progreso")
            
            print(f"{'*'*70}\n")
            
            # Actualizar tabla
            arp_table[src_ip] = src_mac
            
            print(f"{timestamp:<20} {'[CHANGE]':<12} {src_ip:<15} {src_mac:<18} {'MAC changed':<15}")
            print("-"*70)
            return
    
    # DETECCION 3: Primera vez que vemos esta IP
    if src_ip not in arp_table:
        arp_table[src_ip] = src_mac
        alert_count[src_ip] = 0
        print(f"{timestamp:<20} {'[NEW]':<12} {src_ip:<15} {src_mac:<18} {'Learned':<15}")

def print_statistics():
    """
    Imprime estadisticas de la tabla ARP
    """
    print("\n" + "="*70)
    print("  ESTADISTICAS DE MONITOREO")
    print("="*70)
    print(f"\nPaquetes totales capturados: {stats['total_packets']}")
    print(f"  - ARP Requests: {stats['arp_requests']}")
    print(f"  - ARP Replies:  {stats['arp_replies']}")
    print(f"\nAtaques detectados: {stats['attacks_detected']}")
    print(f"\nHosts monitoreados: {len(arp_table)}")
    
    if arp_table:
        print(f"\nTabla ARP dinamica aprendida:")
        print(f"{'IP':<15} {'MAC':<20} {'Alertas':<10} {'Estado':<15}")
        print("-"*70)
        
        for ip, mac in arp_table.items():
            alerts = alert_count.get(ip, 0)
            
            # Verificar si es legitimo
            if ip in KNOWN_HOSTS:
                if mac.lower() == KNOWN_HOSTS[ip].lower():
                    status = "[LEGITIMO]"
                else:
                    status = "[ATACANTE]"
            else:
                status = "[DESCONOCIDO]"
            
            if alerts >= ALERT_THRESHOLD:
                status = "[SOSPECHOSO]"
            
            print(f"{ip:<15} {mac:<20} {alerts:<10} {status:<15}")
    
    print("="*70 + "\n")

def test_interface():
    """
    Verifica que la interfaz exista y este activa
    """
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        if INTERFACE not in interfaces:
            print(f"[ERROR] Interfaz {INTERFACE} no encontrada")
            print(f"[INFO] Interfaces disponibles: {interfaces}")
            return False
    except ImportError:
        # Si no esta netifaces, intentar con ip
        import subprocess
        result = subprocess.run(['ip', 'link', 'show', INTERFACE], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] Interfaz {INTERFACE} no encontrada")
            return False
    
    return True

def main():
    """
    Funcion principal del IDS
    """
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root")
        print("[AYUDA] Ejecuta: sudo python3 arp_detector.py")
        sys.exit(1)
    
    # Verificar interfaz
    if not test_interface():
        print(f"\n[SOLUCION] Si estas en Mininet, asegurate de:")
        print(f"  1. Haber ejecutado: mininet> xterm monitor")
        print(f"  2. En la ventana monitor: ifconfig")
        print(f"  3. Verificar el nombre de la interfaz")
        sys.exit(1)
    
    print_header()
    
    try:
        # Iniciar captura de paquetes ARP
        # IMPORTANTE: filter="arp" captura TODOS los paquetes ARP
        sniff(iface=INTERFACE, 
              prn=check_arp_spoofing,
              filter="arp",
              store=0,
              promisc=True)  # Modo promiscuo para capturar todo
              
    except KeyboardInterrupt:
        print("\n\n[*] Deteniendo monitor...")
        print_statistics()
        
        if stats['attacks_detected'] > 0:
            print(f"\n[RESUMEN] Se detectaron {stats['attacks_detected']} ataques!")
            print(f"[LOG] Ver detalles en: /tmp/arp_attack_log.txt")
        else:
            print(f"\n[RESUMEN] No se detectaron ataques durante el monitoreo")
        
        sys.exit(0)
    except PermissionError:
        print("\n[ERROR] Permiso denegado para capturar paquetes")
        print("[SOLUCION] Ejecuta con sudo: sudo python3 arp_detector.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("\n" + "="*70)
    print("  IDS - Sistema de Deteccion de ARP Spoofing")
    print("="*70)
    print("\n[INFO] Monitoreo pasivo de trafico ARP")
    print("[INFO] Deteccion basada en:")
    print("  1. Tabla de hosts conocidos (estatica)")
    print("  2. Aprendizaje dinamico de MAC addresses")
    print("  3. Deteccion de cambios anomalos")
    print("\n[INFO] Presiona Ctrl+C para detener y ver estadisticas\n")
    
    time.sleep(2)
    main()
