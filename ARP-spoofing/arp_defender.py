#!/usr/bin/env python3
"""
Sistema de Defensa Activa contra ARP Spoofing
Detecta y contrarresta ataques ARP en tiempo real
"""

from scapy.all import ARP, Ether, send, sniff, get_if_hwaddr, sendp
from datetime import datetime
import sys
import os
import time

# Configuracion
INTERFACE = "monitor-eth0"
PROTECTED_NETWORK = "192.168.1.0/24"

# Tabla de mapeo IP -> MAC legitimo (configuracion estatica)
LEGITIMATE_HOSTS = {
    "192.168.1.1": "00:00:00:00:00:01",    # Gateway
    "192.168.1.10": "00:00:00:00:00:10",   # Victim
    "192.168.1.50": "00:00:00:00:00:50",   # Server
    "192.168.1.100": "00:00:00:00:00:99",  # Attacker (conocido)
    "192.168.1.200": "00:00:00:00:00:AA",  # Monitor
}

# Contador de ataques bloqueados
blocked_attacks = 0

def print_header():
    """
    Imprime el header del sistema de defensa
    """
    print("\n" + "="*70)
    print("  SISTEMA DE DEFENSA ACTIVA CONTRA ARP SPOOFING")
    print("="*70)
    print(f"\nInterfaz: {INTERFACE}")
    print(f"Red protegida: {PROTECTED_NETWORK}")
    print(f"Hosts legitimos configurados: {len(LEGITIMATE_HOSTS)}")
    print("\n[MODO] Defensa activa - Enviando ARPs correctivos")
    print("-"*70)

def get_timestamp():
    """
    Retorna timestamp formateado
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def send_correct_arp(target_ip, legitimate_mac, broadcast=True):
    """
    Envia un ARP correcto para restaurar la tabla ARP
    """
    if broadcast:
        # Enviar a broadcast para que todos actualicen
        arp_correct = ARP(op=2,  # ARP reply
                         pdst="255.255.255.255",
                         hwdst="ff:ff:ff:ff:ff:ff",
                         psrc=target_ip,
                         hwsrc=legitimate_mac)
        
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / arp_correct
    else:
        # Enviar unicast
        arp_correct = ARP(op=2,
                         pdst=target_ip,
                         psrc=target_ip,
                         hwsrc=legitimate_mac)
        packet = arp_correct
    
    sendp(packet, iface=INTERFACE, verbose=False)

def defend_against_spoofing(packet):
    """
    Analiza paquetes ARP y contrarresta ataques
    """
    global blocked_attacks
    
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        
        # Solo procesar ARP replies
        if arp_layer.op != 2:
            return
        
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc
        
        # Verificar si esta IP esta en nuestra lista de hosts legitimos
        if src_ip in LEGITIMATE_HOSTS:
            legitimate_mac = LEGITIMATE_HOSTS[src_ip]
            
            # Si la MAC no coincide, es un ataque
            if src_mac.lower() != legitimate_mac.lower():
                timestamp = get_timestamp()
                blocked_attacks += 1
                
                print(f"\n{'!'*70}")
                print(f"[ATAQUE DETECTADO Y BLOQUEADO #{blocked_attacks}]")
                print(f"{'!'*70}")
                print(f"Timestamp: {timestamp}")
                print(f"IP suplantada: {src_ip}")
                print(f"MAC legitima:  {legitimate_mac}")
                print(f"MAC atacante:  {src_mac} <-- BLOQUEADO")
                print(f"\n[ACCION] Enviando ARP correctivo a la red...")
                
                # Contraatacar: Enviar ARP correcto multiples veces
                for _ in range(5):
                    send_correct_arp(src_ip, legitimate_mac, broadcast=True)
                    time.sleep(0.1)
                
                print(f"[OK] ARP correctivo enviado (5 paquetes broadcast)")
                
                # Registrar en log
                with open("/tmp/arp_defense_log.txt", "a") as f:
                    f.write(f"{timestamp} - ATAQUE BLOQUEADO - IP: {src_ip}, "
                           f"MAC legitima: {legitimate_mac}, MAC atacante: {src_mac}\n")
                
                print(f"{'!'*70}\n")

def periodic_arp_refresh():
    """
    Envia periodicamente ARPs correctos para prevenir ataques
    """
    print("[*] Iniciando envio periodico de ARPs preventivos...")
    
    while True:
        try:
            time.sleep(30)  # Cada 30 segundos
            
            print(f"\n[PREVENTIVO] Enviando ARPs legitimos ({get_timestamp()})")
            
            for ip, mac in LEGITIMATE_HOSTS.items():
                send_correct_arp(ip, mac, broadcast=True)
            
            print(f"[OK] {len(LEGITIMATE_HOSTS)} ARPs preventivos enviados")
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ERROR] en envio preventivo: {e}")

def print_statistics():
    """
    Imprime estadisticas de defensa
    """
    print("\n" + "="*70)
    print("  ESTADISTICAS DE DEFENSA")
    print("="*70)
    print(f"\nTotal de ataques bloqueados: {blocked_attacks}")
    print(f"\nHosts protegidos:")
    print(f"{'IP':<15} {'MAC Legitima':<20}")
    print("-"*70)
    
    for ip, mac in LEGITIMATE_HOSTS.items():
        print(f"{ip:<15} {mac:<20}")
    
    print("="*70 + "\n")

def main():
    """
    Funcion principal del sistema de defensa
    """
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root")
        sys.exit(1)
    
    print_header()
    
    print("\n[CONFIGURACION] Hosts legitimos:")
    for ip, mac in LEGITIMATE_HOSTS.items():
        print(f"  {ip:<15} -> {mac}")
    
    print("\n[*] Iniciando defensa activa...")
    print("[*] Presiona Ctrl+C para detener\n")
    
    # Enviar ARPs iniciales
    print("[*] Enviando ARPs iniciales a la red...")
    for ip, mac in LEGITIMATE_HOSTS.items():
        send_correct_arp(ip, mac, broadcast=True)
    print("[OK] ARPs iniciales enviados\n")
    
    try:
        # Iniciar captura y defensa
        sniff(iface=INTERFACE,
              prn=defend_against_spoofing,
              filter="arp",
              store=0)
              
    except KeyboardInterrupt:
        print("\n\n[*] Deteniendo sistema de defensa...")
        print_statistics()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("\n[INFO] Sistema de Defensa Activa contra ARP Spoofing")
    print("[INFO] Este sistema detecta y contrarresta ataques automaticamente\n")
    
    main()
