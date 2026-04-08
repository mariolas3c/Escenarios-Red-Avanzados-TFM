#!/usr/bin/env python3
"""
Sistema de Defensa contra DNS Spoofing
Detecta y bloquea respuestas DNS falsas
"""

from scapy.all import *
from datetime import datetime
import sys
import os
import time

# Configuracion
INTERFACE = "monitor-eth0"
LEGITIMATE_DNS_SERVER = "10.0.0.53"

# Registros DNS legitimos (whitelist)
LEGITIMATE_DNS_RECORDS = {
    "www.banco.com": "10.0.0.80",
    "banco.com": "10.0.0.80",
    "www.example.com": "10.0.0.80",
    "example.com": "10.0.0.80",
    "legitimo.com": "10.0.0.80",
}

# Contador de ataques bloqueados
stats = {
    'attacks_blocked': 0,
    'corrective_packets_sent': 0,
    'queries_monitored': 0
}

# Tracking de consultas
pending_queries = {}  # query_id -> {domain, client, timestamp}

def print_header():
    """
    Imprime header del sistema de defensa
    """
    print("\n" + "="*70)
    print("  SISTEMA DE DEFENSA ACTIVA CONTRA DNS SPOOFING")
    print("="*70)
    print(f"\nInterfaz: {INTERFACE}")
    print(f"Servidor DNS legitimo: {LEGITIMATE_DNS_SERVER}")
    print(f"\nRegistros protegidos:")
    for domain, ip in LEGITIMATE_DNS_RECORDS.items():
        print(f"  {domain:<25} -> {ip}")
    print("\n[MODO] Defensa activa - Bloqueando respuestas falsas")
    print("[*] Iniciando sistema de defensa...")
    print("[*] Presiona Ctrl+C para detener")
    print("-"*70)

def get_timestamp():
    """
    Retorna timestamp formateado
    """
    return datetime.now().strftime("%H:%M:%S")

def send_correct_dns_response(query_id, domain, client_ip, legitimate_ip):
    """
    Envia respuesta DNS correcta al cliente
    """
    try:
        # Construir respuesta DNS correcta
        correct_pkt = IP(dst=client_ip, src=LEGITIMATE_DNS_SERVER) / \
                     UDP(dport=53, sport=53) / \
                     DNS(
                         id=query_id,
                         qr=1,  # Es una respuesta
                         aa=1,  # Authoritative
                         qd=DNSQR(qname=domain),
                         an=DNSRR(
                             rrname=domain,
                             ttl=300,
                             rdata=legitimate_ip
                         )
                     )
        
        # Enviar respuesta correcta
        send(correct_pkt, verbose=0, iface=INTERFACE)
        stats['corrective_packets_sent'] += 1
        
        return True
    except Exception as e:
        print(f"[ERROR] No se pudo enviar respuesta correctiva: {e}")
        return False

def defend_dns(packet):
    """
    Detecta y bloquea DNS spoofing
    """
    if not packet.haslayer(DNS):
        return
    
    dns_layer = packet[DNS]
    
    # Rastrear consultas DNS
    if dns_layer.qr == 0:  # Query
        stats['queries_monitored'] += 1
        
        if dns_layer.qd:
            query_id = dns_layer.id
            domain = dns_layer.qd.qname.decode('utf-8').rstrip('.')
            client_ip = packet[IP].src if packet.haslayer(IP) else None
            
            if domain in LEGITIMATE_DNS_RECORDS and client_ip:
                pending_queries[query_id] = {
                    'domain': domain,
                    'client': client_ip,
                    'timestamp': time.time()
                }
    
    # Analizar respuestas DNS
    elif dns_layer.qr == 1:  # Response
        if not dns_layer.an:
            return
        
        query_id = dns_layer.id
        server_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        
        # Procesar respuestas
        for i in range(dns_layer.ancount):
            answer = dns_layer.an[i]
            
            if answer.type == 1:  # Tipo A
                domain = answer.rrname.decode('utf-8').rstrip('.')
                resolved_ip = answer.rdata
                
                # Verificar si es un dominio protegido
                if domain in LEGITIMATE_DNS_RECORDS:
                    legitimate_ip = LEGITIMATE_DNS_RECORDS[domain]
                    
                    # Verificar si la respuesta es falsa
                    if resolved_ip != legitimate_ip:
                        # ATAQUE DETECTADO - BLOQUEAR
                        stats['attacks_blocked'] += 1
                        
                        timestamp = get_timestamp()
                        
                        print(f"\n{'!'*70}")
                        print(f"[!!!] ATAQUE DNS BLOQUEADO #{stats['attacks_blocked']} [!!!]")
                        print(f"{'!'*70}")
                        print(f"Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        print(f"Dominio:       {domain}")
                        print(f"IP Legitima:   {legitimate_ip}")
                        print(f"IP Falsa:      {resolved_ip} <-- BLOQUEADA")
                        print(f"Servidor:      {server_ip}")
                        
                        # Enviar respuesta correcta si tenemos info del cliente
                        if query_id in pending_queries:
                            query_info = pending_queries[query_id]
                            client_ip = query_info['client']
                            
                            print(f"\n[ACCION] Enviando respuesta DNS correcta al cliente {client_ip}")
                            
                            if send_correct_dns_response(query_id, domain, client_ip, legitimate_ip):
                                print(f"[OK] Respuesta correctiva enviada")
                                print(f"[PROTECCION] Cliente recibira IP correcta: {legitimate_ip}")
                            else:
                                print(f"[ERROR] Fallo al enviar respuesta correctiva")
                            
                            # Limpiar
                            del pending_queries[query_id]
                        else:
                            print(f"\n[WARN] No se encontro consulta original - no se puede corregir")
                        
                        # Log
                        with open("/tmp/dns_defense_log.txt", "a") as f:
                            f.write(f"{datetime.now()} - ATAQUE BLOQUEADO - "
                                   f"Dominio: {domain}, IP legit: {legitimate_ip}, "
                                   f"IP falsa: {resolved_ip}\n")
                        
                        print(f"{'!'*70}\n")

def cleanup_old_queries():
    """
    Limpia consultas antiguas (mas de 30 segundos)
    """
    current_time = time.time()
    to_delete = []
    
    for query_id, info in pending_queries.items():
        if current_time - info['timestamp'] > 30:
            to_delete.append(query_id)
    
    for query_id in to_delete:
        del pending_queries[query_id]

def print_statistics():
    """
    Imprime estadisticas de defensa
    """
    print("\n" + "="*70)
    print("  ESTADISTICAS DE DEFENSA DNS")
    print("="*70)
    print(f"\nConsultas monitoreadas:      {stats['queries_monitored']}")
    print(f"Ataques bloqueados:          {stats['attacks_blocked']}")
    print(f"Respuestas correctivas:      {stats['corrective_packets_sent']}")
    
    if stats['attacks_blocked'] > 0:
        print(f"\n[RESUMEN]")
        print(f"  [SUCCESS] Se bloquearon {stats['attacks_blocked']} ataques DNS spoofing")
        print(f"  [PROTECCION] Clientes protegidos con respuestas correctas")
        print(f"  [LOG] Ver detalles en: /tmp/dns_defense_log.txt")
    else:
        print(f"\n[RESUMEN] No se detectaron ataques durante el monitoreo")
    
    print("\nDominios protegidos:")
    for domain, ip in LEGITIMATE_DNS_RECORDS.items():
        print(f"  {domain:<25} -> {ip}")
    
    print("="*70 + "\n")

def main():
    """
    Funcion principal
    """
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root")
        sys.exit(1)
    
    print_header()
    
    try:
        # Iniciar captura
        sniff(
            iface=INTERFACE,
            prn=defend_dns,
            filter="udp port 53",
            store=0,
            promisc=True
        )
    except KeyboardInterrupt:
        print("\n\n[*] Deteniendo sistema de defensa...")
        print_statistics()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("\n[INFO] Sistema de Defensa Activa contra DNS Spoofing")
    print("[INFO] Este sistema detecta y bloquea ataques automaticamente\n")
    time.sleep(2)
    main()
