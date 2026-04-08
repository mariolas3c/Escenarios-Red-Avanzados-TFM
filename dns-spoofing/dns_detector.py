#!/usr/bin/env python3
"""
Sistema de Deteccion de DNS Spoofing (IDS)
Monitorea trafico DNS y detecta respuestas anomalas
"""

from scapy.all import *
from datetime import datetime
import sys
import os
import time
from collections import defaultdict

# Configuracion
INTERFACE = "monitor-eth0"
LEGITIMATE_DNS_SERVER = "10.0.0.53"

# Tabla de respuestas DNS legitimas conocidas
KNOWN_DNS_RECORDS = {
    "www.banco.com": "10.0.0.80",
    "banco.com": "10.0.0.80",
    "www.example.com": "10.0.0.80",
    "example.com": "10.0.0.80",
    "legitimo.com": "10.0.0.80",
}

# Tracking de consultas y respuestas
dns_queries = {}  # query_id -> {domain, timestamp, client}
dns_responses = defaultdict(list)  # domain -> [IPs]

# Estadisticas
stats = {
    'total_queries': 0,
    'total_responses': 0,
    'spoofing_detected': 0,
    'duplicate_responses': 0,
    'mismatched_ips': 0
}

def print_header():
    """
    Imprime header del IDS
    """
    print("\n" + "="*70)
    print("  SISTEMA DE DETECCION DE DNS SPOOFING (IDS)")
    print("="*70)
    print(f"\nInterfaz de monitoreo: {INTERFACE}")
    print(f"Servidor DNS legitimo: {LEGITIMATE_DNS_SERVER}")
    print(f"\nRegistros DNS legitimos conocidos:")
    for domain, ip in KNOWN_DNS_RECORDS.items():
        print(f"  {domain:<25} -> {ip}")
    print("\n[MODO] Monitoreo pasivo - Deteccion de anomalias DNS")
    print("[*] Iniciando captura de trafico DNS...")
    print("[*] Presiona Ctrl+C para detener")
    print("-"*70)
    print(f"{'TIMESTAMP':<12} {'TIPO':<10} {'DOMINIO':<25} {'IP':<15} {'ESTADO':<20}")
    print("-"*70)

def get_timestamp():
    """
    Retorna timestamp formateado
    """
    return datetime.now().strftime("%H:%M:%S")

def detect_dns_spoofing(packet):
    """
    Analiza paquetes DNS en busca de spoofing
    """
    global stats
    
    if not packet.haslayer(DNS):
        return
    
    dns_layer = packet[DNS]
    
    # PROCESAR CONSULTAS DNS (qr=0)
    if dns_layer.qr == 0:
        stats['total_queries'] += 1
        
        if dns_layer.qd:
            query_id = dns_layer.id
            domain = dns_layer.qd.qname.decode('utf-8').rstrip('.')
            client_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            
            # Guardar consulta para correlacionar con respuestas
            dns_queries[query_id] = {
                'domain': domain,
                'timestamp': time.time(),
                'client': client_ip
            }
            
            print(f"{get_timestamp():<12} {'QUERY':<10} {domain:<25} "
                  f"{'from ' + client_ip:<15} {'Waiting...':<20}")
    
    # PROCESAR RESPUESTAS DNS (qr=1)
    elif dns_layer.qr == 1:
        stats['total_responses'] += 1
        
        if not dns_layer.an:
            return
        
        query_id = dns_layer.id
        server_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        
        # Procesar cada respuesta (puede haber multiples)
        for i in range(dns_layer.ancount):
            answer = dns_layer.an[i]
            
            if answer.type == 1:  # Tipo A (IPv4)
                domain = answer.rrname.decode('utf-8').rstrip('.')
                resolved_ip = answer.rdata
                
                timestamp = get_timestamp()
                
                # DETECCION 1: Verificar contra registros conocidos
                if domain in KNOWN_DNS_RECORDS:
                    legitimate_ip = KNOWN_DNS_RECORDS[domain]
                    
                    if resolved_ip != legitimate_ip:
                        # SPOOFING DETECTADO!
                        stats['spoofing_detected'] += 1
                        stats['mismatched_ips'] += 1
                        
                        print(f"\n{'!'*70}")
                        print(f"[!!!] ALERTA - DNS SPOOFING DETECTADO [!!!]")
                        print(f"{'!'*70}")
                        print(f"Timestamp:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                        print(f"Dominio:       {domain}")
                        print(f"IP Legitima:   {legitimate_ip}")
                        print(f"IP Recibida:   {resolved_ip} <-- FALSA/MALICIOSA")
                        print(f"Servidor DNS:  {server_ip}")
                        print(f"Query ID:      {query_id}")
                        
                        # Informacion adicional si tenemos la consulta original
                        if query_id in dns_queries:
                            original = dns_queries[query_id]
                            print(f"Cliente:       {original['client']}")
                            elapsed = time.time() - original['timestamp']
                            print(f"Tiempo resp:   {elapsed:.3f} segundos")
                        
                        print(f"\n[CRITICO] Posible ataque DNS spoofing en progreso")
                        print(f"[IMPACTO]  Cliente sera redirigido a servidor malicioso")
                        print(f"[ACCION]   Investigar IP {resolved_ip} y servidor {server_ip}")
                        
                        # Log
                        with open("/tmp/dns_attack_log.txt", "a") as f:
                            f.write(f"{datetime.now()} - DNS SPOOFING - "
                                   f"Dominio: {domain}, IP legit: {legitimate_ip}, "
                                   f"IP falsa: {resolved_ip}, Servidor: {server_ip}\n")
                        
                        print(f"{'!'*70}\n")
                        print(f"{timestamp:<12} {'[ATTACK]':<10} {domain:<25} "
                              f"{resolved_ip:<15} {'SPOOFED!':<20}")
                        print("-"*70)
                        return
                
                # DETECCION 2: Multiples respuestas diferentes para el mismo dominio
                dns_responses[domain].append({
                    'ip': resolved_ip,
                    'server': server_ip,
                    'timestamp': time.time()
                })
                
                # Limpiar respuestas antiguas (mas de 60 segundos)
                current_time = time.time()
                dns_responses[domain] = [
                    r for r in dns_responses[domain]
                    if current_time - r['timestamp'] < 60
                ]
                
                # Verificar si hay respuestas conflictivas
                unique_ips = set(r['ip'] for r in dns_responses[domain])
                if len(unique_ips) > 1:
                    stats['duplicate_responses'] += 1
                    
                    print(f"\n{'*'*70}")
                    print(f"[*] ADVERTENCIA - Respuestas DNS conflictivas")
                    print(f"{'*'*70}")
                    print(f"Dominio: {domain}")
                    print(f"IPs diferentes detectadas:")
                    for r in dns_responses[domain]:
                        print(f"  - {r['ip']:<15} desde {r['server']}")
                    print(f"\n[SOSPECHOSO] Posible DNS spoofing o problema de cache")
                    print(f"{'*'*70}\n")
                
                # DETECCION 3: Respuesta no viene del servidor DNS legitimo
                if server_ip != LEGITIMATE_DNS_SERVER:
                    print(f"\n[WARN] Respuesta DNS desde servidor no autorizado: {server_ip}")
                
                # Mostrar respuesta normal
                status = "OK" if domain not in KNOWN_DNS_RECORDS else "Verified"
                print(f"{timestamp:<12} {'RESPONSE':<10} {domain:<25} "
                      f"{resolved_ip:<15} {status:<20}")

def print_statistics():
    """
    Imprime estadisticas del monitoreo
    """
    print("\n" + "="*70)
    print("  ESTADISTICAS DE MONITOREO DNS")
    print("="*70)
    print(f"\nTotal de consultas DNS:      {stats['total_queries']}")
    print(f"Total de respuestas DNS:     {stats['total_responses']}")
    print(f"Ataques de spoofing:         {stats['spoofing_detected']}")
    print(f"Respuestas duplicadas:       {stats['duplicate_responses']}")
    print(f"IPs no coincidentes:         {stats['mismatched_ips']}")
    
    if stats['spoofing_detected'] > 0:
        print(f"\n[RESUMEN]")
        print(f"  [CRITICO] Se detectaron {stats['spoofing_detected']} ataques DNS spoofing")
        print(f"  [LOG]     Ver detalles en: /tmp/dns_attack_log.txt")
    else:
        print(f"\n[RESUMEN] No se detectaron ataques durante el monitoreo")
    
    print("="*70 + "\n")

def test_interface():
    """
    Verifica que la interfaz exista
    """
    import subprocess
    result = subprocess.run(['ip', 'link', 'show', INTERFACE],
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] Interfaz {INTERFACE} no encontrada")
        print(f"[SOLUCION] Verifica con: ifconfig")
        return False
    return True

def main():
    """
    Funcion principal del IDS
    """
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root")
        print("[SOLUCION] Ejecuta: sudo python3 dns_detector.py")
        sys.exit(1)
    
    if not test_interface():
        sys.exit(1)
    
    print_header()
    
    try:
        # Capturar paquetes DNS (puerto 53)
        sniff(
            iface=INTERFACE,
            prn=detect_dns_spoofing,
            filter="udp port 53",
            store=0,
            promisc=True
        )
    except KeyboardInterrupt:
        print("\n\n[*] Deteniendo monitor DNS...")
        print_statistics()
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    print("\n" + "="*70)
    print("  IDS - Sistema de Deteccion de DNS Spoofing")
    print("="*70)
    print("\n[INFO] Monitoreo pasivo de trafico DNS")
    print("[INFO] Deteccion basada en:")
    print("  1. Tabla de registros DNS conocidos")
    print("  2. Deteccion de respuestas conflictivas")
    print("  3. Verificacion de servidor DNS autoritativo")
    print("\n[INFO] Presiona Ctrl+C para detener\n")
    
    time.sleep(2)
    main()
