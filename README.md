# Escenarios Red Avanzados TFM
Recopilatorio de escenarios de red avanzados con Mininet

Recopilatorio de escenarios de red avanzados desarrollados con **Mininet** como parte de mi Trabajo de Fin de Máster. Los escenarios cubren tanto técnicas de ataque como mecanismos de defensa y conceptos de redes modernas.

Para ejecutar los distintos escenarios es necesario disponer de una VM con [Mininet](https://mininet.org) instalado. Cada escenario incluye una topología personalizada definida en Python y su propio `README.md` con instrucciones para levantar el entorno y realizar las pruebas.



## Escenarios

| Escenario | Descripción |
|---|---|
| [`ARP-spoofing`](./ARP-spoofing) | Simulación de ataques de envenenamiento ARP para interceptar tráfico en una red local. |
| [`dns-spoofing`](./dns-spoofing) | Suplantación de respuestas DNS para redirigir el tráfico hacia hosts maliciosos. |
| [`escenario-vlans`](./escenario-vlans) | Configuración y segmentación de redes mediante VLANs sobre topologías virtuales. |
| [`port-scanning`](./port-scanning) | Reconocimiento de red mediante técnicas de escaneo de puertos con herramientas como Nmap. |
| [`sdn-openflow`](./sdn-openflow) | Redes definidas por software usando el protocolo OpenFlow y un controlador SDN. |
| [`waf-modsecurity`](./waf-modsecurity) | Despliegue de un Web Application Firewall basado en ModSecurity para detección y bloqueo de ataques web. |
