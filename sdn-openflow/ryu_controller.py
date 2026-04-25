#!/usr/bin/env python3
"""
Controlador SDN Ryu con OpenFlow 1.3
- L2 switch con aprendizaje de MACs
- Firewall dinamico gestionado via REST API
- Recoleccion de estadisticas de flujo
- Deteccion automatica de port scans y bloqueo de IP
"""

import json
import time
import threading
from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from ryu.lib import hub
from webob import Response

ANOMALY_PORT_THRESHOLD = 15   # puertos unicos en ventana de tiempo
ANOMALY_TIME_WINDOW    = 5    # segundos
STATS_POLL_INTERVAL    = 5    # segundos entre peticiones de stats


class SDNFirewallController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']

        self.mac_to_port = {}           # {dpid: {mac: port}}
        self.datapaths   = {}           # {dpid: datapath}
        self.flow_stats  = {}           # {dpid: [flow_info, ...]}
        self.blocked_ips = set()        # IPs con regla DROP en switch
        self.syn_counters = defaultdict(list)  # {src_ip: [(ts, dst_port)]}

        self.firewall_rules = []
        self._rule_id = 1
        self._lock = threading.Lock()

        wsgi.register(SDNRestAPI, {'sdn_app': self})
        self._monitor = hub.spawn(self._stats_loop)

        self.logger.info('Controlador SDN iniciado | REST API :8080')

    # ------------------------------------------------------------------ #
    #  Eventos OpenFlow                                                    #
    # ------------------------------------------------------------------ #

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.mac_to_port.setdefault(dp.id, {})

        # Regla table-miss: enviar al controlador
        parser = dp.ofproto_parser
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                          dp.ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions)
        self.logger.info('Switch conectado: dpid=%016x', dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        dp       = msg.datapath
        ofproto  = dp.ofproto
        parser   = dp.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Aprendizaje de MAC
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)

        # Procesamiento de paquetes IPv4
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # Verificar bloqueo por anomalia
            if src_ip in self.blocked_ips:
                self.logger.debug('Paquete descartado (IP bloqueada): %s', src_ip)
                return

            # Verificar reglas de firewall
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            dst_port = (tcp_pkt.dst_port if tcp_pkt else
                        udp_pkt.dst_port if udp_pkt else None)

            if self._firewall_blocks(dp, src_ip, dst_ip, ip_pkt.proto, dst_port):
                return

            # Deteccion de port scan via SYN flood
            if tcp_pkt and (tcp_pkt.bits & 0x02):  # flag SYN
                self._check_port_scan(dp, src_ip, tcp_pkt.dst_port)

            # Instalar flujo en switch para trafico unicast conocido
            if out_port != ofproto.OFPP_FLOOD:
                self._install_ip_flow(dp, src_ip, dst_ip, ip_pkt.proto,
                                      dst_port, out_port)

        # Enviar paquete
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid  = ev.msg.datapath.id
        flows = []
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue
            flows.append({
                'priority':     stat.priority,
                'match':        str(stat.match),
                'packets':      stat.packet_count,
                'bytes':        stat.byte_count,
                'duration_sec': stat.duration_sec,
            })
        self.flow_stats[dpid] = flows

    # ------------------------------------------------------------------ #
    #  Helpers OpenFlow                                                    #
    # ------------------------------------------------------------------ #

    def _add_flow(self, dp, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        inst   = [parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        )
        dp.send_msg(mod)

    def _add_drop_flow(self, dp, priority, match, hard_timeout=0):
        parser = dp.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=[],
            hard_timeout=hard_timeout,
        )
        dp.send_msg(mod)

    def _delete_flow(self, dp, priority, match):
        ofproto = dp.ofproto
        parser  = dp.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=dp,
            command=ofproto.OFPFC_DELETE,
            priority=priority,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
        )
        dp.send_msg(mod)

    def _install_ip_flow(self, dp, src_ip, dst_ip, proto, dst_port, out_port):
        parser     = dp.ofproto_parser
        match_args = {
            'eth_type':  ether_types.ETH_TYPE_IP,
            'ipv4_src':  src_ip,
            'ipv4_dst':  dst_ip,
        }
        if proto == 6 and dst_port:
            match_args['ip_proto'] = 6
            match_args['tcp_dst']  = dst_port
        elif proto == 17 and dst_port:
            match_args['ip_proto'] = 17
            match_args['udp_dst']  = dst_port
        match   = parser.OFPMatch(**match_args)
        actions = [parser.OFPActionOutput(out_port)]
        self._add_flow(dp, priority=10, match=match,
                       actions=actions, idle_timeout=30)

    # ------------------------------------------------------------------ #
    #  Firewall                                                            #
    # ------------------------------------------------------------------ #

    def _firewall_blocks(self, dp, src_ip, dst_ip, proto, dst_port):
        proto_num = {'tcp': 6, 'udp': 17, 'icmp': 1}
        with self._lock:
            for rule in self.firewall_rules:
                if rule['action'] != 'block':
                    continue
                if rule['src_ip'] not in ('*', src_ip):
                    continue
                if rule['dst_ip'] not in ('*', dst_ip):
                    continue
                if rule['protocol'] != '*':
                    if proto != proto_num.get(rule['protocol'], -1):
                        continue
                if rule['dst_port'] is not None:
                    if dst_port != rule['dst_port']:
                        continue
                self.logger.info('FIREWALL BLOCK regla#%s: %s -> %s:%s',
                                 rule['id'], src_ip, dst_ip, dst_port)
                return True
        return False

    def _next_rule_id(self):
        rid = self._rule_id
        self._rule_id += 1
        return rid

    # ------------------------------------------------------------------ #
    #  Bloqueo de IP (instala regla DROP en switch)                       #
    # ------------------------------------------------------------------ #

    def block_ip(self, ip, reason='manual'):
        if ip in self.blocked_ips:
            return
        self.blocked_ips.add(ip)
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match  = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
            self._add_drop_flow(dp, priority=200, match=match)
        with self._lock:
            self.firewall_rules.append({
                'id':       'auto_%s' % ip.replace('.', '_'),
                'src_ip':   ip,
                'dst_ip':   '*',
                'protocol': '*',
                'dst_port': None,
                'action':   'block',
                'reason':   reason,
                'auto':     True,
            })
        self.logger.warning('IP BLOQUEADA: %s (razon: %s)', ip, reason)

    def unblock_ip(self, ip):
        self.blocked_ips.discard(ip)
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match  = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
            self._delete_flow(dp, priority=200, match=match)
        with self._lock:
            self.firewall_rules = [
                r for r in self.firewall_rules
                if not (r.get('auto') and r.get('src_ip') == ip)
            ]
        self.syn_counters.pop(ip, None)
        self.logger.info('IP DESBLOQUEADA: %s', ip)

    # ------------------------------------------------------------------ #
    #  Deteccion de anomalias                                              #
    # ------------------------------------------------------------------ #

    def _check_port_scan(self, dp, src_ip, dst_port):
        now = time.time()
        entries = self.syn_counters[src_ip]
        # Limpiar entradas fuera de la ventana
        self.syn_counters[src_ip] = [
            (ts, p) for ts, p in entries if now - ts < ANOMALY_TIME_WINDOW
        ]
        self.syn_counters[src_ip].append((now, dst_port))

        unique_ports = len(set(p for _, p in self.syn_counters[src_ip]))
        if unique_ports >= ANOMALY_PORT_THRESHOLD:
            self.logger.warning(
                'PORT SCAN DETECTADO: %s (%d puertos unicos en %ds) -> BLOQUEANDO',
                src_ip, unique_ports, ANOMALY_TIME_WINDOW)
            self.block_ip(src_ip, reason='port_scan_auto')

    # ------------------------------------------------------------------ #
    #  Estadisticas periodicas                                             #
    # ------------------------------------------------------------------ #

    def _stats_loop(self):
        while True:
            hub.sleep(STATS_POLL_INTERVAL)
            for dp in self.datapaths.values():
                req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)


# ======================================================================= #
#  REST API                                                                #
# ======================================================================= #

def _json_response(data, status=200):
    return Response(
        status=status,
        content_type='application/json',
        body=json.dumps(data, indent=2).encode('utf-8'),
    )


class SDNRestAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data['sdn_app']

    # --- Estadisticas globales ---

    @route('sdn', '/sdn/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        app = self.app
        return _json_response({
            'switches':    [str(dpid) for dpid in app.datapaths],
            'blocked_ips': list(app.blocked_ips),
            'mac_table':   {str(dpid): tbl
                            for dpid, tbl in app.mac_to_port.items()},
            'flow_stats':  {str(dpid): flows
                            for dpid, flows in app.flow_stats.items()},
        })

    @route('sdn', '/sdn/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        app = self.app
        switches = [
            {'dpid': str(dpid), 'mac_table': tbl}
            for dpid, tbl in app.mac_to_port.items()
        ]
        return _json_response({'switches': switches})

    # --- Reglas de firewall ---

    @route('sdn', '/sdn/firewall/rules', methods=['GET'])
    def list_rules(self, req, **kwargs):
        return _json_response(self.app.firewall_rules)

    @route('sdn', '/sdn/firewall/rules', methods=['POST'])
    def add_rule(self, req, **kwargs):
        try:
            body = json.loads(req.body)
        except Exception:
            return Response(status=400, body=b'JSON invalido')

        app = self.app
        with app._lock:
            rule = {
                'id':       app._next_rule_id(),
                'src_ip':   body.get('src_ip', '*'),
                'dst_ip':   body.get('dst_ip', '*'),
                'protocol': body.get('protocol', '*'),
                'dst_port': body.get('dst_port'),
                'action':   body.get('action', 'block'),
                'auto':     False,
            }
            app.firewall_rules.append(rule)

        app.logger.info('REGLA CREADA: %s', rule)
        return _json_response(rule)

    @route('sdn', '/sdn/firewall/rules/{rule_id}', methods=['DELETE'])
    def delete_rule(self, req, rule_id, **kwargs):
        app = self.app
        with app._lock:
            before = len(app.firewall_rules)
            app.firewall_rules = [
                r for r in app.firewall_rules if str(r['id']) != rule_id
            ]
            if len(app.firewall_rules) == before:
                return Response(status=404, body=b'Regla no encontrada')

        app.logger.info('REGLA ELIMINADA: id=%s', rule_id)
        return _json_response({'deleted': rule_id})

    # --- Bloqueo de IP ---

    @route('sdn', '/sdn/block/{ip}', methods=['POST'])
    def block_ip(self, req, ip, **kwargs):
        app = self.app
        if not app.datapaths:
            return Response(status=503, body=b'Sin switches conectados')
        app.block_ip(ip, reason='manual')
        return _json_response({'blocked': ip})

    @route('sdn', '/sdn/block/{ip}', methods=['DELETE'])
    def unblock_ip(self, req, ip, **kwargs):
        app = self.app
        if not app.datapaths:
            return Response(status=503, body=b'Sin switches conectados')
        app.unblock_ip(ip)
        return _json_response({'unblocked': ip})
