from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
import joblib
import numpy as np
import pandas as pd

class ExplainableIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExplainableIDS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # New Feature Set with PPS and BPS
        self.features = ['packet_count', 'byte_count', 'duration_sec', 'pps', 'bps', 'protocol_type']
        
        # Deduplication Cache to prevent console spam
        self.blocked_ips = set()
        
        print("\n⏳ Loading Upgraded ML Model (PPS/BPS enabled)...", flush=True)
        self.model = joblib.load('rf_model.pkl')
        self.explainer = joblib.load('shap_explainer.pkl')
        print("✅ Production-Grade IDS Controller Initialized!\n", flush=True)

        self.monitor_thread = hub.spawn(self._monitor)
        self.cleanup_thread = hub.spawn(self._cache_cleanup)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                print(f"🔗 Registered Switch Datapath: DPID={datapath.id}", flush=True)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        """Polls switch flow counters every 3 seconds."""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(3)

    def _cache_cleanup(self):
        """Clears the blocked IP cache every 20 seconds to align with idle_timeout."""
        while True:
            hub.sleep(20)
            self.blocked_ips.clear()

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser

        for stat in body:
            # Only monitor active forwarding flows
            if stat.priority != 1:
                continue

            real_packet_count = stat.packet_count
            real_byte_count = stat.byte_count
            real_duration = stat.duration_sec + (stat.duration_nsec / 1e9)
            
            # Extract IP from OFPMatch object safely
            ip_src = stat.match.to_jsondict()['OFPMatch'].get('oxm_fields', [])
            src_ip_val = None
            proto_val = 1 # Default ICMP
            
            for field in ip_src:
                if field.get('OXMTlv', {}).get('field') == 'ipv4_src':
                    src_ip_val = field['OXMTlv']['value']
                if field.get('OXMTlv', {}).get('field') == 'ip_proto':
                    proto_val = field['OXMTlv']['value']

            if real_packet_count == 0 or not src_ip_val:
                continue
                
            # Skip if already mitigated in this window
            if src_ip_val in self.blocked_ips:
                continue

            duration = max(real_duration, 0.1)
            # Engineered Rate Features
            pps = real_packet_count / duration
            bps = real_byte_count / duration

            flow_df = pd.DataFrame([[real_packet_count, real_byte_count, duration, pps, bps, proto_val]],
                                   columns=self.features)

            pred = self.model.predict(flow_df)[0]

            if pred == 1:
                # Add to deduplication cache
                self.blocked_ips.add(src_ip_val)
                
                # Identify Attack Type based on protocol
                attack_map = {1: "ICMP Volumetric Flood", 6: "TCP SYN Flood", 17: "UDP Bandwidth Flood"}
                attack_type = attack_map.get(proto_val, "Generic Network Flood")

                print(f"\n🚨 [ATTACK DETECTED: {attack_type}] Host: {src_ip_val}", flush=True)
                print(f"📈 [HARDWARE STATS] Packets: {real_packet_count} | PPS: {pps:.2f} pkt/s | BPS: {bps:.2f} B/s", flush=True)
                
                shap_vals = self.explainer.shap_values(flow_df)
                vals = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]
                top_idx = int(np.argmax(np.abs(vals)))
                top_feat = self.features[top_idx]

                print(f"📊 [XAI ATTRIBUTION] Primary Anomaly: '{top_feat}' (Observed: {flow_df[top_feat].values[0]:.2f})", flush=True)
                print(f"🛡️  [FLOW MITIGATION] Installing priority-100 DROP rule (timeout=15s)\n", flush=True)

                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip_val)
                self.add_flow(datapath, priority=100, match=match, actions=[], idle_timeout=15)

                import json, time
                alert_data = {"time": time.strftime("%H:%M:%S"), "ip": src_ip_val, "type": attack_type, 
                              "pps": round(pps, 2), "bps": round(bps, 2), "driver": top_feat}
                with open("alerts.json", "a") as f:
                    f.write(json.dumps(alert_data) + "\n")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                # Capture protocol type for multi-attack detection
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst,
                                        ip_proto=ip_pkt.proto)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)