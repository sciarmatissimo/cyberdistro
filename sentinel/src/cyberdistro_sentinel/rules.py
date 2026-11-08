"""Layer 2 — deterministic correlation.

Turns normalised events into incidents. Every incident carries:
  rule      which rule fired (stable id, used by the explanation cards)
  level     "confermato" (signature or deterministic threshold met) or
            "sospetto" (anomaly without a signature)
  severity  "bassa" | "media" | "alta"
  facts     the numbers and names the explanation may use — and nothing else
  evidence  up to 20 pointers to the engine records that support it

The language model never reaches this module: colour and urgency come from
here only.
"""

from __future__ import annotations

import ipaddress
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .config import Thresholds
from .events import Event, is_internal

CONFIRMED, SUSPICIOUS = "confermato", "sospetto"
LOW, MEDIUM, HIGH = "bassa", "media", "alta"
SCAN_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "RSTR", "RSTRH", "SH", "SHR", "OTH"}
MAX_EVIDENCE = 20
# Suricata categories that describe normal traffic: recorded, never an alarm.
INFO_CATEGORIES = {"Not Suspicious Traffic", "Unknown Traffic", "Generic Protocol Command Decode"}
# Periodic by design (time sync, DNS, discovery): never "beaconing".
BEACON_SKIP_PORTS = {53, 123, 1900, 5353}
USER_GRACE = 30.0          # seconds after the end of a scan the user started


@dataclass
class Incident:
    key: str
    rule: str
    level: str
    severity: str
    src: str | None
    dst: str | None
    first_ts: float
    last_ts: float
    count: int = 1
    facts: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)

    def add_evidence(self, refs):
        for r in refs:
            if r not in self.evidence and len(self.evidence) < MAX_EVIDENCE:
                self.evidence.append(r)


@dataclass
class Device:
    mac: str | None
    ip: str | None
    first_seen: float
    last_seen: float
    hostname: str | None = None
    mdns_names: list = field(default_factory=list)
    services: list = field(default_factory=list)
    is_gateway: bool = False
    is_self: bool = False
    new: bool = False


class Window:
    """Time-ordered deque of (ts, value, ref) trimmed to a window."""

    def __init__(self, span: float):
        self.span, self.q = span, deque()

    def add(self, ts, value, ref):
        self.q.append((ts, value, ref))
        while self.q and ts - self.q[0][0] > self.span:
            self.q.popleft()

    def values(self):
        return [v for _, v, _ in self.q]

    def refs(self):
        return [r for _, _, r in self.q]


class Correlator:
    def __init__(self, th: Thresholds | None = None):
        self.th = th or Thresholds()
        self.incidents: dict[str, Incident] = {}
        self.changed: set[str] = set()
        self.devices: dict[str, Device] = {}          # key: mac (or "ip:<addr>" when no mac)
        self.ip_index: dict[str, str] = {}            # ip -> device key
        self.ip_mac: dict[str, tuple[str, float]] = {}
        self.mac_ips: dict[str, set] = defaultdict(set)
        self.gateway: str | None = None
        self.self_ip: str | None = None
        self.start_ts: float | None = None
        # Activity the user started from the Security Center: (start, end, kind, target)
        self.user_windows: list[tuple[float, float, str, str]] = []
        self.last_ts: dict[str, float] = {}           # per engine: last record seen
        w = defaultdict
        self._scan = w(lambda: Window(self.th.scan_window))
        self._sweep = w(lambda: Window(self.th.scan_window))
        self._brute = w(lambda: Window(self.th.brute_window))
        self._nx = w(lambda: Window(self.th.nxdomain_window))
        self._tun = w(lambda: Window(self.th.tunnel_window))
        self._beacon = w(list)
        self._exfil = w(lambda: Window(self.th.exfil_window))
        self._lateral = w(lambda: Window(self.th.lateral_window))

    # ------------------------------------------------------------ helpers
    def set_user_activity(self, windows) -> None:
        """Scans the user started (from the actions table): [(start, end|None, kind, target)]."""
        self.user_windows = [(float(a), float(b) if b else float(a) + 900.0, k, t) for a, b, k, t in windows]

    def by_user(self, ts: float, peer: str | None = None) -> bool:
        """True if ``ts`` falls in a scan the user started; with ``peer``, the other
        endpoint must also be the scan's target (address or network) or the router."""
        for a, b, _kind, target in self.user_windows:
            if not (a - 5.0 <= ts <= b + USER_GRACE):
                continue
            if peer is None or peer == self.gateway:
                return True
            try:
                if ipaddress.ip_address(peer) in ipaddress.ip_network(target, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def role(self, ip) -> str | None:
        if not ip:
            return None
        if ip == self.self_ip:
            return "self"
        if ip == self.gateway:
            return "gateway"
        return None

    def _raise(self, key, rule, level, severity, ev: Event, facts, refs, src=..., dst=...):
        inc = self.incidents.get(key)
        if inc is None:
            inc = Incident(key=key, rule=rule, level=level, severity=severity,
                           src=ev.src if src is ... else src,
                           dst=ev.dst if dst is ... else dst,
                           first_ts=ev.ts, last_ts=ev.ts, facts=dict(facts))
            for side in ("src", "dst"):
                r = self.role(getattr(inc, side))
                if r:
                    inc.facts[f"{side}_role"] = r
            self.incidents[key] = inc
        else:
            inc.last_ts = ev.ts
            inc.count += 1
            inc.facts.update(facts)
            # escalate, never downgrade
            if {LOW: 0, MEDIUM: 1, HIGH: 2}[severity] > {LOW: 0, MEDIUM: 1, HIGH: 2}[inc.severity]:
                inc.severity = severity
            if level == CONFIRMED:
                inc.level = CONFIRMED
        inc.add_evidence(refs)
        self.changed.add(key)
        return inc

    def _device(self, mac, ip, ts):
        if not mac and not ip:
            return Device(mac=None, ip=None, first_seen=ts, last_seen=ts)
        if not mac and ip in self.ip_index:          # known by IP already (maybe with MAC)
            k = self.ip_index[ip]
        else:
            k = mac or f"ip:{ip}"
        if mac and ip and f"ip:{ip}" in self.devices and k != f"ip:{ip}":
            old = self.devices.pop(f"ip:{ip}")      # merge an IP-only entry into the MAC entry
            if k not in self.devices:
                old.mac = mac
                self.devices[k] = old
        d = self.devices.get(k)
        if d is None:
            new = self.start_ts is not None and ts - self.start_ts > self.th.learning_period
            d = Device(mac=mac, ip=ip, first_seen=ts, last_seen=ts, new=new)
            self.devices[k] = d
            if ip and ip == self.gateway:
                d.is_gateway = True
            if ip and ip == self.self_ip:
                d.is_self = True
            if new and not d.is_self:
                f = {"mac": mac, "ip": ip}
                if self.by_user(ts):
                    f["found_by_scan"] = True       # it answered the user's scan: it was already there
                self._raise(f"new_device:{k}", "new_device", CONFIRMED, LOW,
                            Event(ts=ts, engine="sensor", kind="device", ref=f"device:{k}", src=ip),
                            f, [f"device:{k}"])
        d.last_seen = max(d.last_seen, ts)
        if ip:
            d.ip = ip
            self.ip_index[ip] = k
            d.is_gateway = d.is_gateway or ip == self.gateway
        return d

    # ------------------------------------------------------------ main entry
    def process(self, ev: Event) -> None:
        if self.start_ts is None:
            self.start_ts = ev.ts
        self.last_ts[ev.engine] = max(self.last_ts.get(ev.engine, 0.0), ev.ts)
        h = getattr(self, f"_on_{ev.engine}_{ev.kind}", None)
        if h:
            h(ev)

    # ------------------------------------------------------------ sensor
    def _on_sensor_net(self, ev):
        self.gateway = ev.data.get("gateway") or self.gateway
        self.self_ip = ev.data.get("self_ip") or self.self_ip
        if self.self_ip:
            self._device(ev.data.get("self_mac"), self.self_ip, ev.ts).is_self = True

    def _on_sensor_arp(self, ev):
        ip, mac = ev.src, ev.data.get("mac")
        if not ip or not mac:
            return
        prev = self.ip_mac.get(ip)
        self.mac_ips[mac].add(ip)
        if prev and prev[0] != mac:
            gw = ip == self.gateway
            self._raise(f"arp_spoof:{ip}", "arp_spoof", CONFIRMED if gw else SUSPICIOUS,
                        HIGH if gw else MEDIUM, ev,
                        {"ip": ip, "old_mac": prev[0], "new_mac": mac, "is_gateway": gw},
                        [ev.ref], src=None, dst=ip)
            self._device(mac, None, ev.ts)          # the claimant, without the claimed IP
            if gw:
                return                              # keep the gateway's original identity
        else:
            self._device(mac, ip, ev.ts)
        self.ip_mac[ip] = (mac, ev.ts)
        internal = [a for a in self.mac_ips[mac] if ":" not in a]
        if len(internal) >= 5:
            self._raise(f"arp_multi:{mac}", "arp_multi_ip", SUSPICIOUS, MEDIUM, ev,
                        {"mac": mac, "ip_count": len(internal)}, [ev.ref], src=None, dst=None)

    def _on_sensor_ipmac(self, ev):
        """Gateway MAC learned from normal IP traffic (not ARP)."""
        ip, mac = ev.src, ev.data.get("mac")
        if not ip or not mac:
            return
        prev = self.ip_mac.get(ip)
        if prev is None:
            self.ip_mac[ip] = (mac, ev.ts)
            self._device(mac, ip, ev.ts)

    def _on_sensor_dhcp(self, ev):
        d = self._device(ev.data.get("mac"), ev.src, ev.ts)
        if ev.data.get("hostname"):
            d.hostname = ev.data["hostname"]

    def _on_sensor_mdns(self, ev):
        d = self._device(ev.data.get("mac"), ev.src, ev.ts)
        d.mdns_names = sorted(set(d.mdns_names) | set(ev.data.get("names") or []))[:8]
        d.services = sorted(set(d.services) | set(ev.data.get("services") or []))[:16]

    def _on_sensor_ndp(self, ev):
        self._device(ev.data.get("mac"), ev.src, ev.ts)

    # ------------------------------------------------------------ suricata
    def _on_suricata_alert(self, ev):
        sev = {1: HIGH, 2: MEDIUM}.get(ev.data.get("severity"), LOW)
        sid = ev.data.get("signature_id")
        cat = ev.data.get("category")
        f = {"signature": ev.data.get("signature"), "category": cat, "signature_id": sid}
        if cat in INFO_CATEGORIES:
            f["informational"] = True
            sev = LOW
        elif self.self_ip in (ev.src, ev.dst) and self.by_user(
                ev.ts, peer=ev.dst if ev.src == self.self_ip else ev.src):
            f["by_user"] = True                     # side effect of a scan the user started
            sev = LOW
        self._raise(f"suricata:{sid}:{ev.src}:{ev.dst}", "suricata_alert", CONFIRMED, sev, ev, f, [ev.ref])

    def _own(self, ev, kind, facts, refs, dst=...):
        """This PC is the one scanning/connecting. Started by the user = information;
        not started by the user = a program on this PC is doing it (suspicious)."""
        target = ev.dst if dst is ... else dst
        mine = self.by_user(ev.ts, peer=target)
        return self._raise(f"own:{kind}:{target or 'rete'}:{'user' if mine else 'auto'}", "own_scan",
                           CONFIRMED, LOW if mine else MEDIUM, ev,
                           {**facts, "kind": kind, "by_user": mine}, refs, dst=target)

    # ------------------------------------------------------------ zeek
    def _on_zeek_conn(self, ev):
        th, d = self.th, ev.data
        src, dst, dport = ev.src, ev.dst, ev.dport
        if not src or not dst:
            return
        if is_internal(src) and ":" not in src:
            self._device(None, src, ev.ts)
        # port scan (vertical) and sweep (horizontal)
        if d.get("state") in SCAN_STATES and dport is not None:
            w = self._scan[(src, dst)]
            w.add(ev.ts, dport, ev.ref)
            ports = set(w.values())
            if len(ports) >= th.scan_ports and src == self.self_ip:
                self._own(ev, "porte", {"ports": len(ports), "window_s": int(th.scan_window)}, w.refs()[-5:])
            elif len(ports) >= th.scan_ports:
                self._raise(f"port_scan:{src}:{dst}", "port_scan", CONFIRMED,
                            HIGH if dst == self.self_ip else MEDIUM, ev,
                            {"ports": len(ports), "window_s": int(th.scan_window)}, w.refs()[-5:])
            s = self._sweep[(src, dport)]
            s.add(ev.ts, dst, ev.ref)
            hosts = set(s.values())
            if len(hosts) >= th.sweep_hosts and src == self.self_ip:
                self._own(ev, "rete", {"hosts": len(hosts), "port": dport, "window_s": int(th.scan_window)},
                          s.refs()[-5:], dst=None)
            elif len(hosts) >= th.sweep_hosts:
                self._raise(f"sweep:{src}:{dport}", "host_sweep", CONFIRMED, MEDIUM, ev,
                            {"hosts": len(hosts), "port": dport, "window_s": int(th.scan_window)},
                            s.refs()[-5:], dst=None)
        # brute force on login services (only connections that got an answer)
        if dport in th.brute_ports and d.get("state") not in SCAN_STATES:
            w = self._brute[(src, dst, dport)]
            w.add(ev.ts, 1, ev.ref)
            n = len(w.values())
            if n >= th.brute_conns and src == self.self_ip and self.by_user(ev.ts):
                pass                                # the user's own scan touching a login port
            elif n >= th.brute_conns:
                self._raise(f"brute:{src}:{dst}:{dport}", "brute_force", CONFIRMED,
                            HIGH if dst == self.self_ip else MEDIUM, ev,
                            {"attempts": n, "port": dport, "window_s": int(th.brute_window)},
                            w.refs()[-5:])
        # lateral movement: internal -> many internal on admin ports
        if is_internal(src) and is_internal(dst) and dport in th.lateral_ports and d.get("state") not in SCAN_STATES:
            w = self._lateral[src]
            w.add(ev.ts, dst, ev.ref)
            hosts = set(w.values())
            if len(hosts) >= th.lateral_hosts and src == self.self_ip and self.by_user(ev.ts):
                self._own(ev, "amministrazione", {"hosts": len(hosts), "window_s": int(th.lateral_window)},
                          w.refs()[-5:], dst=None)
            elif len(hosts) >= th.lateral_hosts:
                self._raise(f"lateral:{src}", "lateral_movement", SUSPICIOUS, MEDIUM, ev,
                            {"hosts": len(hosts), "window_s": int(th.lateral_window)},
                            w.refs()[-5:], dst=None)
        # outbound to external
        if is_internal(src) and not is_internal(dst):
            ob = int(d.get("orig_bytes") or 0)
            if ob:
                w = self._exfil[(src, dst)]
                w.add(ev.ts, ob, ev.ref)
                total = sum(w.values())
                if total >= th.exfil_bytes:
                    self._raise(f"exfil:{src}:{dst}", "exfiltration", SUSPICIOUS, MEDIUM, ev,
                                {"megabytes": round(total / 1048576), "window_s": int(th.exfil_window)},
                                w.refs()[-5:])
            if dport in BEACON_SKIP_PORTS:
                return
            b = self._beacon[(src, dst, dport)]
            b.append((ev.ts, ev.ref))
            if len(b) > 50:
                del b[0]
            if len(b) >= th.beacon_min_conns:
                ts = [t for t, _ in b]
                gaps = [y - x for x, y in zip(ts, ts[1:])]
                mean = statistics.fmean(gaps)
                if mean >= th.beacon_min_interval:
                    cv = statistics.pstdev(gaps) / mean if mean else 1.0
                    if cv <= th.beacon_max_cv:
                        self._raise(f"beacon:{src}:{dst}:{dport}", "beaconing", SUSPICIOUS, MEDIUM, ev,
                                    {"connections": len(b), "interval_s": round(mean),
                                     "port": dport}, [r for _, r in b][-5:])

    def _on_zeek_dns(self, ev):
        th, d, src = self.th, ev.data, ev.src
        q = d.get("query") or ""
        if d.get("rcode") == "NXDOMAIN":
            w = self._nx[src]
            w.add(ev.ts, q, ev.ref)
            n = len(set(w.values()))
            if n >= th.nxdomain_count and not (src == self.self_ip and self.by_user(ev.ts)):
                self._raise(f"nxdomain:{src}", "dns_nxdomain_burst", SUSPICIOUS, MEDIUM, ev,
                            {"domains": n, "window_s": int(th.nxdomain_window)}, w.refs()[-5:], dst=None)
        labels = q.split(".")
        if q and (max((len(x) for x in labels), default=0) >= th.tunnel_label_len or d.get("qtype") == "TXT"):
            parent = ".".join(labels[-2:]) if len(labels) >= 2 else q
            w = self._tun[(src, parent)]
            w.add(ev.ts, q, ev.ref)
            n = len(w.values())
            if n >= th.tunnel_count:
                self._raise(f"dns_tunnel:{src}:{parent}", "dns_tunnel", SUSPICIOUS, MEDIUM, ev,
                            {"queries": n, "window_s": int(th.tunnel_window)}, w.refs()[-5:], dst=None)

    def _on_zeek_ssh(self, ev):
        if ev.data.get("auth_success") is True:
            key = f"brute:{ev.src}:{ev.dst}:22"
            if key in self.incidents:
                self._raise(key, "brute_force", CONFIRMED, HIGH, ev,
                            {"login_succeeded": True}, [ev.ref])

    # ------------------------------------------------------------ batch
    def run(self, events) -> dict[str, Incident]:
        for e in events:
            self.process(e)
        return self.incidents

    def pop_changed(self) -> list[Incident]:
        out = [self.incidents[k] for k in sorted(self.changed)]
        self.changed.clear()
        return out
