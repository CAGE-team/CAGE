import subprocess
import threading
import queue
import logging
import time
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from src.uid_resolver import SYSTEM_NAMESPACES

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger("network-monitor")

def hex_to_ip(hex_str):
    addr = int(hex_str, 16)
    return socket.inet_ntoa(struct.pack("<I", addr))

def hex_to_port(hex_str):
    return int(hex_str, 16)

def read_proc_net_tcp(namespace, pod_name):
    """Read /proc/net/tcp from inside a pod via kubectl exec"""
    try:
        result = subprocess.run(
            ["kubectl", "exec", "-n", namespace, pod_name, "--", "cat", "/proc/net/tcp"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout
    except Exception:
        return ""

def parse_tcp_connections(raw):
    connections = []
    for line in raw.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        remote = parts[2]
        state = parts[3]
        # state 01 = ESTABLISHED
        if state != "01":
            continue
        local_ip, local_port = local.split(":")
        remote_ip, remote_port = remote.split(":")
        connections.append({
            "local_ip": hex_to_ip(local_ip),
            "local_port": hex_to_port(local_port),
            "remote_ip": hex_to_ip(remote_ip),
            "remote_port": hex_to_port(remote_port),
        })
    return connections

class NetworkMonitor:
    def __init__(self, cache, out_queue: queue.Queue, poll_interval=5):
        self.cache = cache
        self.out_queue = out_queue
        self.poll_interval = poll_interval
        self._seen = set()  # avoid duplicate events
        self._seen_lock = threading.Lock()
        self._api_server_ip = self._resolve_api_server_ip()

    def _resolve_api_server_ip(self):
        """Look up the real in-cluster API server ClusterIP instead of
        hardcoding kind's default (10.96.0.1) — that value only holds
        because kind defaults to the 10.96.0.0/12 service CIDR; a cluster
        configured with a different service CIDR has a different address
        here, and without this the hardcoded value silently stops excluding
        the API server, turning routine in-cluster API calls into apparent
        T1610 scan traffic."""
        try:
            from kubernetes import client
            svc = client.CoreV1Api().read_namespaced_service("kubernetes", "default")
            ip = svc.spec.cluster_ip
            log.info(f"Resolved in-cluster API server ClusterIP: {ip}")
            return ip
        except Exception as e:
            log.warning(f"Could not resolve API server ClusterIP, falling back to none: {e}")
            return None

    def start(self, pods_to_monitor=None):
        # List of (namespace, pod_name) pairs. If not given explicitly,
        # watch every pod currently known to the UID cache outside the
        # noisy system namespaces — not just one hardcoded pod name, so
        # lateral movement is observable from any compromised workload,
        # not only from a pod literally named "attacker".
        if pods_to_monitor is not None:
            self._pods = pods_to_monitor
        else:
            self._pods = [
                (meta["ns"], meta["name"])
                for meta in self.cache.snapshot().values()
                if meta.get("ns") not in SYSTEM_NAMESPACES
            ]
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        log.info(f"Network monitor started, watching pods: {self._pods}")

    def _loop(self):
        # Checking pods sequentially (one kubectl exec at a time) meant a
        # full sweep's wall-clock time grew with the number of monitored
        # pods — with enough pods, the time between two checks of the SAME
        # pod exceeded CONNECTION_BURST_WINDOW_SECONDS (10s) in
        # causal_graph.py, so a genuine 5-distinct-destination scan burst
        # got split across separate sweeps and T1610 could never fire no
        # matter how long the connections were held open. A thread pool
        # keeps one sweep's duration close to poll_interval regardless of
        # how many pods are being watched.
        with ThreadPoolExecutor(max_workers=max(1, len(self._pods) or 1)) as pool:
            while True:
                futures = {
                    pool.submit(self._check_pod, namespace, pod_name): (namespace, pod_name)
                    for namespace, pod_name in self._pods
                }
                for future in futures:
                    namespace, pod_name = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        log.warning(f"Error checking {namespace}/{pod_name}: {e}")
                time.sleep(self.poll_interval)

    def _check_pod(self, namespace, pod_name):
        raw = read_proc_net_tcp(namespace, pod_name)
        if not raw:
            return

        conns = parse_tcp_connections(raw)
        for conn in conns:
            remote_ip = conn["remote_ip"]

            # Skip loopback and the kubernetes API server (resolved dynamically
            # at startup — see _resolve_api_server_ip — rather than assuming
            # kind's default ClusterIP).
            if remote_ip.startswith("127.") or (self._api_server_ip and remote_ip == self._api_server_ip):
                continue

            # Look up source pod UID
            src_uid = self.cache.resolve_by_name(namespace, pod_name)

            # Look up destination pod UID
            dst_uid = self.cache.resolve_by_ip(remote_ip)
            dst_meta = self.cache.get_meta(dst_uid) if dst_uid else None
            dst_name = dst_meta["name"] if dst_meta else remote_ip

            key = (namespace, pod_name, remote_ip, conn["remote_port"])
            with self._seen_lock:
                if key in self._seen:
                    continue
                self._seen.add(key)

            log.info(f"[NET] {namespace}/{pod_name} -> {dst_name} ({remote_ip}:{conn['remote_port']})")

            self.out_queue.put({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event_type": "network_connect",
                "src_pod": pod_name,
                "src_uid": src_uid,
                "dst_ip": remote_ip,
                "dst_port": conn["remote_port"],
                # Field names must match what causal_graph.py's _check_t1610
                # reads (dst_pod_name / dst_pod_uid) — tetragon_consumer.py's
                # own network_connect producer already uses these names;
                # this one didn't, so every event NetworkMonitor ever
                # produced was silently rejected by the T1610 rule
                # (event.get("dst_pod_name", "") was always "" here).
                "dst_pod_name": dst_name,
                "dst_pod_uid": dst_uid,
                "namespace": namespace,
                "pod_uid": src_uid,
                "pod_name": pod_name,
            })

if __name__ == "__main__":
    from src.uid_resolver import PodUIDCache
    from kubernetes import config
    config.load_kube_config()

    cache = PodUIDCache()
    cache.start_watch()
    time.sleep(2)

    q = queue.Queue()
    monitor = NetworkMonitor(cache, q)
    monitor.start(pods_to_monitor=[("default", "attacker")])

    # Make attacker connect to victim
    VICTIM_IP = "10.244.2.4"
    log.info(f"Triggering connection from attacker to victim ({VICTIM_IP})...")
    subprocess.Popen(
        ["kubectl", "exec", "attacker", "--",
         "bash", "-c", f"cat /proc/version > /dev/tcp/{VICTIM_IP}/8080 2>/dev/null || true"],
    )

    log.info("Monitoring for 30s...")
    start = time.time()
    while time.time() - start < 30:
        try:
            ev = q.get(timeout=1)
            print(f"\n[T1021 DETECTED] {ev['src_pod']} -> {ev['dst_pod_name']} on port {ev['dst_port']}")
            print(f"  src_uid={ev['src_uid']}")
            print(f"  dst_uid={ev['dst_pod_uid']}")
        except queue.Empty:
            pass
