"""
AIMMS - Day 4: Network Packet Sniffer
Uses Scapy to capture packets and POST them to the Node.js API.
Run as root: sudo python3 sniffer.py
"""

import time
import threading
import requests
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, conf

# ─── Config ───────────────────────────────────────────────────────────────────
API_URL       = "http://localhost:3000/api/network-event"
BATCH_SIZE    = 10       # send every N packets
BATCH_TIMEOUT = 2.0      # or every N seconds, whichever comes first
IGNORED_IPS   = {"127.0.0.1"}  # add your own IP here to avoid self-noise

# ─── Shared state ─────────────────────────────────────────────────────────────
batch     = []
batch_lock = threading.Lock()
last_flush = time.time()

# ─── Packet handler ───────────────────────────────────────────────────────────
def handle_packet(pkt):
    global last_flush

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if src_ip in IGNORED_IPS:
        return

    protocol = "OTHER"
    dst_port = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        dst_port = pkt[UDP].dport

    event = {
        "source_ip":  src_ip,
        "dest_ip":    dst_ip,
        "port":       dst_port,
        "protocol":   protocol,
        "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S")
    }

    with batch_lock:
        batch.append(event)
        should_flush = (
            len(batch) >= BATCH_SIZE or
            (time.time() - last_flush) >= BATCH_TIMEOUT
        )

    if should_flush:
        flush_batch()

# ─── Batch sender ─────────────────────────────────────────────────────────────
def flush_batch():
    global last_flush

    with batch_lock:
        if not batch:
            return
        to_send = batch.copy()
        batch.clear()
        last_flush = time.time()

    try:
        resp = requests.post(
            API_URL,
            json={"events": to_send},
            timeout=3
        )
        print(f"[sniffer] sent {len(to_send)} events → {resp.status_code}")
    except requests.exceptions.ConnectionError:
        print("[sniffer] ERROR: cannot reach API. Is Node.js running?")
    except Exception as e:
        print(f"[sniffer] ERROR: {e}")

# ─── Periodic flush thread (catches leftover packets) ─────────────────────────
def flush_worker():
    while True:
        time.sleep(BATCH_TIMEOUT)
        flush_batch()

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[sniffer] starting AIMMS packet sniffer...")
    print(f"[sniffer] posting to {API_URL}")
    print("[sniffer] press Ctrl+C to stop\n")

    t = threading.Thread(target=flush_worker, daemon=True)
    t.start()

    # filter: only TCP/UDP, skip loopback
    sniff(
        filter="ip and (tcp or udp)",
        prn=handle_packet,
        store=False
    )
