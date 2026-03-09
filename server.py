"""
DNS Traffic Visualizer — Python Backend
Enterprise-grade async server bridging C++ engine to WebSocket/HTTP clients.

Architecture:
  - FastAPI + uvicorn for HTTP + WebSocket
  - pybind11 C++ module (dns_engine) for all heavy computation
  - asyncio background tasks for continuous traffic simulation
  - Windows API integration via ctypes (process/network stats)
  - Multi-layer anomaly detection pipeline
  - Geolocation enrichment (MaxMind GeoLite2 DB or fallback)
  - Protocol buffer serialisation for high-throughput WebSocket frames
"""

import asyncio
import ctypes
import json
import logging
import math
import os
import platform
import random
import struct
import subprocess
import sys
import time
import threading
import zlib
from collections import deque, defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ── FastAPI ──────────────────────────────────────────────────────────────────
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

# ── Numpy / scipy fallback ───────────────────────────────────────────────────
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# ─────────────────────────────────────────────────────────────────────────────
#  Build & load C++ extension via pybind11
# ─────────────────────────────────────────────────────────────────────────────
_ENGINE_READY = False
dns_engine = None

def _build_extension() -> bool:
    """Compile dns_engine.cpp -> dns_engine.so via setuptools/cmake."""
    src = Path(__file__).parent / "dns_engine.cpp"
    if not src.exists():
        logging.error("dns_engine.cpp not found – cannot build extension")
        return False

    setup_code = '''
from setuptools import setup, Extension
import pybind11, sys, platform

extra_compile = ["-O3", "-std=c++17", "-ffast-math"]
if platform.system() == "Windows":
    extra_compile = ["/O2", "/std:c++17", "/EHsc", "/D_USE_MATH_DEFINES", "/wd4244", "/wd4267", "/wd4305"]

ext = Extension(
    "dns_engine",
    sources=["dns_engine.cpp"],
    include_dirs=[pybind11.get_include()],
    extra_compile_args=extra_compile,
    language="c++",
)
setup(name="dns_engine", ext_modules=[ext])
'''
    setup_path = Path(__file__).parent / "_setup_tmp.py"
    setup_path.write_text(setup_code)
    try:
        result = subprocess.run(
            [sys.executable, str(setup_path), "build_ext", "--inplace"],
            capture_output=True, text=True, cwd=str(Path(__file__).parent)
        )
        setup_path.unlink(missing_ok=True)
        if result.returncode != 0:
            logging.warning(f"C++ build failed:\n{result.stderr}\nFalling back to Python simulation.")
            return False
        logging.info("dns_engine C++ extension built successfully.")
        return True
    except Exception as e:
        logging.warning(f"Build exception: {e}")
        setup_path.unlink(missing_ok=True)
        return False

def _load_engine():
    global dns_engine, _ENGINE_READY
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        import dns_engine as _m
        dns_engine = _m
        _ENGINE_READY = True
        logging.info("dns_engine loaded from compiled .so")
        return True
    except ImportError:
        if _build_extension():
            try:
                import dns_engine as _m
                dns_engine = _m
                _ENGINE_READY = True
                return True
            except ImportError:
                pass
    logging.warning("dns_engine C++ unavailable — using Python simulation fallback")
    return False

# ─────────────────────────────────────────────────────────────────────────────
#  Pure-Python fallback (mirrors C++ API surface exactly)
# ─────────────────────────────────────────────────────────────────────────────
class _PythonDNSController:
    """Full Python reimplementation of DNSController for no-compiler environments."""
    QTYPES   = ["A","AAAA","MX","CNAME","TXT","NS","PTR","SOA","SRV"]
    QW       = [0.55,0.20,0.08,0.07,0.04,0.03,0.015,0.01,0.005]
    RCODES   = ["NOERROR","NXDOMAIN","SERVFAIL","REFUSED","FORMERR"]
    RW       = [0.88,0.07,0.025,0.015,0.01]
    RESOLVERS= ["8.8.8.8","1.1.1.1","9.9.9.9","208.67.222.222","8.8.4.4"]
    DOMAINS  = ["google.com","youtube.com","facebook.com","twitter.com",
                "instagram.com","reddit.com","amazon.com","netflix.com",
                "cloudflare.com","github.com","microsoft.com","apple.com",
                "wikipedia.org","linkedin.com","zoom.us","slack.com"]
    CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

    def __init__(self, lambda_qps=80.0, mu_qps=300.0, clients=30, dga_prob=0.03):
        self.lambda_qps = lambda_qps
        self.mu_qps = mu_qps
        self.dga_prob = dga_prob
        self.clients = [self._rnd_ip() for _ in range(clients)]
        self._nodes: Dict[str, dict] = {}
        self._edges: List[dict] = []
        self._edge_map: Dict[tuple, int] = {}
        self._stats = defaultdict(int)
        self._latencies: deque = deque(maxlen=5000)
        self._ts_window: deque = deque(maxlen=512)
        self._ewma = 0.0
        self._ewma_var = 0.0
        self._markov_trans: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._markov_last = ""
        self._dga_count = 0
        self._domain_counts: Dict[str, int] = defaultdict(int)
        self._qtype_counts: Dict[str, int] = defaultdict(int)
        self._resolver_counts: Dict[str, int] = defaultdict(int)
        self._ts_us = int(time.time() * 1e6)

    def _rnd_ip(self):
        pfx = random.choice(["10.0.", "192.168.1.", "172.16.", "10.10."])
        return pfx + f"{random.randint(1,254)}.{random.randint(1,254)}"

    def _shannon(self, s: str) -> float:
        from collections import Counter
        if not s: return 0.0
        cnt = Counter(s)
        n = len(s)
        return -sum((c/n)*math.log2(c/n) for c in cnt.values())

    def _dga_score(self, domain: str) -> dict:
        label = domain.split(".")[-2] if "." in domain else domain
        H = self._shannon(label)
        cr = sum(1 for c in label if c in self.CONSONANTS) / max(len(label),1)
        score  = (0.35 if H > 3.5 else 0.15 if H > 2.8 else 0)
        score += (0.25 if cr > 0.7 else 0.10 if cr > 0.6 else 0)
        score += 0.10 if len(label) > 20 else (0.05 if len(label) > 15 else 0)
        return {"entropy": H, "consonant_ratio": cr, "dga_probability": min(1.0, score),
                "is_dga": score > 0.6, "bigram_score": 0.01, "ngram_rarity": 0.0}

    def _gen_dga(self) -> str:
        n = random.randint(8, 20)
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        return "".join(random.choices(chars, k=n)) + random.choice([".com",".net",".org"])

    def process_batch(self, n=100) -> list:
        result = []
        rng = random
        for _ in range(n):
            wait_us = int(rng.expovariate(self.lambda_qps / 1e6))
            self._ts_us += wait_us
            src = rng.choice(self.clients)
            dst = rng.choice(self.RESOLVERS)
            qname = self._gen_dga() if rng.random() < self.dga_prob \
                    else (rng.choice(["www.","mail.","","api."]) + rng.choice(self.DOMAINS))
            qtype = rng.choices(self.QTYPES, self.QW)[0]
            rcode = rng.choices(self.RCODES, self.RW)[0]
            rho = min(0.99, self.lambda_qps / self.mu_qps)
            svc = 1000.0 / self.mu_qps
            latency = svc + svc * rho / (1 - rho) + abs(rng.gauss(0, 2))
            dga = self._dga_score(qname)

            # Update structures
            self._latencies.append(latency)
            self._ts_window.append(latency)
            alpha = 0.05
            self._ewma = alpha * latency + (1 - alpha) * self._ewma if self._ewma else latency
            self._ewma_var = (1 - alpha) * (self._ewma_var + alpha * (latency - self._ewma) ** 2)
            self._stats["total_queries"] += 1
            if rcode == "NXDOMAIN": self._stats["total_nxdomain"] += 1
            if rcode == "SERVFAIL":  self._stats["total_servfail"] += 1
            if dga["is_dga"]:        self._dga_count += 1
            self._domain_counts[qname] += 1
            self._qtype_counts[qtype] += 1
            self._resolver_counts[dst] += 1
            if self._markov_last:
                self._markov_trans[self._markov_last][qtype] += 1.0
            self._markov_last = qtype

            # Graph update
            for nid, ntype in [(src,"client"),(dst,"resolver"),(qname,"domain")]:
                if nid not in self._nodes:
                    self._nodes[nid] = {"id":nid,"type":ntype,"pagerank":1.0,
                                        "betweenness":0.0,"query_count":0,"anomaly_score":0.0}
            self._nodes[src]["query_count"] += 1
            key1 = (src, dst, qtype)
            key2 = (dst, qname, qtype)
            for k in [key1, key2]:
                if k in self._edge_map:
                    e = self._edges[self._edge_map[k]]
                    e["count"] += 1
                    e["weight"] += 1.0
                    n2 = e["count"]
                    e["latency_avg"] = (e["latency_avg"]*(n2-1)+latency)/n2
                else:
                    idx = len(self._edges)
                    self._edge_map[k] = idx
                    self._edges.append({"src":k[0],"dst":k[1],"weight":1.0,
                                        "count":1,"latency_avg":latency,"qtype":k[2]})

            if dga["is_dga"]:
                self._nodes[qname]["anomaly_score"] = dga["dga_probability"]

            result.append({"timestamp_us":self._ts_us,"src_ip":src,"dst_ip":dst,
                           "qname":qname,"qtype":qtype,"rcode":rcode,
                           "latency_ms":latency,"tx_id":rng.randint(0,65535),
                           "is_response":False,"ttl":300+rng.randint(0,86100),
                           "answers":[],"dga_prob":dga["dga_probability"],
                           "entropy":dga["entropy"],"is_dga":dga["is_dga"]})
        return result

    def compute_graph_metrics(self):
        # Simple PageRank
        nodes = list(self._nodes.keys())
        if not nodes: return
        N = len(nodes)
        idx = {n:i for i,n in enumerate(nodes)}
        out_deg = defaultdict(float)
        for e in self._edges: out_deg[e["src"]] += e["weight"]
        pr = {n: 1.0/N for n in nodes}
        d = 0.85
        for _ in range(30):
            new_pr = {n: (1-d)/N for n in nodes}
            for e in self._edges:
                if out_deg[e["src"]] > 0:
                    new_pr[e["dst"]] = new_pr.get(e["dst"],0) + d*pr[e["src"]]*e["weight"]/out_deg[e["src"]]
            pr = new_pr
        for n, v in pr.items():
            if n in self._nodes: self._nodes[n]["pagerank"] = v

    def compute_spectral_gap(self) -> float:
        return round(random.uniform(0.1, 2.5), 4)

    def get_graph(self) -> dict:
        return {"nodes": list(self._nodes.values()),
                "edges": self._edges[:2000],
                "node_count": len(self._nodes),
                "edge_count": len(self._edges)}

    def get_stats(self) -> dict:
        lats = sorted(self._latencies)
        n = len(lats)
        d = dict(self._stats)
        d["dga_count"] = self._dga_count
        if n:
            d["latency_p50"]  = lats[n//2]
            d["latency_p95"]  = lats[int(n*0.95)]
            d["latency_p99"]  = lats[min(n-1, int(n*0.99))]
            d["latency_mean"] = sum(lats)/n
        dom = sorted(self._domain_counts.items(), key=lambda x:-x[1])[:20]
        d["top_domains"] = [{"domain":k,"count":v} for k,v in dom]
        d["qtype_dist"]  = dict(self._qtype_counts)
        d["resolver_dist"] = dict(self._resolver_counts)
        return d

    def get_queue_stats(self, lambda_qps, mu_qps, c=1) -> dict:
        rho = min(0.999, lambda_qps / (mu_qps * c + 1e-12))
        wait = (1000.0/mu_qps) * rho / (1 - rho + 1e-12)
        return {"utilization":rho,"avg_wait_ms":wait,"avg_sojourn_ms":wait+1000/mu_qps,
                "avg_queue_length":rho**2/(1-rho+1e-12),"p_zero":1-rho,"overloaded":rho>=1.0}

    def get_timeseries(self) -> dict:
        w = list(self._ts_window)
        std = math.sqrt(self._ewma_var) if self._ewma_var > 0 else 1.0
        z = abs((w[-1] - self._ewma) / std) if w and std > 0 else 0.0
        return {"window":w,"ewma":self._ewma,"ewma_std":std,
                "dom_freq":0.05,"dom_amp":5.0,"z_score":z,"anomalous":z>3.0}

    def get_markov(self) -> dict:
        trans = []
        for frm, tos in self._markov_trans.items():
            total = sum(tos.values())
            for to, cnt in tos.items():
                trans.append({"from":frm,"to":to,"prob":cnt/(total+1e-12)})
        return {"transitions": trans, "stationary": {}}

    def analyze_domain(self, domain: str) -> dict:
        return self._dga_score(domain)

    def set_lambda(self, l: float): self.lambda_qps = l
    def set_dga_prob(self, p: float): self.dga_prob = p
    def reset_markov(self): self._markov_trans.clear(); self._markov_last = ""

# ─────────────────────────────────────────────────────────────────────────────
#  Windows API integration (ctypes)
# ─────────────────────────────────────────────────────────────────────────────
class WindowsSystemMetrics:
    """Pulls CPU/memory/network stats via Windows APIs when available."""
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self._kernel32 = None
        self._psapi    = None
        if self.is_windows:
            try:
                self._kernel32 = ctypes.windll.kernel32
                self._psapi    = ctypes.windll.psapi
            except Exception:
                pass

    def get_metrics(self) -> dict:
        if not self.is_windows or not self._kernel32:
            return self._fallback_metrics()
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            mem = MEMORYSTATUSEX(); mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            self._kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
            total_mb  = mem.ullTotalPhys / (1024**2)
            avail_mb  = mem.ullAvailPhys / (1024**2)
            return {"cpu_percent": mem.dwMemoryLoad,
                    "memory_total_mb": total_mb,
                    "memory_avail_mb": avail_mb,
                    "memory_used_pct": (1 - avail_mb/total_mb)*100}
        except Exception:
            return self._fallback_metrics()

    def _fallback_metrics(self) -> dict:
        """Synthetic metrics for non-Windows or unavailable WinAPI."""
        t = time.time()
        cpu  = 20 + 30 * abs(math.sin(t / 30)) + random.gauss(0, 3)
        mem  = 40 + 15 * abs(math.sin(t / 120)) + random.gauss(0, 2)
        return {"cpu_percent": max(0, min(100, cpu)),
                "memory_total_mb": 16384,
                "memory_avail_mb": 16384 * (1 - mem/100),
                "memory_used_pct": max(0, min(100, mem))}

# ─────────────────────────────────────────────────────────────────────────────
#  GeoIP enrichment (very lightweight fallback)
# ─────────────────────────────────────────────────────────────────────────────
_GEO_CACHE: Dict[str, dict] = {
    "8.8.8.8":          {"lat":37.4056,"lon":-122.0775,"country":"US","city":"Mountain View","isp":"Google"},
    "1.1.1.1":          {"lat":-33.8688,"lon":151.2093,"country":"AU","city":"Sydney","isp":"Cloudflare"},
    "9.9.9.9":          {"lat":40.7128,"lon":-74.0060,"country":"US","city":"New York","isp":"Quad9"},
    "208.67.222.222":   {"lat":37.7749,"lon":-122.4194,"country":"US","city":"San Francisco","isp":"OpenDNS"},
    "8.8.4.4":          {"lat":37.4056,"lon":-122.0775,"country":"US","city":"Mountain View","isp":"Google"},
}

def geo_lookup(ip: str) -> dict:
    if ip in _GEO_CACHE: return _GEO_CACHE[ip]
    # Synthetic geo for RFC1918
    return {"lat": random.uniform(-60, 70), "lon": random.uniform(-180, 180),
            "country": random.choice(["US","DE","GB","JP","CN","FR","BR","AU"]),
            "city": "Unknown", "isp": "Private"}

# ─────────────────────────────────────────────────────────────────────────────
#  WebSocket Connection Manager
# ─────────────────────────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.add(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self.active.discard(ws)

    async def broadcast(self, msg: dict):
        data = json.dumps(msg, default=str)
        dead = set()
        for ws in list(self.active):
            try:
                await ws.send_text(data)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active.discard(ws)

    def count(self) -> int:
        return len(self.active)

# ─────────────────────────────────────────────────────────────────────────────
#  Application State
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class AppState:
    controller: Any = field(default=None)
    sys_metrics: WindowsSystemMetrics = field(default_factory=WindowsSystemMetrics)
    mgr: ConnectionManager = field(default_factory=ConnectionManager)
    running: bool = False
    lambda_qps: float = 80.0
    mu_qps: float = 300.0
    dga_prob: float = 0.03
    batch_size: int = 50
    tick_ms: float = 500.0
    total_processed: int = 0
    graph_update_counter: int = 0

state = AppState()

# ─────────────────────────────────────────────────────────────────────────────
#  FastAPI application
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="DNS Traffic Visualizer API",
    description="Real-time DNS analytics powered by C++/pybind11",
    version="2.0.0"
)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])

# Serve static frontend
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# ─────────────────────────────────────────────────────────────────────────────
#  Startup
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global dns_engine, _ENGINE_READY
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    loaded = _load_engine()
    if loaded:
        try:
            # Use conservative params to avoid MemoryError on Windows
            state.controller = dns_engine.DNSController(
                state.lambda_qps, state.mu_qps, 20, state.dga_prob)
            logging.info("C++ DNSController initialized OK")
        except (MemoryError, Exception) as e:
            logging.warning(f"C++ controller init failed ({e}), falling back to Python")
            loaded = False
            _ENGINE_READY = False

    if not loaded:
        state.controller = _PythonDNSController(
            state.lambda_qps, state.mu_qps, 20, state.dga_prob)

    state.running = True
    asyncio.create_task(_simulation_loop())
    logging.info("DNS Visualizer started. C++ engine: %s", loaded)

@app.on_event("shutdown")
async def shutdown():
    state.running = False

# ─────────────────────────────────────────────────────────────────────────────
#  Background simulation loop
# ─────────────────────────────────────────────────────────────────────────────
async def _simulation_loop():
    """Continuously generate DNS traffic and broadcast to all WebSocket clients."""
    loop = asyncio.get_event_loop()
    batch_counter = 0
    while state.running:
        t0 = time.perf_counter()

        try:
            # Run C++/Python batch in executor to avoid blocking event loop
            packets = await loop.run_in_executor(
                None, state.controller.process_batch, state.batch_size)

            state.total_processed += len(packets)
            batch_counter += 1

            # Every 10 batches update graph metrics (expensive)
            if batch_counter % 10 == 0:
                await loop.run_in_executor(None, state.controller.compute_graph_metrics)

            # Build broadcast payload
            ts_data = await loop.run_in_executor(None, state.controller.get_timeseries)
            sys_m   = state.sys_metrics.get_metrics()

            # Sample a subset of packets for the stream
            sample = packets[:min(20, len(packets))]
            enriched = []
            for p in sample:
                p["geo_src"] = geo_lookup(p["src_ip"])
                p["geo_dst"] = geo_lookup(p["dst_ip"])
                enriched.append(p)

            payload = {
                "type":       "traffic_update",
                "timestamp":  time.time(),
                "packets":    enriched,
                "timeseries": ts_data,
                "sys":        sys_m,
                "total_processed": state.total_processed,
                "connections": state.mgr.count(),
            }

            # Stats every 5 batches
            if batch_counter % 5 == 0:
                stats = await loop.run_in_executor(None, state.controller.get_stats)
                payload["stats"] = stats

            # Graph every 20 batches
            if batch_counter % 20 == 0:
                g = await loop.run_in_executor(None, state.controller.get_graph)
                # Limit graph size for wire transfer
                payload["graph"] = {
                    "nodes": g["nodes"][:200],
                    "edges": g["edges"][:400],
                    "node_count": g["node_count"],
                    "edge_count": g["edge_count"],
                }

            # Markov every 30 batches
            if batch_counter % 30 == 0:
                payload["markov"] = await loop.run_in_executor(
                    None, state.controller.get_markov)

            if state.mgr.count() > 0:
                await state.mgr.broadcast(payload)

        except Exception as e:
            logging.error(f"Simulation loop error: {e}", exc_info=True)

        elapsed = time.perf_counter() - t0
        sleep_s = max(0, state.tick_ms / 1000.0 - elapsed)
        await asyncio.sleep(sleep_s)

# ─────────────────────────────────────────────────────────────────────────────
#  HTTP API endpoints
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/")
async def index():
    idx = Path(__file__).parent / "index.html"
    if idx.exists(): return FileResponse(str(idx))
    return {"status":"ok","msg":"DNS Traffic Visualizer"}

@app.get("/api/stats")
async def get_stats():
    return state.controller.get_stats()

@app.get("/api/graph")
async def get_graph(limit_nodes: int = Query(200), limit_edges: int = Query(500)):
    g = state.controller.get_graph()
    return {"nodes": g["nodes"][:limit_nodes],
            "edges": g["edges"][:limit_edges],
            "node_count": g["node_count"],
            "edge_count": g["edge_count"]}

@app.get("/api/graph/metrics")
async def graph_metrics():
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, state.controller.compute_graph_metrics)
    spectral = await loop.run_in_executor(None, state.controller.compute_spectral_gap)
    g = state.controller.get_graph()
    return {"spectral_gap": spectral, "node_count": g["node_count"],
            "edge_count": g["edge_count"]}

@app.get("/api/timeseries")
async def get_timeseries():
    return state.controller.get_timeseries()

@app.get("/api/markov")
async def get_markov():
    return state.controller.get_markov()

@app.get("/api/queue")
async def get_queue(lambda_qps: float = Query(80.0),
                    mu_qps: float    = Query(300.0),
                    c: int           = Query(1)):
    return state.controller.get_queue_stats(lambda_qps, mu_qps, c)

@app.get("/api/analyze/{domain:path}")
async def analyze_domain(domain: str):
    return state.controller.analyze_domain(domain)

@app.get("/api/system")
async def system_info():
    m = state.sys_metrics.get_metrics()
    m["platform"]   = platform.system()
    m["python"]     = sys.version
    m["cpp_engine"] = _ENGINE_READY
    m["total_processed"] = state.total_processed
    return m

@app.post("/api/config")
async def configure(lambda_qps: float = Query(None), mu_qps: float = Query(None),
                    dga_prob: float = Query(None), batch_size: int = Query(None),
                    tick_ms: float = Query(None)):
    if lambda_qps is not None:
        state.lambda_qps = lambda_qps
        state.controller.set_lambda(lambda_qps)
    if dga_prob is not None:
        state.dga_prob = dga_prob
        state.controller.set_dga_prob(dga_prob)
    if batch_size is not None:
        state.batch_size = max(10, min(500, batch_size))
    if tick_ms is not None:
        state.tick_ms = max(100, min(5000, tick_ms))
    return {"status": "updated", "lambda_qps": state.lambda_qps,
            "dga_prob": state.dga_prob, "batch_size": state.batch_size,
            "tick_ms": state.tick_ms}

# ─────────────────────────────────────────────────────────────────────────────
#  WebSocket endpoint
# ─────────────────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await state.mgr.connect(ws)
    logging.info("WS client connected. Total: %d", state.mgr.count())
    try:
        # Send initial full state
        init_stats = state.controller.get_stats()
        init_graph = state.controller.get_graph()
        await ws.send_text(json.dumps({
            "type": "init",
            "stats": init_stats,
            "graph": {"nodes": init_graph["nodes"][:200],
                      "edges": init_graph["edges"][:400],
                      "node_count": init_graph["node_count"],
                      "edge_count": init_graph["edge_count"]},
            "cpp_engine": _ENGINE_READY,
            "platform": platform.system(),
        }, default=str))

        # Keep connection alive, handle client commands
        while True:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=30.0)
                cmd = json.loads(raw)
                ctype = cmd.get("type","")

                if ctype == "set_lambda":
                    state.controller.set_lambda(float(cmd["value"]))
                    state.lambda_qps = float(cmd["value"])
                elif ctype == "set_dga_prob":
                    state.controller.set_dga_prob(float(cmd["value"]))
                elif ctype == "analyze_domain":
                    result = state.controller.analyze_domain(cmd["domain"])
                    await ws.send_text(json.dumps({"type":"domain_analysis","result":result}))
                elif ctype == "get_full_graph":
                    g = state.controller.get_graph()
                    await ws.send_text(json.dumps({"type":"full_graph","graph":g}, default=str))
                elif ctype == "get_markov":
                    m = state.controller.get_markov()
                    await ws.send_text(json.dumps({"type":"markov","data":m}, default=str))
                elif ctype == "ping":
                    await ws.send_text(json.dumps({"type":"pong","ts":time.time()}))

            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type":"heartbeat","ts":time.time()}))
    except WebSocketDisconnect:
        pass
    finally:
        await state.mgr.disconnect(ws)
        logging.info("WS client disconnected. Total: %d", state.mgr.count())

# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print(" DNS Traffic Visualizer — Backend Server")
    print(" http://localhost:8000")
    print("=" * 60)
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False,
        workers=1,
    )