# DNS Traffic Visualizer

Real-time DNS traffic analysis and 3D visualization platform.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  index.html  (Three.js 3D · D3 Force Graph · Chart.js · WebGL) │
│  WebSocket ↔ FastAPI · uvicorn                                  │
│  Python server.py  (asyncio, background simulation loop)        │
│  pybind11 ↔ dns_engine.cpp  (C++17 core engine)                │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|---|---|
| `dns_engine.cpp` | C++ core: all algorithms, packet synthesis, graph engine |
| `server.py` | Python backend: FastAPI, WebSocket, Windows API, fallback sim |
| `index.html` | Frontend: 3D, D3, Charts, Geo map, all UI |
| `requirements.txt` | Python dependencies |

## Theories Implemented

### C++ Engine (dns_engine.cpp)
- **Shannon Information Theory** — DGA domain entropy scoring (H = -Σ p·log₂p)
- **Bayesian Inference** — Multi-feature DGA classification probability
- **Graph Theory** — PageRank (d=0.85, power iteration), Brandes Betweenness Centrality O(VE)
- **Spectral Graph Theory** — Fiedler value (algebraic connectivity) via power iteration on Laplacian
- **Queuing Theory** — M/M/1 and M/M/c DNS resolver pool models (Erlang-C)
- **Markov Chains** — Query type transition matrix + stationary distribution via power iteration
- **Time-Series** — Cooley-Tukey FFT (DIT), EWMA, exponential variance tracking, z-score anomaly
- **Bloom Filter** — FNV-1a + Murmur-inspired dual-hash probabilistic membership
- **Poisson Process** — Inter-arrival times for realistic traffic synthesis (λ exponential)
- **DGA Simulation** — Conficker-variant character distribution with bigram scoring vs English corpus

### Python Server (server.py)
- **Windows API** — `ctypes.windll.kernel32.GlobalMemoryStatusEx` for memory metrics
- **M/M/1 Queuing** — Live utilization ρ = λ/μ, wait time Wq = ρ/(μ(1-ρ))
- **Pure-Python fallback** — Full reimplementation of all algorithms when C++ unavailable

### Frontend (index.html)
- **3D Force Layout** — Spherical node placement, Three.js WebGL renderer
- **D3 Force Simulation** — forceLink, forceManyBody (Barnes-Hut), forceCenter, forceCollide
- **Bézier Geo Animation** — Quadratic Bézier arcs for geo packet animation
- **PageRank Visualization** — Node size/color mapped to centrality
- **Real-time Markov Canvas** — Hand-drawn state-transition diagram with probability weights
- **FFT Anomaly Display** — Z-score threshold (>3σ) highlighted on time-series

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run (auto-builds C++ extension on first start)
python server.py

# 3. Open browser
# http://localhost:8000
```

## UI Keyboard Shortcuts

| Key | Action |
|---|---|
| `1` | 3D Network View |
| `2` | D3 Force Graph |
| `3` | Timeline Charts |
| `4` | Geo Map |
| `Space` | Pause/Resume |

## API Endpoints

```
GET  /api/stats          — Aggregate statistics
GET  /api/graph          — Full graph (nodes + edges)
GET  /api/graph/metrics  — PageRank, betweenness, spectral gap
GET  /api/timeseries     — FFT, EWMA, z-score
GET  /api/markov         — Transition matrix + stationary distribution
GET  /api/queue          — M/M/c queue model results
GET  /api/analyze/{domain} — DGA entropy analysis
GET  /api/system         — System metrics (Windows API / fallback)
POST /api/config         — Update lambda, dga_prob, tick_ms
WS   /ws                 — Real-time bidirectional stream
```

## C++ Build Notes

The server auto-compiles `dns_engine.cpp` on startup via `setuptools`.
If compilation fails, the server falls back to the pure-Python simulation
with identical API surface — no feature loss, just ~10x slower.

### Manual build
```bash
python -c "
from setuptools import setup, Extension
import pybind11
ext = Extension('dns_engine', sources=['dns_engine.cpp'],
    include_dirs=[pybind11.get_include()],
    extra_compile_args=['-O3','-std=c++17'])
setup(name='dns_engine', ext_modules=[ext])
" build_ext --inplace
```
