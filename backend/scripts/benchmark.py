"""Measure ingest throughput: python scripts/benchmark.py 100000  (uses DATABASE_URL)"""
import sys, time
sys.path.insert(0, ".")
from app import pipeline
from app.db import SessionLocal, init_db
from app.simulator import Simulator

n_target = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
init_db(); pipeline.get_detector()
sim, done, t0 = Simulator(100, p_anomaly=0.002, seed=1), 0, time.time()
with SessionLocal() as db:
    while done < n_target:
        done += pipeline.process_batch(db, sim.tick())["processed"]
dt = time.time() - t0
print(f"{done:,} events in {dt:.1f}s = {done/dt:,.0f} events/s  (~{done/dt*86400/1e6:,.1f}M events/day)")
