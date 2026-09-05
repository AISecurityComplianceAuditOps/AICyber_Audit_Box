import asyncio
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    SCHEDULER_AVAILABLE = True
except ImportError:
    AsyncIOScheduler = None
    SCHEDULER_AVAILABLE = False

from src.core.orchestrator import run_orchestrator_sweep

scheduler = AsyncIOScheduler() if SCHEDULER_AVAILABLE else None

def start_scheduler():
    if scheduler:
        scheduler.start()
        print("[Scheduler] Automated Asset Sweep is running in ON-DEMAND mode (Cron disabled).")
    else:
        print("[Scheduler] apscheduler library not installed. Running without background cron scheduler.")

def stop_scheduler():
    if scheduler:
        scheduler.shutdown()
