import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from src.core.orchestrator import run_orchestrator_sweep

scheduler = AsyncIOScheduler()

def start_scheduler():
    # Schedule the orchestrator sweep to run daily at midnight (or configure as needed)
    # scheduler.add_job(run_orchestrator_sweep, 'cron', hour=0, minute=0)
    scheduler.start()
    print("[Scheduler] Automated Asset Sweep is running in ON-DEMAND mode (Cron disabled).")

def stop_scheduler():
    scheduler.shutdown()
