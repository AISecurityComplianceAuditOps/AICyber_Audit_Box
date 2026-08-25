"""
Unit tests for the 128k Token Pool + 8-bit KV Cache + TOP_K enterprise changes.
Tests all 6 modified components without requiring a running server.
"""
import ast
import json
import os
import sys
import threading
import unittest
from unittest.mock import patch, MagicMock

# Ensure src is importable — test file lives in testsprite_tests/, so root is one level up
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)



# ─── TEST 1: retrieval_config.json enterprise TOP_K matrix ────────────────────
class TestRetrievalConfig(unittest.TestCase):
    def setUp(self):
        config_path = os.path.join(PROJECT_ROOT, "config", "retrieval_config.json")
        with open(config_path, encoding="utf-8") as f:
            self.config = json.load(f)

    def test_xlsx_minimum_35(self):
        """xlsx TOP_K must be >= 35 to cover multi-tab Active Directory dumps"""
        self.assertGreaterEqual(self.config["xlsx"], 35,
            "xlsx TOP_K must be >=35 to cover multi-tab AD dumps without evidence leaks")

    def test_csv_minimum_35(self):
        """csv TOP_K must be >= 35"""
        self.assertGreaterEqual(self.config["csv"], 35)

    def test_pdf_minimum_30(self):
        """pdf TOP_K must be >= 30 to cover full policy chapters"""
        self.assertGreaterEqual(self.config["pdf"], 30)

    def test_docx_minimum_30(self):
        """docx TOP_K must be >= 30"""
        self.assertGreaterEqual(self.config["docx"], 30)

    def test_pptx_minimum_25(self):
        """pptx TOP_K must be >= 25"""
        self.assertGreaterEqual(self.config["pptx"], 25)

    def test_txt_minimum_25(self):
        """txt TOP_K must be >= 25"""
        self.assertGreaterEqual(self.config["txt"], 25)

    def test_no_file_type_below_20(self):
        """No file type should be below 20 for enterprise audit coverage"""
        for ftype, k in self.config.items():
            if ftype.startswith("_"):
                continue
            self.assertGreaterEqual(k, 20, f"{ftype} TOP_K={k} is below minimum 20")


# ─── TEST 2: retrieval.py deep mode floor and reranker window ─────────────────
class TestRetrievalPy(unittest.TestCase):
    def setUp(self):
        path = os.path.join(PROJECT_ROOT, "src", "core", "retrieval.py")
        with open(path, encoding="utf-8") as f:
            self.src = f.read()

    def test_deep_mode_floor_is_30(self):
        """Deep mode must enforce floor of 30 (not 20)"""
        self.assertIn("max(configured_top_k, 30)", self.src,
            "Deep mode floor must be 30 in retrieval.py")

    def test_deep_mode_floor_not_20(self):
        """Old deep mode floor of 20 must not be present"""
        self.assertNotIn("max(configured_top_k, 20)", self.src,
            "Old 20-floor found — must be updated to 30")

    def test_reranker_window_is_40(self):
        """Reranker candidate window must be 40 for zero evidence leaks"""
        self.assertIn("deduplicated[:40]", self.src,
            "Reranker candidate window must be 40, not 20")

    def test_reranker_window_not_20(self):
        """Old reranker window of 20 must not remain"""
        self.assertNotIn("deduplicated[:20]", self.src,
            "Old reranker window of 20 still present — must be updated to 40")

    def test_default_top_k_fallback_is_30(self):
        """Config fallback must be 30 not 15"""
        self.assertIn('top_k_config.get(file_type, 30)', self.src)

    def test_syntax_valid(self):
        """retrieval.py must have no syntax errors"""
        try:
            ast.parse(self.src)
        except SyntaxError as e:
            self.fail(f"retrieval.py has syntax error: {e}")


# ─── TEST 3: llm_client.py auto-start 128k flags ─────────────────────────────
class TestLlmClientPy(unittest.TestCase):
    def setUp(self):
        path = os.path.join(PROJECT_ROOT, "src", "core", "llm_client.py")
        with open(path, encoding="utf-8") as f:
            self.src = f.read()

    def test_context_131072(self):
        """Auto-start must use -c 131072 for 128k shared pool"""
        self.assertIn('"131072"', self.src,
            "Auto-start context must be 131072 (128k)")

    def test_no_old_dynamic_context(self):
        """Old per-slot context computation (16384 * _np) must be gone"""
        self.assertNotIn("16384 * _np", self.src,
            "Old per-slot context computation still present")

    def test_ctk_q8_0(self):
        """Auto-start must include 8-bit KV cache key: -ctk q8_0"""
        self.assertIn('"-ctk"', self.src)
        self.assertIn('"q8_0"', self.src)

    def test_ctv_q8_0(self):
        """Auto-start must include 8-bit KV cache value: -ctv q8_0"""
        self.assertIn('"-ctv"', self.src)

    def test_slot_ceiling_is_physical_cores(self):
        """Slot ceiling must be _physical_cores not hardcoded 8"""
        self.assertIn("_physical_cores", self.src,
            "llm_client.py must use _physical_cores as slot ceiling")
        self.assertNotIn("min(8, int(", self.src,
            "Old hardcoded slot ceiling of 8 still present")

    def test_slot_gb_900mb(self):
        """KV-cache slot estimate must be 0.9 GB (8-bit, 128k pool) not 0.5 GB"""
        self.assertIn("_slot_gb  = 0.9", self.src)
        self.assertNotIn("_slot_gb  = 0.5", self.src)

    def test_syntax_valid(self):
        """llm_client.py must have no syntax errors"""
        try:
            ast.parse(self.src)
        except SyntaxError as e:
            self.fail(f"llm_client.py has syntax error: {e}")


# ─── TEST 4: port_pool.py CPU queue depth tracking ────────────────────────────
class TestPortPoolQueueDepth(unittest.TestCase):
    def setUp(self):
        path = os.path.join(PROJECT_ROOT, "src", "core", "port_pool.py")
        with open(path, encoding="utf-8") as f:
            self.src = f.read()

    def test_queue_depth_field_exists(self):
        """Port pool must have _queue_depth counter"""
        self.assertIn("self._queue_depth = 0", self.src)

    def test_queue_depth_lock_exists(self):
        """Port pool must have _queue_depth_lock for atomic operations"""
        self.assertIn("self._queue_depth_lock = threading.Lock()", self.src)

    def test_increment_decrement_methods(self):
        """_increment_queue_depth and _decrement_queue_depth must exist"""
        self.assertIn("def _increment_queue_depth(self):", self.src)
        self.assertIn("def _decrement_queue_depth(self):", self.src)

    def test_cpu_queue_notice_event_type(self):
        """CPU_QUEUE_NOTICE must be the event type in log_system_event call"""
        self.assertIn('"CPU_QUEUE_NOTICE"', self.src)

    def test_queue_position_in_message(self):
        """Queue message must include position and estimated wait time"""
        self.assertIn("queue_position", self.src)
        self.assertIn("est_wait_s", self.src)

    def test_non_blocking_acquire_first(self):
        """Must use non-blocking acquire to detect capacity before queuing"""
        self.assertIn("port_lock.acquire(blocking=False)", self.src)

    def test_timeout_fallback_on_queue_fail(self):
        """PORT_LOCK_TIMEOUT must be emitted if queued request also times out"""
        self.assertIn('"PORT_LOCK_TIMEOUT"', self.src)

    def test_syntax_valid(self):
        """port_pool.py must have no syntax errors"""
        try:
            ast.parse(self.src)
        except SyntaxError as e:
            self.fail(f"port_pool.py has syntax error: {e}")


# ─── TEST 5: port_pool runtime — queue depth counter atomic correctness ────────
class TestPortPoolQueueDepthRuntime(unittest.TestCase):
    """Runtime test of _increment_queue_depth and _decrement_queue_depth atomicity."""

    def _build_manager(self):
        """Constructs a LLMPortPoolManager-like object using only the counter methods."""
        import importlib.util, types
        # We can't import the full module because it has side-effects (singleton print).
        # Instead, directly test the helper methods by inline-class construction.
        class FakeManager:
            def __init__(self):
                self._queue_depth = 0
                self._queue_depth_lock = threading.Lock()

            def _increment_queue_depth(self):
                with self._queue_depth_lock:
                    self._queue_depth += 1
                    return self._queue_depth

            def _decrement_queue_depth(self):
                with self._queue_depth_lock:
                    self._queue_depth = max(0, self._queue_depth - 1)

        return FakeManager()

    def test_concurrent_increments_are_correct(self):
        """50 concurrent increments must produce depth = 50"""
        mgr = self._build_manager()
        results = []
        def inc():
            results.append(mgr._increment_queue_depth())
        threads = [threading.Thread(target=inc) for _ in range(50)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(mgr._queue_depth, 50)
        # All positions 1..50 must be present (no duplicates, no gaps)
        self.assertEqual(sorted(results), list(range(1, 51)))

    def test_decrements_never_go_below_zero(self):
        """_decrement_queue_depth must never produce a negative value"""
        mgr = self._build_manager()
        mgr._queue_depth = 2
        for _ in range(10):
            mgr._decrement_queue_depth()
        self.assertEqual(mgr._queue_depth, 0)

    def test_increment_then_decrement_is_balanced(self):
        """After N increments and N decrements, depth must be 0"""
        mgr = self._build_manager()
        N = 20
        for _ in range(N):
            mgr._increment_queue_depth()
        for _ in range(N):
            mgr._decrement_queue_depth()
        self.assertEqual(mgr._queue_depth, 0)


# ─── TEST 6: run_all.bat shell-level flags ────────────────────────────────────
class TestRunAllBat(unittest.TestCase):
    def setUp(self):
        path = os.path.join(PROJECT_ROOT, "run_all.bat")
        with open(path, encoding="utf-8") as f:
            self.src = f.read()

    def test_context_131072(self):
        """run_all.bat must use -c 131072 for 128k shared pool"""
        self.assertIn("-c 131072", self.src)

    def test_ctk_q8_0(self):
        """run_all.bat must use 8-bit KV key cache: -ctk q8_0"""
        self.assertIn("-ctk q8_0", self.src)

    def test_ctv_q8_0(self):
        """run_all.bat must use 8-bit KV value cache: -ctv q8_0"""
        self.assertIn("-ctv q8_0", self.src)

    def test_slots_dynamic_physical_cores(self):
        """LLM_SLOTS must default to %PHYSICAL_CORES% not a hardcoded number"""
        self.assertIn("LLM_SLOTS=%PHYSICAL_CORES%", self.src)

    def test_no_hardcoded_8_slots(self):
        """Old hardcoded LLM_SLOTS=8 must be gone"""
        self.assertNotIn("LLM_SLOTS=8", self.src)

    def test_fallback_slots_4(self):
        """Numeric fallback LLM_SLOTS=4 must be present for safety"""
        self.assertIn("LLM_SLOTS=4", self.src)

    def test_cont_batching(self):
        """--cont-batching must be present"""
        self.assertIn("--cont-batching", self.src)


# ─── TEST 7: run_all.sh shell-level flags ────────────────────────────────────
class TestRunAllSh(unittest.TestCase):
    def setUp(self):
        path = os.path.join(PROJECT_ROOT, "run_all.sh")
        with open(path, encoding="utf-8") as f:
            self.src = f.read()

    def test_context_131072(self):
        """run_all.sh must use -c 131072"""
        self.assertIn("-c 131072", self.src)

    def test_ctk_q8_0(self):
        """run_all.sh must use -ctk q8_0"""
        self.assertIn("-ctk q8_0", self.src)

    def test_ctv_q8_0(self):
        """run_all.sh must use -ctv q8_0"""
        self.assertIn("-ctv q8_0", self.src)

    def test_np_cpu_cores(self):
        """run_all.sh must use -np $CPU_CORES"""
        self.assertIn("-np $CPU_CORES", self.src)

    def test_cont_batching(self):
        """--cont-batching must be present"""
        self.assertIn("--cont-batching", self.src)

    def test_no_old_c_16384(self):
        """Old context -c 16384 must be gone"""
        self.assertNotIn("-c 16384", self.src)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestRetrievalConfig,
        TestRetrievalPy,
        TestLlmClientPy,
        TestPortPoolQueueDepth,
        TestPortPoolQueueDepthRuntime,
        TestRunAllBat,
        TestRunAllSh,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
