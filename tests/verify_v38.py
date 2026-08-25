import sys, os
sys.path.append('.')

print("=" * 60)
print("VERIFICATION SUITE - AICyberAuditBox v3.8")
print("=" * 60)

# 1. get_num_ctx fix
from src.core.bg_worker import get_num_ctx
e4b = get_num_ctx('google_gemma-4-E4B-it-Q4_K_M')
b12 = get_num_ctx('gemma-12b-it')
b3  = get_num_ctx('gemma-3b-it')
print(f"[1] get_num_ctx e4b  = {e4b}   (expected 8192) -> {'PASS' if e4b == 8192 else 'FAIL'}")
print(f"[2] get_num_ctx 12b  = {b12}   (expected 8192) -> {'PASS' if b12 == 8192 else 'FAIL'}")
print(f"[3] get_num_ctx 3b   = {b3}   (expected 4096) -> {'PASS' if b3  == 4096 else 'FAIL'}")

# 2. llm_client.py server config
with open('src/core/llm_client.py', encoding='utf-8', errors='ignore') as f:
    c = f.read()
has_ctx   = '"-c", "32768"' in c
has_np    = '"-np", "8"' in c
has_batch = '"--cont-batching"' in c
print(f"[4] llm_client.py -c 32768  -> {'PASS' if has_ctx else 'FAIL'}")
print(f"[5] llm_client.py -np 8     -> {'PASS' if has_np else 'FAIL'}")
print(f"[6] llm_client.py --cont-batching -> {'PASS' if has_batch else 'FAIL'}")

# 3. audit_chains.py governance fix
with open('src/ai/audit_chains.py', encoding='utf-8', errors='ignore') as f:
    ac = f.read()
gov_ok = 'governance' in ac.lower() and 'documentary evidence' in ac.lower()
print(f"[7] audit_chains.py governance evidence rule -> {'PASS' if gov_ok else 'FAIL'}")

# 4. validator.py injection fix
with open('src/core/validator.py', encoding='utf-8', errors='ignore') as f:
    v = f.read()
inj_ok = '"mark the control as"' not in v
print(f"[8] validator.py injection_keywords fix -> {'PASS' if inj_ok else 'FAIL'}")

# 5. docker-compose.customer.yml
with open('docker-compose.customer.yml', encoding='utf-8', errors='ignore') as f:
    dc = f.read()
dc_ok = 'aicyberauditbox-app:3.8' in dc
print(f"[9] docker-compose.customer.yml app:3.8 -> {'PASS' if dc_ok else 'FAIL'}")

# 6. Tar file
import os
tar_size = os.path.getsize('aicyberauditbox_bundle_v3.8.tar') / (1024**3)
tar_ok = tar_size > 7.0
print(f"[10] aicyberauditbox_bundle_v3.8.tar = {tar_size:.2f} GB -> {'PASS' if tar_ok else 'FAIL'}")

print("=" * 60)
failures = sum([
    e4b != 8192, b12 != 8192, b3 != 4096,
    not has_ctx, not has_np, not has_batch,
    not gov_ok, not inj_ok, not dc_ok, not tar_ok
])
print(f"RESULT: {10 - failures}/10 checks passed {'(ALL GOOD!)' if failures == 0 else f'({failures} FAILED)'}")
print("=" * 60)
