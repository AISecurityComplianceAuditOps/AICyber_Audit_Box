import requests, json

API_BASE = 'http://127.0.0.1:8000/api'
res = requests.post(f'{API_BASE}/auth/login', json={'username': 'admin', 'password': 'password123'})
if res.status_code != 200:
    res = requests.post(f'{API_BASE}/auth/login', json={'username': 'admin', 'password': 'admin123'})

token = res.json().get('access_token')
headers = {'Authorization': f'Bearer {token}'}

session_id = 'test_session_123'

res = requests.get(f'{API_BASE}/mcp/servers', headers=headers)
servers = res.json()
if type(servers) is list and len(servers) > 0:
    server_id = servers[0]['id']
else:
    res = requests.post(f'{API_BASE}/mcp/servers', json={
        'name': 'TestGithub11',
        'server_type': 'github',
        'command': 'npx',
        'args': '["-y", "@modelcontextprotocol/server-github"]',
        'env': '{}'
    }, headers=headers)
    server_id = res.json()['id']

repo_path = 'https://github.com/Ajaymuralidhar/Test.git'
file_path = 'https://github.com/Ajaymuralidhar/Test/blob/main/43_PAM_Pim-Idam%20for%20Aadhar.pdf'

payload = {
    'session_id': session_id,
    'repo_or_path': repo_path,
    'file_path': file_path
}
print(f"Calling import with server {server_id}...")
res = requests.post(f'{API_BASE}/mcp/{server_id}/import', json=payload, headers=headers)
print('STATUS:', res.status_code)
print('RESPONSE:', res.text)
