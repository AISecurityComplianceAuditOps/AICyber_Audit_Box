import asyncio
import json
from src.db.database import SessionLocal, MCPServerConfig
from src.core.mcp_client import get_mcp_manager_for_config
from src.core.inventory_parser import generate_csv_and_check_delta
from src.core.pqc_filter import is_pqc_file

async def run_orchestrator_sweep(company_name: str = None, mode: str = "general"):
    print(f"[Orchestrator] Starting automated enterprise asset sweep... (Company: {company_name or 'ALL'}, Mode: {mode})")
    db = SessionLocal()
    try:
        query = db.query(MCPServerConfig).filter(MCPServerConfig.is_active == True)
        if company_name:
            query = query.filter(MCPServerConfig.company_name == company_name)
            
        servers = query.all()
        
        for config in servers:
            print(f"[Orchestrator] Processing server: {config.name} ({config.server_type})")
            mcp = get_mcp_manager_for_config(config)
            
            company = config.company_name or "Global"
            category = config.asset_category or config.server_type
            
            try:
                await mcp.connect()
                all_records = []
                columns = set()
                
                if config.server_type.lower() == 'postgres':
                    queries = [
                        "SHOW ssl;",
                        "SHOW ssl_ciphers;",
                        "SELECT datname, pg_stat_activity.pid, usename, ssl, version, cipher, bits FROM pg_stat_ssl JOIN pg_stat_activity ON pg_stat_ssl.pid = pg_stat_activity.pid;",
                        "SELECT line_number, type, database, user_name, address, netmask, auth_method FROM pg_hba_file_rules;",
                        "SHOW password_encryption;",
                        "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles;",
                        "SHOW log_statement;",
                        "SHOW log_connections;"
                    ]
                    for sql in queries:
                        result = await mcp.call_tool("query", {"sql": sql})
                        if not hasattr(result, 'isError') or not result.isError:
                            if hasattr(result, 'content') and result.content:
                                try:
                                    data = json.loads(result.content[0].text)
                                    if isinstance(data, list):
                                        for row in data:
                                            row['_query'] = sql  # Tag it
                                            all_records.append(row)
                                            columns.update(row.keys())
                                except:
                                    pass

                elif config.server_type.lower() == 'azure':
                    tools = [
                        ("sql", {"command": "servers list"}),
                        ("storage", {"command": "accounts list"}),
                        ("role", {"command": "role_assignment_list"}),
                        ("keyvault", {"command": "vaults list"})
                    ]
                    for tool_name, args in tools:
                        result = await mcp.call_tool(tool_name, args)
                        if not hasattr(result, 'isError') or not result.isError:
                            if hasattr(result, 'content') and result.content:
                                try:
                                    data = json.loads(result.content[0].text)
                                    if isinstance(data, list):
                                        for row in data:
                                            row['_tool'] = tool_name
                                            all_records.append(row)
                                            columns.update(row.keys())
                                except:
                                    pass

                elif config.server_type.lower() == 'github':
                    # GitHub logic requires walking the tree, but we need an owner/repo.
                    # For automated sweep, if not specified in env, use a fallback to prevent crashes.
                    env_dict = {}
                    if config.env:
                        try:
                            env_dict = json.loads(config.env)
                        except:
                            pass
                    owner = env_dict.get("GITHUB_OWNER", "octocat")
                    repo = env_dict.get("GITHUB_REPO", "Hello-World")
                    
                    result = await mcp.call_tool("get_file_contents", {"owner": owner, "repo": repo, "path": ""})
                    if not hasattr(result, 'isError') or not result.isError:
                        if hasattr(result, 'content') and result.content:
                            try:
                                data = json.loads(result.content[0].text)
                                if isinstance(data, list):
                                    for item in data:
                                        if item.get("type") == "file":
                                            if mode == "general" or is_pqc_file(item.get("name", "")):
                                                all_records.append(item)
                                                columns.update(item.keys())
                            except:
                                pass
                
                if all_records:
                    file_path = generate_csv_and_check_delta(company, category, all_records, list(columns), config.id)
                    print(f"[Orchestrator] Saved inventory for {config.name}: {file_path}")
                else:
                    print(f"[Orchestrator] No parseable inventory data found for {config.name}")
                    
            except Exception as e:
                print(f"[Orchestrator] Failed to scan server {config.name}: {str(e)}")
            finally:
                await mcp.close()
                
    finally:
        db.close()
    
    print("[Orchestrator] Automated sweep completed.")

if __name__ == "__main__":
    asyncio.run(run_orchestrator_sweep())
