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
        
        # Group active servers by company to produce one comprehensive inventory file per company
        servers_by_company = {}
        for s in servers:
            comp = s.company_name or "Global"
            servers_by_company.setdefault(comp, []).append(s)
            
        for comp, company_servers in servers_by_company.items():
            print(f"[Orchestrator] Sweeping assets for company '{comp}' ({len(company_servers)} active server(s))...")
            all_company_records = []
            all_company_columns = set()
            
            for config in company_servers:
                print(f"[Orchestrator] Processing server: {config.name} ({config.server_type})")
                mcp = get_mcp_manager_for_config(config)
                server_category = config.asset_category or config.server_type
                
                try:
                    await mcp.connect()
                    server_records = []
                    
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
                                                row['_query'] = sql
                                                server_records.append(row)
                                    except Exception:
                                        pass

                    elif config.server_type.lower() == 'azure':
                        tools = [
                            ("group", {"command": "list"}),
                            ("vm", {"command": "list"}),
                            ("network", {"command": "nsg list"}),
                            ("network", {"command": "vnet list"}),
                            ("network", {"command": "public-ip list"}),
                            ("storage", {"command": "accounts list"}),
                            ("sql", {"command": "servers list"}),
                            ("role", {"command": "list-assignments"}),
                            ("keyvault", {"command": "vaults list"}),
                            ("resourcehealth", {"command": "list-events"})
                        ]
                        for tool_name, args in tools:
                            try:
                                result = await mcp.call_tool(tool_name, args)
                                if not hasattr(result, 'isError') or not result.isError:
                                    if hasattr(result, 'content') and result.content:
                                        raw_text = result.content[0].text if hasattr(result.content[0], 'text') else str(result.content[0])
                                        try:
                                            data = json.loads(raw_text)
                                            items = []
                                            if isinstance(data, list):
                                                items = data
                                            elif isinstance(data, dict):
                                                if "value" in data and isinstance(data["value"], list):
                                                    items = data["value"]
                                                elif "resources" in data and isinstance(data["resources"], list):
                                                    items = data["resources"]
                                                elif "items" in data and isinstance(data["items"], list):
                                                    items = data["items"]
                                                else:
                                                    items = [data]
                                            
                                            for item in items:
                                                if isinstance(item, dict):
                                                    row = {"_tool": tool_name}
                                                    for k, v in item.items():
                                                        if isinstance(v, (str, int, float, bool)) or v is None:
                                                            row[k] = v
                                                        elif isinstance(v, dict):
                                                            for sub_k, sub_v in v.items():
                                                                if isinstance(sub_v, (str, int, float, bool)) or sub_v is None:
                                                                    row[f"{k}_{sub_k}"] = sub_v
                                                                else:
                                                                    row[f"{k}_{sub_k}"] = json.dumps(sub_v)
                                                        elif isinstance(v, list):
                                                            row[k] = json.dumps(v)
                                                    server_records.append(row)
                                        except Exception:
                                            pass
                            except Exception as tool_e:
                                print(f"[Orchestrator] Azure tool {tool_name} error: {tool_e}")

                    elif config.server_type.lower() == 'github':
                        env_dict = {}
                        if config.env:
                            try:
                                env_dict = json.loads(config.env)
                            except:
                                pass
                        
                        raw_owner = str(env_dict.get("GITHUB_OWNER", "")).strip()
                        raw_repo = str(env_dict.get("GITHUB_REPO", "")).strip()
                        full_target = f"{raw_owner}/{raw_repo}".strip("/").replace("https://", "").replace("http://", "").replace("github.com/", "").replace("www.github.com/", "").strip("/")
                        parts = [p for p in full_target.split("/") if p]
                        
                        if len(parts) >= 2:
                            owner, repo = parts[0], parts[1]
                        elif len(parts) == 1:
                            owner, repo = parts[0], "Hello-World"
                        else:
                            owner, repo = "octocat", "Hello-World"
                        
                        result = await mcp.call_tool("get_file_contents", {"owner": owner, "repo": repo, "path": ""})
                        if not hasattr(result, 'isError') or not result.isError:
                            if hasattr(result, 'content') and result.content:
                                try:
                                    data = json.loads(result.content[0].text)
                                    if isinstance(data, list):
                                        for item in data:
                                            if item.get("type") == "file":
                                                if mode == "general" or is_pqc_file(item.get("name", "")):
                                                    server_records.append(item)
                                except:
                                    pass

                    elif config.server_type.lower() == 'jira':
                        try:
                            result = await mcp.call_tool("jira_search", {"jql": "ORDER BY created DESC", "maxResults": 50})
                            if not hasattr(result, 'isError') or not result.isError:
                                if hasattr(result, 'content') and result.content:
                                    data = json.loads(result.content[0].text)
                                    issues = data.get("issues", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                                    for issue in issues:
                                        if isinstance(issue, dict):
                                            fields = issue.get("fields", {})
                                            server_records.append({
                                                "issue_key": issue.get("key"),
                                                "summary": fields.get("summary"),
                                                "status": fields.get("status", {}).get("name") if isinstance(fields.get("status"), dict) else str(fields.get("status")),
                                                "assignee": fields.get("assignee", {}).get("displayName") if isinstance(fields.get("assignee"), dict) else str(fields.get("assignee")),
                                                "created": fields.get("created"),
                                                "updated": fields.get("updated")
                                            })
                        except Exception as jira_e:
                            print(f"[Orchestrator] Jira scan error: {jira_e}")

                    # Standardize each record with Asset identification tags
                    for rec in server_records:
                        standardized_rec = {
                            "Asset_Name": config.name,
                            "Asset_Type": config.server_type.upper(),
                            "Asset_Category": server_category,
                            **rec
                        }
                        all_company_records.append(standardized_rec)
                        all_company_columns.update(standardized_rec.keys())

                    print(f"[Orchestrator] Harvested {len(server_records)} asset records from {config.name}")

                except Exception as e:
                    print(f"[Orchestrator] Failed to scan server {config.name}: {str(e)}")
                finally:
                    await mcp.close()

            # Generate ONE unified comprehensive CSV snapshot for this company sweep
            if all_company_records:
                priority_cols = ["Asset_Name", "Asset_Type", "Asset_Category"]
                other_cols = [c for c in sorted(all_company_columns) if c not in priority_cols]
                ordered_columns = priority_cols + other_cols
                
                file_path = generate_csv_and_check_delta(
                    company_name=comp,
                    asset_category="Comprehensive_Inventory",
                    new_data=all_company_records,
                    columns=ordered_columns,
                    mcp_server_id=None
                )
                print(f"[Orchestrator] Saved Comprehensive Inventory for '{comp}' ({len(all_company_records)} total assets): {file_path}")
            else:
                print(f"[Orchestrator] No assets harvested for company '{comp}'")
                    
    finally:
        db.close()
    
    print("[Orchestrator] Automated sweep completed.")

if __name__ == "__main__":
    asyncio.run(run_orchestrator_sweep())
