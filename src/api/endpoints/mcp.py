from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
import json
import asyncio

from src.db.database import SessionLocal, MCPServerConfig
from src.core.crypto_utils import encrypt_credential
from src.core.mcp_client import get_mcp_manager_for_config
from src.api.endpoints.auth import _require_auth
from src.core.orchestrator import run_orchestrator_sweep
from src.core.pqc_filter import is_pqc_file

router = APIRouter(prefix="/mcp", tags=["mcp"])

class OrchestratorTriggerRequest(BaseModel):
    company_name: Optional[str] = None
    mode: Optional[str] = "general"

@router.post("/orchestrator/trigger")
async def trigger_orchestrator(payload: OrchestratorTriggerRequest, request: Request):
    """Manually triggers the daily asset sweep for testing."""
    _require_auth(request)
    # Fire and forget the sweep so we don't block the HTTP response
    asyncio.create_task(run_orchestrator_sweep(company_name=payload.company_name, mode=payload.mode))
    return {"status": "success", "message": f"Orchestrator sweep triggered for {payload.company_name or 'Global'} in {payload.mode} mode."}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class MCPConfigCreate(BaseModel):
    name: str
    server_type: str
    company_name: Optional[str] = None
    asset_category: Optional[str] = None
    command: str
    args: str
    env: str
    credentials: Optional[str] = None

class MCPConfigResponse(BaseModel):
    id: int
    name: str
    server_type: str
    company_name: Optional[str] = None
    asset_category: Optional[str] = None
    command: str
    args: str
    env: str
    has_credentials: bool
    is_active: bool

@router.get("/servers", response_model=List[MCPConfigResponse])
def list_servers(request: Request, db: Session = Depends(get_db)):
    auth_user = _require_auth(request)
    configs = db.query(MCPServerConfig).filter(MCPServerConfig.is_active == True).all()
    return [
        MCPConfigResponse(
            id=c.id,
            name=c.name,
            server_type=c.server_type,
            company_name=c.company_name,
            asset_category=c.asset_category,
            command=c.command or "",
            args=c.args or "[]",
            env=c.env or "{}",
            has_credentials=bool(c.encrypted_credentials),
            is_active=c.is_active
        ) for c in configs
    ]

@router.post("/servers", response_model=MCPConfigResponse)
def create_server(config: MCPConfigCreate, request: Request, db: Session = Depends(get_db)):
    auth_user = _require_auth(request)
    
    existing = db.query(MCPServerConfig).filter(MCPServerConfig.name == config.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Server config with this name already exists")
    
    new_config = MCPServerConfig(
        name=config.name,
        server_type=config.server_type,
        company_name=config.company_name,
        asset_category=config.asset_category,
        command=config.command,
        args=config.args,
        env=config.env,
        encrypted_credentials=encrypt_credential(config.credentials) if config.credentials else None
    )
    db.add(new_config)
    db.commit()
    db.refresh(new_config)
    
    return MCPConfigResponse(
        id=new_config.id,
        name=new_config.name,
        server_type=new_config.server_type,
        company_name=new_config.company_name,
        asset_category=new_config.asset_category,
        command=new_config.command or "",
        args=new_config.args or "[]",
        env=new_config.env or "{}",
        has_credentials=bool(new_config.encrypted_credentials),
        is_active=new_config.is_active
    )

@router.delete("/servers/{server_id}")
def delete_server(server_id: int, request: Request, db: Session = Depends(get_db)):
    auth_user = _require_auth(request)
    config = db.query(MCPServerConfig).filter(MCPServerConfig.id == server_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Server not found")
    
    db.delete(config)
    db.commit()
    return {"status": "success", "message": "Server deleted successfully"}

@router.post("/{server_id}/test")
async def test_server_connection(server_id: int, request: Request, db: Session = Depends(get_db)):
    auth_user = _require_auth(request)
    config = db.query(MCPServerConfig).filter(MCPServerConfig.id == server_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Server config not found")
        
    mcp = get_mcp_manager_for_config(config)
    try:
        await mcp.connect()
        return {"status": "success", "message": "Connected to MCP server successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection failed: {str(e)}")
    finally:
        await mcp.close()

class ImportRequest(BaseModel):
    session_id: str
    repo_or_path: str
    file_path: str
    import_mode: str = "general"

@router.post("/{server_id}/import")
async def import_file(server_id: int, req: ImportRequest, request: Request, db: Session = Depends(get_db)):
    auth_user = _require_auth(request)
    config = db.query(MCPServerConfig).filter(MCPServerConfig.id == server_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Server config not found")
        
    mcp = get_mcp_manager_for_config(config)
    
    from src.db.database import EvidenceFile, force_master
    from src.api.endpoints.audit import get_or_create_audit_report
    from src.core.crypto_utils import decrypt_credential
    from src.api.endpoints.audit import _bg_extract_and_chunk
    import urllib.parse
    import json, base64, requests
    import os, time, random, threading
    
    pat = decrypt_credential(config.encrypted_credentials) if config.encrypted_credentials else None
    headers = {"Authorization": f"token {pat}"} if pat else {}
    
    fetched_files = []
    
    try:
        await mcp.connect()
        if config.server_type.lower() == 'github':
            env_dict = {}
            if config.env:
                try:
                    env_dict = json.loads(config.env)
                except:
                    pass
            owner = env_dict.get("GITHUB_OWNER", "octocat")
            repo = env_dict.get("GITHUB_REPO", "Hello-World")
            
            # Sanitize File Path
            f_path = req.file_path.strip()
            f_path = urllib.parse.unquote(f_path)
            if "blob/main/" in f_path:
                f_path = f_path.split("blob/main/")[-1]
            elif "blob/master/" in f_path:
                f_path = f_path.split("blob/master/")[-1]
            elif "tree/main/" in f_path:
                f_path = f_path.split("tree/main/")[-1]
            elif "tree/master/" in f_path:
                f_path = f_path.split("tree/master/")[-1]
            # The lists of PQC keywords, extensions, and the is_pqc_file function 
            # have been moved to src.core.pqc_filter to prevent circular dependencies.
            
            MAX_FILES = 50
            items_to_fetch = [f_path]
            
            while items_to_fetch and len(fetched_files) < MAX_FILES:
                current_path = items_to_fetch.pop(0)
                args = {"owner": owner, "repo": repo, "path": current_path}
                
                result = await mcp.call_tool("get_file_contents", args)
                if hasattr(result, 'isError') and result.isError:
                    err_msg = str(result.content) if hasattr(result, 'content') else "Unknown tool error"
                    raise HTTPException(status_code=400, detail=f"GitHub API Error: {err_msg}")
                    
                if hasattr(result, 'content') and len(result.content) > 0 and hasattr(result.content[0], 'text'):
                    try:
                        data = json.loads(result.content[0].text)
                        if isinstance(data, list):
                            # It's a directory
                            for item in data:
                                if item.get("type") == "file":
                                    if req.import_mode == "pqc" and not is_pqc_file(item.get("name", "")):
                                        continue
                                    if len(fetched_files) + len([p for p in items_to_fetch if p]) < MAX_FILES:
                                        fetched_files.append(item)
                                elif item.get("type") == "dir":
                                    items_to_fetch.append(item.get("path"))
                        else:
                            # Single file
                            if req.import_mode == "pqc" and not is_pqc_file(data.get("name", "")):
                                pass
                            else:
                                fetched_files.append(data)
                    except json.JSONDecodeError:
                        raise HTTPException(status_code=500, detail="Failed to parse GitHub MCP response.")
        elif config.server_type.lower() == 'jira':
            issue_key = req.file_path.strip()
            if not issue_key:
                raise HTTPException(status_code=400, detail="Issue key is required for Jira imports")
                
            args = {"action": "get", "issueKey": issue_key}
            result = await mcp.call_tool("jira_issues", args)
            
            if hasattr(result, 'isError') and result.isError:
                err_msg = str(result.content) if hasattr(result, 'content') else "Unknown tool error"
                raise HTTPException(status_code=400, detail=f"Jira API Error: {err_msg}")
                
            if hasattr(result, 'content') and len(result.content) > 0 and hasattr(result.content[0], 'text'):
                try:
                    data = json.loads(result.content[0].text)
                    fields = data.get("fields", {})
                    summary = fields.get("summary", "No Summary")
                    status = fields.get("status", {}).get("name", "Unknown")
                    
                    assignee_obj = fields.get("assignee")
                    assignee = assignee_obj.get("displayName", "Unassigned") if assignee_obj else "Unassigned"
                    
                    desc = fields.get("description", "No description provided.")
                    if isinstance(desc, dict):
                        desc = json.dumps(desc, indent=2)
                        
                    md = f"# {issue_key}: {summary}\n\n"
                    md += f"**Status:** {status}\n"
                    md += f"**Assignee:** {assignee}\n\n"
                    md += f"## Description\n{desc}\n\n"
                    
                    comments = fields.get("comment", {}).get("comments", [])
                    if comments:
                        md += "## Comments\n"
                        for c in comments:
                            author = c.get("author", {}).get("displayName", "Unknown")
                            body = c.get("body", "")
                            if isinstance(body, dict):
                                body = json.dumps(body)
                            md += f"**{author}:**\n{body}\n\n"
                            
                    subtasks = fields.get("subtasks", [])
                    if subtasks:
                        md += "## Subtasks\n"
                        for st in subtasks:
                            st_key = st.get("key")
                            st_sum = st.get("fields", {}).get("summary", "")
                            st_stat = st.get("fields", {}).get("status", {}).get("name", "")
                            md += f"- **{st_key}**: {st_sum} ({st_stat})\n"
                        md += "\n"
                            
                    links = fields.get("issuelinks", [])
                    if links:
                        md += "## Linked Issues\n"
                        for link in links:
                            type_name = link.get("type", {}).get("name", "Links to")
                            inward = link.get("inwardIssue")
                            outward = link.get("outwardIssue")
                            if inward:
                                md += f"- **{type_name}**: {inward.get('key')} - {inward.get('fields', {}).get('summary', '')}\n"
                            if outward:
                                md += f"- **{type_name}**: {outward.get('key')} - {outward.get('fields', {}).get('summary', '')}\n"
                                
                    fetched_files.append({
                        "name": f"{issue_key}.md",
                        "content": md
                    })
                except json.JSONDecodeError:
                    # Fallback if the MCP server returned raw text/markdown instead of JSON
                    fetched_files.append({
                        "name": f"{issue_key}.md",
                        "content": result.content[0].text
                    })
        elif config.server_type.lower() == 'postgres':
            queries = []
            custom_sql = req.file_path.strip()
            
            if req.import_mode == "pqc":
                if custom_sql:
                    queries.append(("Custom PQC Query", custom_sql))
                else:
                    queries.append(("SSL Configuration", "SHOW ssl;"))
                    queries.append(("SSL Ciphers", "SHOW ssl_ciphers;"))
                    queries.append(("Active SSL Connections", "SELECT datname, pg_stat_activity.pid, usename, ssl, version, cipher, bits FROM pg_stat_ssl JOIN pg_stat_activity ON pg_stat_ssl.pid = pg_stat_activity.pid;"))
                    queries.append(("Client Authentication Rules (pg_hba)", "SELECT line_number, type, database, user_name, address, netmask, auth_method FROM pg_hba_file_rules;"))
                    queries.append(("Password Encryption Standard", "SHOW password_encryption;"))
                    queries.append(("Role & Privilege Matrix", "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles;"))
                    queries.append(("Statement Logging Settings", "SHOW log_statement;"))
                    queries.append(("Connection Logging Settings", "SHOW log_connections;"))
            else:
                if custom_sql:
                    queries.append(("Custom SQL Query", custom_sql))
                else:
                    queries.append(("Active Connections (Top 50)", "SELECT datname, pid, usename, state, query FROM pg_stat_activity LIMIT 50;"))
                    
            md = f"# PostgreSQL Server Diagnostic Report\n\n**Mode:** {req.import_mode.upper()}\n\n"
            
            for title, sql in queries:
                md += f"## {title}\n"
                md += f"`{sql}`\n\n"
                
                args = {"sql": sql}
                try:
                    result = await mcp.call_tool("query", args)
                    
                    if hasattr(result, 'isError') and result.isError:
                        err_msg = str(result.content) if hasattr(result, 'content') else "Unknown error"
                        md += f"**Error executing query:** {err_msg}\n\n"
                        continue
                        
                    if hasattr(result, 'content') and len(result.content) > 0 and hasattr(result.content[0], 'text'):
                        try:
                            data = json.loads(result.content[0].text)
                            if isinstance(data, list) and len(data) > 0:
                                headers = list(data[0].keys())
                                md += "| " + " | ".join(headers) + " |\n"
                                md += "| " + " | ".join(["---"] * len(headers)) + " |\n"
                                for row in data:
                                    md += "| " + " | ".join([str(row.get(h, "")).replace('\n', ' ') for h in headers]) + " |\n"
                                md += "\n"
                            elif isinstance(data, list) and len(data) == 0:
                                md += "*No results returned.*\n\n"
                            else:
                                md += f"```json\n{json.dumps(data, indent=2)}\n```\n\n"
                        except json.JSONDecodeError:
                            md += f"```\n{result.content[0].text}\n```\n\n"
                    else:
                        md += "*No content returned.*\n\n"
                except Exception as e:
                    md += f"**MCP Error:** Failed to execute query. The database might be unreachable or the credentials may be incorrect. Details: {str(e)}\n\n"
                    
            fetched_files.append({
                "name": f"PostgreSQL_{req.import_mode.upper()}_Report.md",
                "content": md
            })
        elif config.server_type.lower() == 'azure':
            md = "# Azure Cloud MCP Report\n\n"
            md += f"**Mode:** {req.import_mode.upper()}\n\n"
            
            queries = []
            if req.import_mode == "general":
                queries.append(("Resource Health Events", "resourcehealth", {"command": "list-events"}))
                queries.append(("Role Assignments", "role", {"command": "list-assignments"}))
            elif req.import_mode == "pqc":
                md += "> **PQC Focus**: Extracting Cryptographic Data (Key Vaults) and Infrastructure Security Configurations (Storage, SQL, RBAC) to satisfy HSM and Network Matrix requirements.\n\n"
                if req.file_path:
                    queries.append((f"Cryptographic Keys in {req.file_path}", "keyvault", {"command": "keyvault_key_get", "parameters": {"vault": req.file_path.strip()}}))
                    queries.append((f"Certificates in {req.file_path}", "keyvault", {"command": "keyvault_certificate_get", "parameters": {"vault": req.file_path.strip()}}))
                else:
                    md += "*(No Vault Name provided. Skipping Key Vault keys extraction).* \n\n"
                
                # Append broader cloud security scans
                queries.append(("Azure SQL Servers (Network & Entra ID Settings)", "sql", {"command": "servers list"}))
                queries.append(("Storage Accounts (HTTPS & TLS Settings)", "storage", {"command": "accounts list"}))
                md += "> Note: The 'role_assignment_list' tool requires a scope (e.g. /subscriptions/<id>). You can provide it in the file path box or run this via General mode.\n\n"
                queries.append(("Role Assignments (RBAC)", "role", {"command": "role_assignment_list"}))
                
            for title, tool_name, args in queries:
                md += f"## {title}\n"
                md += f"`Tool: {tool_name} | Args: {json.dumps(args)}`\n\n"
                try:
                    result = await mcp.call_tool(tool_name, args)
                    if hasattr(result, 'isError') and result.isError:
                        err = str(result.content) if hasattr(result, 'content') else "Error"
                        md += f"**MCP Error:** {err}\n\n"
                        continue
                        
                    if hasattr(result, 'content') and len(result.content) > 0 and hasattr(result.content[0], 'text'):
                        try:
                            data = json.loads(result.content[0].text)
                            if isinstance(data, list) and len(data) == 0:
                                md += "*No results returned.*\n\n"
                            else:
                                md += f"```json\n{json.dumps(data, indent=2)}\n```\n\n"
                        except json.JSONDecodeError:
                            md += f"```\n{result.content[0].text}\n```\n\n"
                    else:
                        md += "*No content returned.*\n\n"
                except Exception as e:
                    md += f"**MCP Exception:** Failed to execute {tool_name}. Check permissions. Details: {str(e)}\n\n"
                    
            fetched_files.append({
                "name": f"AzureCloud_{req.import_mode.upper()}_Report.md",
                "content": md
            })
        else:
            raise HTTPException(status_code=400, detail="Server type not supported for automatic import MVP")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MCP Error: {str(e)}")
    finally:
        await mcp.close()

    if not fetched_files:
        raise HTTPException(status_code=404, detail="No files found to import.")
        
    saved_files = []
    
    try:
        with force_master():
            report = get_or_create_audit_report(db, req.session_id, username=auth_user.get("username"))
            session_dir = os.path.normpath(os.path.join(os.getcwd(), "data", "evidence", str(report.id)))
            os.makedirs(session_dir, exist_ok=True)
            
            for file_data in fetched_files:
                filename = file_data.get("name", file_data.get("path", "unknown").split("/")[-1])
                file_bytes = None
                
                # Fetch actual content bytes
                if file_data.get("download_url"):
                    try:
                        dl_res = requests.get(file_data["download_url"], headers=headers, timeout=10)
                        if dl_res.status_code == 200:
                            file_bytes = dl_res.content
                        else:
                            continue
                    except requests.exceptions.RequestException as e:
                        print(f"raw.githubusercontent.com timed out for {filename}, falling back to MCP get_file_contents...")
                        try:
                            fb_args = {"owner": owner, "repo": repo, "path": file_data.get("path", "")}
                            fb_res = await mcp.call_tool("get_file_contents", fb_args)
                            if hasattr(fb_res, 'content') and len(fb_res.content) > 0 and hasattr(fb_res.content[0], 'text'):
                                fb_data = json.loads(fb_res.content[0].text)
                                if isinstance(fb_data, dict) and "content" in fb_data and fb_data.get("encoding") == "base64":
                                    b64_str = fb_data["content"].replace("\\n", "")
                                    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                                    file_bytes = base64.b64decode(b64_str)
                                else:
                                    continue
                            else:
                                continue
                        except Exception as fb_e:
                            print(f"Fallback failed for {filename}: {fb_e}")
                            continue
                elif file_data.get("encoding") == "base64" and "content" in file_data:
                    b64_str = file_data["content"].replace("\\n", "")
                    b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                    file_bytes = base64.b64decode(b64_str)
                else:
                    file_bytes = str(file_data.get("content", "")).encode("utf-8")
                    
                if not file_bytes:
                    continue
                    
                safe_name = f"{int(time.time())}_{random.randint(1000,9999)}_{filename}"
                save_path = os.path.join(session_dir, safe_name)
                
                with open(save_path, "wb") as f:
                    f.write(file_bytes)
                    
                evidence = EvidenceFile(
                    report_id=report.id,
                    filename=filename,
                    file_path=save_path,
                    is_auditor_uploaded=True,
                    assigned_auditor_username=auth_user.get("username")
                )
                db.add(evidence)
                db.commit()
                db.refresh(evidence)
                
                saved_files.append({"id": evidence.id, "filename": filename})
                
                threading.Thread(target=_bg_extract_and_chunk, args=(filename, file_bytes, report.id)).start()
                
            return {"status": "success", "count": len(saved_files), "files": saved_files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")
