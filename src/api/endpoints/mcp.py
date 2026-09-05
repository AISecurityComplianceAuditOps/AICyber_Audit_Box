from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import json
import asyncio
import os
import glob
import csv

from src.db.database import SessionLocal, MCPServerConfig, AssetInventoryVersion
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

@router.get("/inventory")
def list_inventory_files(request: Request, db: Session = Depends(get_db)):
    """Retrieves all generated MCP Asset Inventory CSV snapshots and Delta versions."""
    auth_user = _require_auth(request)
    inventory_dir = os.path.normpath(os.path.join(os.getcwd(), "data", "inventory"))
    os.makedirs(inventory_dir, exist_ok=True)
    
    db_versions = db.query(AssetInventoryVersion).order_by(AssetInventoryVersion.created_at.desc()).all()
    tracked_paths = set()
    result = []
    
    for v in db_versions:
        norm_path = os.path.normpath(v.file_path) if v.file_path else ""
        if norm_path:
            tracked_paths.add(norm_path)
            tracked_paths.add(os.path.abspath(norm_path))
            tracked_paths.add(os.path.basename(norm_path))
            
        file_exists = os.path.exists(norm_path)
        file_size = os.path.getsize(norm_path) if file_exists else 0
        row_count = 0
        if file_exists:
            try:
                with open(norm_path, 'r', encoding='utf-8', errors='ignore') as f:
                    row_count = max(0, sum(1 for _ in f) - 1)
            except Exception:
                pass
                
        cat_display = v.asset_category.replace("_", " ") if v.asset_category else "Comprehensive Inventory"
        filename = os.path.basename(norm_path) if norm_path else f"inventory_{v.id}.csv"
        
        result.append({
            "id": v.id,
            "filename": filename,
            "company_name": v.company_name,
            "asset_category": cat_display,
            "file_path": norm_path,
            "delta_path": v.delta_path,
            "negative_alerts": v.negative_alerts or 0,
            "file_size": file_size,
            "row_count": row_count,
            "created_at": v.created_at.isoformat() if v.created_at else None,
            "is_delta": False
        })
        
        if v.delta_path and os.path.exists(v.delta_path):
            norm_delta = os.path.normpath(v.delta_path)
            tracked_paths.add(norm_delta)
            tracked_paths.add(os.path.abspath(norm_delta))
            tracked_paths.add(os.path.basename(norm_delta))
            delta_size = os.path.getsize(norm_delta)
            delta_rows = 0
            try:
                with open(norm_delta, 'r', encoding='utf-8', errors='ignore') as f:
                    delta_rows = max(0, sum(1 for _ in f) - 1)
            except Exception:
                pass
            result.append({
                "id": f"delta_{v.id}",
                "filename": os.path.basename(norm_delta),
                "company_name": v.company_name,
                "asset_category": f"{cat_display} (Delta)",
                "file_path": norm_delta,
                "delta_path": None,
                "negative_alerts": v.negative_alerts or 0,
                "file_size": delta_size,
                "row_count": delta_rows,
                "created_at": v.created_at.isoformat() if v.created_at else None,
                "is_delta": True
            })

    # Also detect any CSV files placed directly in data/inventory/ that are not tracked in DB
    disk_files = glob.glob(os.path.join(inventory_dir, "*.csv"))
    for fpath in disk_files:
        norm_path = os.path.normpath(fpath)
        abs_path = os.path.abspath(fpath)
        base_name = os.path.basename(fpath)
        if norm_path in tracked_paths or abs_path in tracked_paths or base_name in tracked_paths:
            continue
            
        file_size = os.path.getsize(norm_path)
        row_count = 0
        try:
            with open(norm_path, 'r', encoding='utf-8', errors='ignore') as f:
                row_count = max(0, sum(1 for _ in f) - 1)
        except Exception:
            pass
        
        clean_name = base_name.replace(".csv", "")
        is_delta = clean_name.startswith("delta_")
        if is_delta:
            clean_name = clean_name[6:]
            
        if "_Comprehensive_Inventory" in clean_name:
            comp_raw = clean_name.split("_Comprehensive_Inventory")[0]
            comp = comp_raw.replace("_", " ").strip()
            cat = "Comprehensive Inventory"
        else:
            parts = clean_name.split("_")
            comp = parts[0] if parts else "Global"
            cat = parts[1] if len(parts) > 1 else "General"
            
        if is_delta:
            cat = f"{cat} (Delta)"
        
        ctime = os.path.getctime(norm_path)
        created_iso = datetime.fromtimestamp(ctime, timezone.utc).isoformat()
        
        result.append({
            "id": f"disk_{abs(hash(norm_path)) % 100000}",
            "filename": base_name,
            "company_name": comp,
            "asset_category": cat,
            "file_path": norm_path,
            "delta_path": None,
            "negative_alerts": 0,
            "file_size": file_size,
            "row_count": row_count,
            "created_at": created_iso,
            "is_delta": is_delta
        })

    return result

@router.get("/inventory/preview")
def preview_inventory_file(filename: Optional[str] = None, file_path: Optional[str] = None, request: Request = None):
    """Previews up to 300 rows of an MCP inventory CSV file."""
    if request:
        _require_auth(request)
    target_path = None
    if file_path and os.path.exists(file_path):
        target_path = file_path
    elif filename:
        safe_name = os.path.basename(filename)
        candidate = os.path.normpath(os.path.join(os.getcwd(), "data", "inventory", safe_name))
        if os.path.exists(candidate):
            target_path = candidate
            
    if not target_path or not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Inventory CSV file not found.")
        
    try:
        import pandas as pd
        df = pd.read_csv(target_path, nrows=300).fillna("")
        columns = list(df.columns)
        records = df.to_dict(orient="records")
        return {
            "status": "success",
            "filename": os.path.basename(target_path),
            "columns": columns,
            "rows": records,
            "total_rows": len(records)
        }
    except Exception as e:
        with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            records = [row for i, row in enumerate(reader) if i < 300]
            columns = list(reader.fieldnames or [])
            return {
                "status": "success",
                "filename": os.path.basename(target_path),
                "columns": columns,
                "rows": records,
                "total_rows": len(records)
            }

@router.get("/inventory/download")
def download_inventory_file(filename: Optional[str] = None, file_path: Optional[str] = None, request: Request = None):
    """Downloads an inventory CSV file."""
    if request:
        _require_auth(request)
    target_path = None
    if file_path and os.path.exists(file_path):
        target_path = file_path
    elif filename:
        safe_name = os.path.basename(filename)
        candidate = os.path.normpath(os.path.join(os.getcwd(), "data", "inventory", safe_name))
        if os.path.exists(candidate):
            target_path = candidate
            
    if not target_path or not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Inventory CSV file not found.")
        
    return FileResponse(
        target_path,
        media_type="text/csv",
        filename=os.path.basename(target_path)
    )

@router.delete("/inventory/{item_id}")
def delete_inventory_file(item_id: str, request: Request, filename: Optional[str] = None, file_path: Optional[str] = None, db: Session = Depends(get_db)):
    """Deletes an inventory record and its CSV file from database and disk."""
    _require_auth(request)
    
    # 1. If item_id is numeric, delete by database record ID
    if item_id.isdigit():
        record = db.query(AssetInventoryVersion).filter(AssetInventoryVersion.id == int(item_id)).first()
        if record:
            if record.file_path and os.path.exists(record.file_path):
                try: os.remove(record.file_path)
                except: pass
            if record.delta_path and os.path.exists(record.delta_path):
                try: os.remove(record.delta_path)
                except: pass
            db.delete(record)
            db.commit()
            return {"status": "success", "message": "Inventory version deleted"}

    # 2. If filename or file_path is passed (or item_id contains a filename), delete file on disk & matching DB rows
    candidates = []
    if file_path:
        candidates.append(os.path.normpath(file_path))
    if filename:
        candidates.append(os.path.normpath(os.path.join(os.getcwd(), "data", "inventory", os.path.basename(filename))))
    if item_id and ".csv" in item_id:
        candidates.append(os.path.normpath(os.path.join(os.getcwd(), "data", "inventory", os.path.basename(item_id))))
        
    for c in candidates:
        if os.path.exists(c):
            try: os.remove(c)
            except Exception as err: print(f"Error removing {c}: {err}")
            
        # Also remove matching DB records if any
        records = db.query(AssetInventoryVersion).filter(
            (AssetInventoryVersion.file_path == c) | (AssetInventoryVersion.delta_path == c)
        ).all()
        for r in records:
            db.delete(r)
        if records:
            db.commit()

    return {"status": "success", "message": "File removed"}

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
            
            raw_owner = str(env_dict.get("GITHUB_OWNER", "")).strip()
            raw_repo = str(env_dict.get("GITHUB_REPO", "")).strip()
            
            # Combine and sanitize if URL was given in env
            full_target = f"{raw_owner}/{raw_repo}".strip("/")
            full_target = full_target.replace("https://", "").replace("http://", "").replace("github.com/", "").replace("www.github.com/", "").strip("/")
            parts = [p for p in full_target.split("/") if p]
            
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1]
            elif len(parts) == 1:
                owner = parts[0]
                repo = "Hello-World"
            else:
                owner = "octocat"
                repo = "Hello-World"
            
            # Sanitize File Path and extract owner/repo if full URL provided in input
            f_path = req.file_path.strip() if req.file_path else ""
            f_path = urllib.parse.unquote(f_path)
            
            if "github.com/" in f_path:
                url_tail = f_path.split("github.com/")[-1].strip("/")
                url_parts = [p for p in url_tail.split("/") if p]
                if len(url_parts) >= 2:
                    owner = url_parts[0]
                    repo = url_parts[1]
                    if len(url_parts) > 4 and url_parts[2] in ["blob", "tree"]:
                        f_path = "/".join(url_parts[4:])
                    elif len(url_parts) > 2:
                        f_path = "/".join(url_parts[2:])
                    else:
                        f_path = ""
            
            for branch_tag in ["blob/main/", "blob/master/", "tree/main/", "tree/master/"]:
                if branch_tag in f_path:
                    f_path = f_path.split(branch_tag)[-1]
            
            MAX_FILES = 50
            items_to_fetch = [f_path]
            
            while items_to_fetch and len(fetched_files) < MAX_FILES:
                current_path = items_to_fetch.pop(0)
                args = {"owner": owner, "repo": repo, "path": current_path}
                
                result = await mcp.call_tool("get_file_contents", args)
                if hasattr(result, 'isError') and result.isError:
                    err_msg = ""
                    if hasattr(result, 'content') and result.content:
                        err_msg = "\n".join([c.text for c in result.content if hasattr(c, 'text')]) or str(result.content)
                    else:
                        err_msg = "Unknown GitHub MCP error"
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
                        fallback_name = current_path.split("/")[-1] if current_path else "github_file.txt"
                        fetched_files.append({
                            "name": fallback_name,
                            "content": result.content[0].text
                        })
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
            md = "# Azure Cloud Infrastructure & Security Report\n\n"
            md += f"**Mode:** {req.import_mode.upper()}\n\n"
            
            queries = []
            if req.import_mode == "general":
                md += "> **General Mode Scope**: Auditing cloud infrastructure boundaries, VM security, Network Security Groups, Public IPs, Storage access, Database security, and RBAC policies.\n\n"
                queries.append(("Resource Groups (Cloud Boundary & Environments)", "group", {"command": "list"}))
                queries.append(("Virtual Machines (Compute & OS Security)", "vm", {"command": "list"}))
                queries.append(("Network Security Groups (Firewall & Exposure Rules)", "network", {"command": "nsg list"}))
                queries.append(("Virtual Networks & Subnets (Segmentation)", "network", {"command": "vnet list"}))
                queries.append(("Public IP Addresses (External Attack Surface)", "network", {"command": "public-ip list"}))
                queries.append(("Storage Accounts (HTTPS & Public Access Policies)", "storage", {"command": "accounts list"}))
                queries.append(("Azure SQL Database Servers (Network, TLS & Auth)", "sql", {"command": "servers list"}))
                queries.append(("IAM Role Assignments (RBAC & Privileged Access)", "role", {"command": "list-assignments"}))
                queries.append(("Key Vaults Inventory (Cryptographic Assets)", "keyvault", {"command": "vaults list"}))
                queries.append(("Resource Health Events & Incident Logs", "resourcehealth", {"command": "list-events"}))
            elif req.import_mode == "pqc":
                md += "> **PQC Focus**: Extracting Cryptographic Keys, Certificates, HSM Inventory, TLS Protocol Configurations, and Data Encryption settings to satisfy Post-Quantum Cryptographic and Quantum-Resilience requirements.\n\n"
                queries.append(("Key Vaults & Dedicated HSMs Inventory", "keyvault", {"command": "vaults list"}))
                if req.file_path:
                    queries.append((f"Cryptographic Keys in Vault '{req.file_path.strip()}'", "keyvault", {"command": "keyvault_key_get", "parameters": {"vault": req.file_path.strip()}}))
                    queries.append((f"Certificates in Vault '{req.file_path.strip()}'", "keyvault", {"command": "keyvault_certificate_get", "parameters": {"vault": req.file_path.strip()}}))
                else:
                    md += "*(Optional: Provide a specific Key Vault name in the file path box to pull granular RSA/ECC keys and certificates).* \n\n"
                
                queries.append(("Storage Accounts (HTTPS Enforcement & Minimum TLS 1.2/1.3)", "storage", {"command": "accounts list"}))
                queries.append(("Azure SQL Database Servers (Minimal TLS & TDE BYOK Status)", "sql", {"command": "servers list"}))
                queries.append(("Application Gateway & Load Balancer SSL Policies", "network", {"command": "appgateway list"}))
                queries.append(("Role Assignments (Cryptographic Administrators)", "role", {"command": "list-assignments"}))
                
            for title, tool_name, args in queries:
                md += f"## {title}\n"
                md += f"`Tool: {tool_name} | Args: {json.dumps(args)}`\n\n"
                try:
                    result = await mcp.call_tool(tool_name, args)
                    if hasattr(result, 'isError') and result.isError:
                        err = str(result.content) if hasattr(result, 'content') else "Error"
                        md += f"**MCP Note:** {err}\n\n"
                        continue
                        
                    if hasattr(result, 'content') and len(result.content) > 0 and hasattr(result.content[0], 'text'):
                        try:
                            data = json.loads(result.content[0].text)
                            table_rows = []
                            if isinstance(data, list):
                                table_rows = data
                            elif isinstance(data, dict):
                                if "value" in data and isinstance(data["value"], list):
                                    table_rows = data["value"]
                                elif "resources" in data and isinstance(data["resources"], list):
                                    table_rows = data["resources"]
                                elif "items" in data and isinstance(data["items"], list):
                                    table_rows = data["items"]
                            
                            if table_rows and len(table_rows) > 0 and isinstance(table_rows[0], dict):
                                headers = [h for h in list(table_rows[0].keys())[:8] if not h.startswith("_")]
                                md += "| " + " | ".join(headers) + " |\n"
                                md += "| " + " | ".join(["---"] * len(headers)) + " |\n"
                                for row in table_rows[:50]:
                                    row_vals = [str(row.get(h, "")).replace('\n', ' ')[:100] for h in headers]
                                    md += "| " + " | ".join(row_vals) + " |\n"
                                md += "\n"
                            elif isinstance(data, list) and len(data) == 0:
                                md += "*No resources returned for this query.*\n\n"
                            else:
                                md += f"```json\n{json.dumps(data, indent=2)}\n```\n\n"
                        except json.JSONDecodeError:
                            md += f"```\n{result.content[0].text}\n```\n\n"
                    else:
                        md += "*No content returned.*\n\n"
                except Exception as e:
                    md += f"**MCP Exception:** Failed to execute {tool_name}. Details: {str(e)}\n\n"
                    
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
                    except Exception as e:
                        print(f"Direct download failed for {filename}: {e}")
                
                if not file_bytes and file_data.get("encoding") == "base64" and "content" in file_data:
                    try:
                        b64_str = file_data["content"].replace("\n", "").replace("\\n", "")
                        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
                        file_bytes = base64.b64decode(b64_str)
                    except Exception as b64_err:
                        print(f"Base64 decode error for {filename}: {b64_err}")
                elif not file_bytes and "content" in file_data:
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
                
            return {"status": "success", "count": len(saved_files), "files_processed": len(saved_files), "files": saved_files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")
