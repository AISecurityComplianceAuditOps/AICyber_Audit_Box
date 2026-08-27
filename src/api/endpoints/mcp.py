from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
import json

from src.db.database import SessionLocal, MCPServerConfig
from src.core.crypto_utils import encrypt_credential
from src.core.mcp_client import get_mcp_manager_for_config
from src.api.endpoints.auth import _require_auth

router = APIRouter(prefix="/mcp", tags=["mcp"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class MCPConfigCreate(BaseModel):
    name: str
    server_type: str
    command: str
    args: str
    env: str
    credentials: Optional[str] = None

class MCPConfigResponse(BaseModel):
    id: int
    name: str
    server_type: str
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
        command=new_config.command or "",
        args=new_config.args or "[]",
        env=new_config.env or "{}",
        has_credentials=bool(new_config.encrypted_credentials),
        is_active=new_config.is_active
    )

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
            # Sanitize Repo Path
            repo_input = req.repo_or_path.strip()
            if repo_input.endswith('.git'):
                repo_input = repo_input[:-4]
            if "github.com/" in repo_input:
                repo_input = repo_input.split("github.com/")[-1]
            r_parts = repo_input.strip("/").split("/")
            owner = r_parts[0]
            repo = r_parts[1] if len(r_parts) > 1 else ""
            
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
                                    if len(fetched_files) + len([p for p in items_to_fetch if p]) < MAX_FILES:
                                        fetched_files.append(item)
                                elif item.get("type") == "dir":
                                    items_to_fetch.append(item.get("path"))
                        else:
                            # Single file
                            fetched_files.append(data)
                    except json.JSONDecodeError:
                        raise HTTPException(status_code=500, detail="Failed to parse GitHub MCP response.")
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
                    dl_res = requests.get(file_data["download_url"], headers=headers, timeout=30)
                    if dl_res.status_code == 200:
                        file_bytes = dl_res.content
                    else:
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
