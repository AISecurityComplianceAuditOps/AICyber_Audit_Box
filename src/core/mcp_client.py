import asyncio
import json
import os
from typing import Optional, List, Dict, Any
from contextlib import AsyncExitStack

# Try to import from mcp SDK. If not available during execution, we handle gracefully.
try:
    from mcp.client.stdio import stdio_client, StdioServerParameters
    from mcp.client.session import ClientSession
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from src.core.crypto_utils import decrypt_credential

class MCPManager:
    def __init__(self, command: str, args: List[str], env: Dict[str, str]):
        self.command = command
        self.args = args
        self.env = env
        self.exit_stack = AsyncExitStack()
        self.session: Optional[ClientSession] = None

    async def connect(self):
        if not MCP_AVAILABLE:
            raise RuntimeError("MCP library is not installed.")
        
        full_env = os.environ.copy()
        if self.env:
            full_env.update(self.env)
            
        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=full_env
        )
        
        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        read, write = stdio_transport
        
        self.session = await self.exit_stack.enter_async_context(ClientSession(read, write))
        await self.session.initialize()

    async def list_resources(self) -> List[Any]:
        if not self.session:
            await self.connect()
        result = await self.session.list_resources()
        return result.resources if hasattr(result, 'resources') else result

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if not self.session:
            await self.connect()
        result = await self.session.call_tool(tool_name, arguments)
        return result

    async def read_resource(self, uri: str) -> Any:
        if not self.session:
            await self.connect()
        result = await self.session.read_resource(uri)
        return result

    async def close(self):
        await self.exit_stack.aclose()
        self.session = None

def get_mcp_manager_for_config(config) -> MCPManager:
    args = json.loads(config.args) if config.args else []
    env = json.loads(config.env) if config.env else {}
    
    if config.encrypted_credentials:
        decrypted = decrypt_credential(config.encrypted_credentials)
        if config.server_type.lower() == 'github':
            env['GITHUB_PERSONAL_ACCESS_TOKEN'] = decrypted
        elif config.server_type.lower() == 'jira':
            env['JIRA_API_TOKEN'] = decrypted
            
    return MCPManager(command=config.command, args=args, env=env)
