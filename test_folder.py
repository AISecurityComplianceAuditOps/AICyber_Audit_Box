import asyncio, os, json
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

async def main():
    args = {'owner': 'octocat', 'repo': 'Spoon-Knife', 'path': ''}  # root directory
    server_params = StdioServerParameters(command='npx', args=['-y', '@modelcontextprotocol/server-github'], env=os.environ.copy())
    
    async with AsyncExitStack() as stack:
        read, write = await stack.enter_async_context(stdio_client(server_params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        
        try:
            result = await session.call_tool('get_file_contents', args)
            if hasattr(result, 'content') and len(result.content) > 0:
                data = json.loads(result.content[0].text)
                if isinstance(data, list):
                    print('It is a directory! Found', len(data), 'items.')
                    for item in data[:5]:
                        print(f"  - {item['type']}: {item['path']} (url: {item.get('download_url')})")
                else:
                    print('It returned a single object:', type(data))
        except Exception as e:
            print('Error:', repr(e))

asyncio.run(main())
