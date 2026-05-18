# MCP Server Setup

The OCI Perimeter Scanner includes a Model Context Protocol (MCP) server that lets you interact with your OCI tenant in plain English through Claude Code or Claude Desktop.

## How it works

The MCP server runs as a subprocess of Claude Code. It starts automatically when you open Claude Code in the project directory, and shuts down when you close it. No ports, no daemons, no background services.

```
You type a question in Claude Code
         │
         ▼
Claude decides which tool to call
         │
         ▼
MCP server runs the scan (using your OCI credentials)
         │
         ▼
Claude reads the results and responds in natural language
```

## Available tools

| Tool | What it does |
|------|-------------|
| `scan_perimeter` | Full scan of 25+ resource categories. Stores results in memory. |
| `get_public_ips` | Lists all public IPs with resource details (VM name, private IP, subnet). |
| `get_public_buckets` | Lists public Object Storage buckets and active Pre-Authenticated Requests. |
| `get_all_exposures` | All records grouped by exposure category. Filterable by category/compartment/region. |
| `find_anomalies` | Highlights risky items: public buckets, open Bastions, orphaned IPs, Cloud Guard flags. |

## Quick setup (recommended)

If you haven't already, run the installer:

```bash
git clone https://github.com/ikicloud/oci-perimeter.git
cd oci-perimeter
./install.sh
```

The installer creates `.mcp.json` automatically. Then:

```bash
source venv/bin/activate
claude
```

Done. Claude Code will detect the MCP server on startup.

## Manual setup

If you prefer to configure manually, create `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "oci-perimeter": {
      "command": "/absolute/path/to/oci-perimeter/venv/bin/python",
      "args": ["/absolute/path/to/oci-perimeter/mcp/oci_perimeter_mcp.py"]
    }
  }
}
```

**Important:** Use absolute paths. Relative paths will fail because Claude Code may launch the subprocess from a different working directory.

To find the correct paths:

```bash
cd /path/to/oci-perimeter
echo "Python:  $(pwd)/venv/bin/python"
echo "Server:  $(pwd)/mcp/oci_perimeter_mcp.py"
```

## Claude Desktop setup

For Claude Desktop (macOS/Windows), add to your Claude Desktop config file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "oci-perimeter": {
      "command": "/absolute/path/to/oci-perimeter/venv/bin/python",
      "args": ["/absolute/path/to/oci-perimeter/mcp/oci_perimeter_mcp.py"]
    }
  }
}
```

Restart Claude Desktop after saving. The tools will appear in the tool selector.

## Verifying the connection

Inside Claude Code, run:

```
/mcp
```

You should see:

```
oci-perimeter  ✓ connected
  Tools: scan_perimeter, get_public_ips, get_public_buckets,
         get_all_exposures, find_anomalies
```

## Example conversations

```
You: Scan my OCI tenant and tell me what's publicly exposed

Claude: [runs scan_perimeter, then get_public_ips, get_public_buckets,
         find_anomalies in parallel]

        Here's your OCI public exposure report:

        🚨 2 public Object Storage buckets — anyone can read them
        🔴 1 Compute VM flagged by Cloud Guard (high severity)
        🟡 4 public IPs across 3 VMs and 1 API Gateway
        🌐 3 Internet Gateways enabled
        ✅ No active Bastion sessions, no orphaned IPs
```

```
You: Which VM has the riskiest public IP?

Claude: [calls get_public_ips — no re-scan needed]

        The postgresql VM (141.0.0.x) is the most concerning:
        a database with a public IP should almost never be directly
        internet-reachable. Check that port 5432 is not open to 0.0.0.0/0.
```

```
You: Are there any public buckets?

Claude: [calls get_public_buckets — no re-scan needed]

        Yes, 2 buckets with ObjectRead access:
        - bucket-example in compartment dev, created 2025-12-10
        - bucket-data in compartment prod, created 2025-07-24
        Both are accessible without authentication.
```

## Authentication in MCP mode

The MCP server uses the same OCI credentials as the CLI. By default it reads `~/.oci/config` with the `DEFAULT` profile.

To use a different profile, ask Claude:

```
Scan using the PRODUCTION profile
```

Claude will pass `profile="PRODUCTION"` to the `scan_perimeter` tool.

For Instance Principal (running on an OCI VM), the MCP server picks it up automatically if the VM has the right Dynamic Group and policies configured.

## Troubleshooting

**Server doesn't appear in `/mcp`:**
- Check that `.mcp.json` exists in the project root
- Verify the Python path is correct: `cat .mcp.json`
- Check that `mcp` is installed: `venv/bin/python -c "from mcp.server.fastmcp import FastMCP; print('OK')"`

**Scan returns an error:**
- Run `oci-perimeter-scan --help` from the terminal to verify the CLI works
- Check OCI credentials: `oci iam region list`
- Try with `--no-cloud-guard` if you see 404 errors

**Scan is very slow:**
- Use `--region eu-frankfurt-1` to limit to one region
- Avoid `all_regions=true` unless you specifically need multi-region coverage

