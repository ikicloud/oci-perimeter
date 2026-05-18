# Installation Guide

This guide covers manual installation for users who want full control over the setup process. If you just want to get started quickly, use the one-command installer instead:

```bash
./install.sh
```

## Prerequisites

### Python 3.10 or newer

```bash
python3 --version
```

If you have Python 3.9 or older, install a newer version:

**RHEL / Oracle Linux 8:**
```bash
sudo dnf module install -y nodejs:20
sudo dnf install -y python3.11 python3.11-pip
python3.11 --version
```

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-pip
python3.11 --version
```

**macOS (Homebrew):**
```bash
brew install python@3.11
python3.11 --version
```

### OCI CLI

The scanner uses OCI SDK (Python), not the OCI CLI binary directly. However, the OCI CLI is needed to set up and verify your credentials.

Install the OCI CLI:

```bash
bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"
```

Accept the defaults. After installation, reload your shell:

```bash
source ~/.bashrc   # Linux
source ~/.zshrc    # macOS with zsh
```

Verify:

```bash
oci --version
```

### OCI credentials

Configure the OCI CLI with your credentials:

```bash
oci setup config
```

You will need:
- **User OCID** — from OCI Console → Profile (top right) → User Settings → copy OCID
- **Tenancy OCID** — from OCI Console → Profile → Tenancy → copy OCID
- **Home region** — e.g. `eu-frankfurt-1`, `us-ashburn-1`
- **API key** — the setup wizard generates one automatically

At the end of `oci setup config`, it prints a public key. You must upload it to OCI Console:
Profile → User Settings → API Keys → Add API Key → Paste Public Key → Add.

Verify the credentials work:

```bash
oci iam region list --output table
```

You should see a table of OCI regions. If you get a 401 error, check that:
- The fingerprint in `~/.oci/config` matches the key uploaded to Console
- The API key is not expired or revoked
- Your system clock is accurate (OCI rejects requests with >5 min clock skew)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ikicloud/oci-perimeter.git
cd oci-perimeter
```

### 2. Create a virtual environment

Always use a virtual environment to avoid conflicts with system Python packages.

```bash
python3.11 -m venv venv
source venv/bin/activate
```

Your prompt should now show `(venv)`.

### 3. Install the scanner

**CLI only (no MCP server):**
```bash
pip install -e .
```

**CLI + MCP server for Claude Code/Desktop:**
```bash
pip install -e ".[mcp]"
```

**Everything (CLI + MCP + visualizer charts):**
```bash
pip install -e ".[all]"
```

### 4. Verify the installation

```bash
oci-perimeter-scan --help
```

You should see the full list of CLI flags.

### 5. Run your first scan

```bash
oci-perimeter-scan --no-cloud-guard --output-dir ./reports
```

`--no-cloud-guard` is recommended for first runs — if Cloud Guard is not enabled in your tenant, it avoids harmless 404 errors in the output.

The scan takes approximately:
- **30-90 seconds** for a single region with few compartments
- **5-10 minutes** for all regions on a large tenant

Output: a JSON file in `./reports/` plus a summary on stdout.

## MCP server setup (Claude Code)

After installing with `pip install -e ".[mcp]"`:

### Generate .mcp.json

```bash
cat > .mcp.json << EOF
{
  "mcpServers": {
    "oci-perimeter": {
      "command": "$(pwd)/venv/bin/python",
      "args": ["$(pwd)/mcp/oci_perimeter_mcp.py"]
    }
  }
}
EOF
```

This uses `$(pwd)` to insert absolute paths automatically.

### Launch Claude Code

```bash
claude
```

Claude Code reads `.mcp.json` on startup and launches the MCP server as a subprocess. The server starts in ~1-2 seconds and shuts down when you close Claude Code.

Verify the server is connected:

```
/mcp
```

You should see `oci-perimeter ✓ connected` with the 5 available tools listed.

### First conversation

```
Scan my OCI tenant and tell me what's publicly exposed
```

Claude will run `scan_perimeter`, then automatically call `get_public_ips`, `get_public_buckets`, and `find_anomalies` to build a complete security report.

## Keeping the scanner updated

```bash
cd oci-perimeter
git pull
pip install -e ".[mcp]"   # picks up any new dependencies
```

No need to recreate the venv or regenerate `.mcp.json` for updates.

## Uninstalling

```bash
# Remove the virtual environment and all installed packages
rm -rf venv

# Remove the project directory
cd ..
rm -rf oci-perimeter
```

The scanner does not write anything outside the project directory (no system files, no cron jobs, no daemons).

## IAM policies

The scanner needs read-only access to your OCI resources. See [permissions.md](permissions.md) for the full list of required policies and setup instructions for both API key and Instance Principal authentication.

## Troubleshooting

**`oci-perimeter-scan: command not found`**
You are outside the virtual environment. Run `source venv/bin/activate` first.

**`ModuleNotFoundError: No module named 'oci'`**
The package is not installed in the active Python environment. Run `pip install -e .` with the venv active.

**`401 NotAuthenticated` errors during scan**
- Check your system clock: `date -u` and compare with real UTC time
- Verify fingerprint: `openssl rsa -in ~/.oci/oci_api_key.pem -pubout -outform DER 2>/dev/null | openssl md5 -c`
- Compare with `fingerprint=` in `~/.oci/config` — they must match exactly

**`429 TooManyRequests` errors**
Add `--api-throttle-ms 100` or `--api-throttle-ms 200` to slow down API calls.

**`404` errors on Cloud Guard**
Cloud Guard is not enabled in your tenant. Use `--no-cloud-guard` to suppress these errors.

**MCP server not appearing in Claude Code**
- Verify `.mcp.json` exists: `cat .mcp.json`
- Verify the Python path is correct: `ls -la venv/bin/python`
- Check that `mcp` is installed: `venv/bin/python -c "from mcp.server.fastmcp import FastMCP; print('OK')"`
- Restart Claude Code completely (not just a new session)
