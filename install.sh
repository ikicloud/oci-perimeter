#!/usr/bin/env bash
# =============================================================================
# OCI Public Perimeter Scanner — installer
# https://github.com/ikicloud/oci-perimeter
#
# Usage:
#   git clone https://github.com/ikicloud/oci-perimeter.git
#   cd oci-perimeter
#   ./install.sh
#
# What this script does:
#   1. Checks prerequisites (Python 3.10+, OCI CLI)
#   2. Creates a Python virtual environment in ./venv
#   3. Installs the scanner + MCP server dependencies
#   4. Generates .mcp.json with correct absolute paths for Claude Code
#   5. Prints next steps
#
# Supported OS: Linux (RHEL/Oracle/Ubuntu/Debian), macOS
# =============================================================================

set -euo pipefail

# --- Colors ------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Helpers -----------------------------------------------------------------
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
header()  { echo -e "\n${BOLD}$*${NC}"; echo "$(echo "$*" | sed 's/./-/g')"; }

# --- Banner ------------------------------------------------------------------
echo ""
echo -e "${BOLD}OCI Public Perimeter Scanner${NC} — by IKI Cloud"
echo -e "https://github.com/ikicloud/oci-perimeter"
echo ""

# =============================================================================
# STEP 1 — Locate project root
# =============================================================================
header "Step 1/5 — Checking project directory"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f "pyproject.toml" ]]; then
    die "pyproject.toml not found. Run this script from the project root directory."
fi

success "Project root: $SCRIPT_DIR"

# =============================================================================
# STEP 2 — Check Python 3.10+
# =============================================================================
header "Step 2/5 — Checking Python version"

find_python() {
    # Try python3.12, python3.11, python3.10 in order, then python3/python
    for cmd in python3.12 python3.11 python3.10 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null)
            major=$(echo "$ver" | tr -d '(),' | awk '{print $1}')
            minor=$(echo "$ver" | tr -d '(),' | awk '{print $2}')
            if [[ "$major" -ge 3 && "$minor" -ge 10 ]]; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON=$(find_python || true)

if [[ -z "$PYTHON" ]]; then
    error "Python 3.10 or newer is required but was not found."
    echo ""
    echo "Install it with:"
    echo "  RHEL/Oracle Linux 8:  sudo dnf module install -y nodejs:20 && sudo dnf install -y python3.11"
    echo "  Ubuntu/Debian:        sudo apt install -y python3.11 python3.11-venv"
    echo "  macOS (Homebrew):     brew install python@3.11"
    echo ""
    die "Please install Python 3.10+ and re-run this script."
fi

PYTHON_VERSION=$("$PYTHON" --version 2>&1)
success "Found: $PYTHON_VERSION ($PYTHON)"

# =============================================================================
# STEP 3 — Check OCI CLI
# =============================================================================
header "Step 3/5 — Checking OCI CLI"

if ! command -v oci &>/dev/null; then
    warn "OCI CLI not found."
    echo ""
    echo "  Install it with:"
    echo "    bash -c \"\$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)\""
    echo ""
    echo "  Then configure it:"
    echo "    oci setup config"
    echo ""
    echo "  After installation, re-run: ./install.sh"
    echo ""
    die "OCI CLI is required. Please install it and re-run this script."
fi

OCI_VERSION=$(oci --version 2>/dev/null || oci -version 2>/dev/null || echo "unknown")
success "OCI CLI found: $OCI_VERSION"

# Check that ~/.oci/config exists
OCI_CONFIG="${OCI_CONFIG_FILE:-$HOME/.oci/config}"
if [[ ! -f "$OCI_CONFIG" ]]; then
    warn "OCI config file not found at $OCI_CONFIG"
    echo ""
    echo "  Run 'oci setup config' to configure your OCI credentials."
    echo "  You will need:"
    echo "    - Your User OCID (from OCI Console → Profile → User Settings)"
    echo "    - Your Tenancy OCID (from OCI Console → Profile → Tenancy)"
    echo "    - Your home region (e.g. eu-frankfurt-1)"
    echo ""
    warn "Continuing install — but the scanner won't work until OCI CLI is configured."
else
    success "OCI config found: $OCI_CONFIG"
fi

# =============================================================================
# STEP 4 — Create virtualenv and install dependencies
# =============================================================================
header "Step 4/5 — Installing Python dependencies"

VENV_DIR="$SCRIPT_DIR/venv"

if [[ -d "$VENV_DIR" ]]; then
    # Check if existing venv uses Python 3.10+
    VENV_PYTHON="$VENV_DIR/bin/python"
    if [[ -f "$VENV_PYTHON" ]]; then
        ver=$("$VENV_PYTHON" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null)
        major=$(echo "$ver" | tr -d '(),' | awk '{print $1}')
        minor=$(echo "$ver" | tr -d '(),' | awk '{print $2}')
        if [[ "$major" -ge 3 && "$minor" -ge 10 ]]; then
            success "Existing venv is Python 3.${minor}, reusing it."
        else
            warn "Existing venv uses Python 3.${minor} (need 3.10+). Recreating..."
            rm -rf "$VENV_DIR"
            "$PYTHON" -m venv "$VENV_DIR"
            success "Virtualenv recreated with $PYTHON_VERSION"
        fi
    fi
else
    info "Creating virtualenv in $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
    success "Virtualenv created with $PYTHON_VERSION"
fi

VENV_PYTHON="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

info "Upgrading pip..."
"$VENV_PIP" install --upgrade pip --quiet

info "Installing oci-perimeter-scanner with MCP support..."
info "(This installs: oci SDK, mcp framework, and all dependencies — may take 2-3 minutes)"
"$VENV_PIP" install -e ".[mcp]" --quiet

success "All Python dependencies installed."

# =============================================================================
# STEP 5 — Generate .mcp.json for Claude Code
# =============================================================================
header "Step 5/5 — Configuring Claude Code MCP integration"

MCP_SERVER_PATH="$SCRIPT_DIR/mcp/oci_perimeter_mcp.py"

if [[ ! -f "$MCP_SERVER_PATH" ]]; then
    die "MCP server not found at $MCP_SERVER_PATH. Is the repository complete?"
fi

MCP_JSON_PATH="$SCRIPT_DIR/.mcp.json"

# Write .mcp.json with absolute paths resolved at install time
cat > "$MCP_JSON_PATH" << EOF
{
  "mcpServers": {
    "oci-perimeter": {
      "command": "$VENV_PYTHON",
      "args": ["$MCP_SERVER_PATH"]
    }
  }
}
EOF

success "Claude Code config written to $MCP_JSON_PATH"

# Verify the JSON is valid
if command -v python3 &>/dev/null; then
    python3 -c "import json; json.load(open('$MCP_JSON_PATH'))" \
        && success ".mcp.json is valid JSON" \
        || warn ".mcp.json may have formatting issues — check it manually"
fi

# =============================================================================
# Done — print next steps
# =============================================================================
echo ""
echo -e "${GREEN}${BOLD}✅ Installation complete!${NC}"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo "  1. Activate the virtual environment:"
echo -e "     ${BOLD}source venv/bin/activate${NC}"
echo ""
echo "  2. (Optional) Verify the scanner works:"
echo -e "     ${BOLD}oci-perimeter-scan --help${NC}"
echo ""
echo "  3. Launch Claude Code from this directory:"
echo -e "     ${BOLD}cd $SCRIPT_DIR && claude${NC}"
echo ""
echo "  4. Ask Claude anything about your OCI tenant:"
echo -e "     ${BOLD}\"Scan my OCI tenant and tell me what's publicly exposed\"${NC}"
echo ""
echo -e "${BOLD}Documentation:${NC}"
echo "  CLI usage:   docs/usage-cli.md"
echo "  MCP setup:   docs/usage-mcp.md"
echo "  Permissions: docs/permissions.md"
echo ""
echo -e "Made with ♥ by ${BOLD}IKI Cloud${NC} — https://github.com/ikicloud/oci-perimeter"
echo ""

