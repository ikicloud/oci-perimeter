# OCI Public Perimeter Scanner

A security audit tool that maps the **public exposure perimeter** of an Oracle Cloud Infrastructure (OCI) tenant. Scans all resources across the tenant looking for public IPs, exposed managed endpoints, public Object Storage buckets, and other potential security exposures.

Also available as a **Model Context Protocol (MCP) server** for interactive analysis with Claude Code, Claude Desktop, and other MCP-compatible AI clients.

---

## Features

The scanner identifies public exposures across **25+ OCI service categories**:

### Networking
- Public IPs (RESERVED and EPHEMERAL, region and AD scoped)
- NAT Gateway, Internet Gateway, Local Peering Gateway
- DRG Attachments (IPSEC, REMOTE_PEERING, VIRTUAL_CIRCUIT)
- Service Gateway inventory

### Compute
- VMs with primary VNIC carrying public IPs
- VMs with **secondary VNICs** carrying public IPs (often missed by other tools)
- Container Instances with public VNICs

### Load Balancing
- Public Load Balancers
- Public Network Load Balancers

### Database family
- DBCS DB Systems with public nodes
- Autonomous Database with public endpoints (resolves SQL Dev Web, APEX, Graph Studio URLs)
- MySQL HeatWave DB System on public subnets
- Managed PostgreSQL DB System on public subnets

### Storage
- Object Storage buckets with `public_access_type != NoPublicAccess`
- Active Pre-Authenticated Requests (PARs)
- FSS Mount Targets attached to public subnets

### Containers & Serverless
- OKE clusters with public Kubernetes API endpoint
- OCI Functions invoke endpoints (opt-in, always public by design)

### Integration & Analytics
- API Gateway with non-PRIVATE endpoints
- Integration Cloud, Analytics Cloud
- Data Science notebook sessions without private endpoint
- GoldenGate deployments with public URL
- OpenSearch clusters on public subnets
- Streaming (Kafka-compatible) bootstrap endpoints (opt-in)
- Big Data Service nodes with public IPs

### Security inventory
- Active Bastion sessions (time-limited port exposures)
- WAF policies (verify attachment to LBs)
- Health Check probes targeting public IPs
- Vulnerability Scanning targets
- **Cloud Guard correlation**: matches detector rule findings to scanned resources

---

## Quick start

### Prerequisites

- Python 3.9+
- OCI CLI configured (`~/.oci/config`) **or** Instance Principal on an OCI VM
- IAM read policies on the target tenant (see [`docs/permissions.md`](docs/permissions.md))

### Installation

```bash
git clone https://github.com/ikicloud/oci-perimeter.git
cd oci-perimeter
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

For optional features:

```bash
pip install -e ".[mcp]"   # MCP server for Claude Code/Desktop
pip install -e ".[viz]"   # Visualizer (charts + HTML dashboard)
pip install -e ".[all]"   # Everything
```

### First scan

```bash
oci-perimeter-scan --output-dir ./reports
```

Produces a JSON file in `./reports/` with all records, plus a summary on stdout.

---

## Usage

### Standalone CLI

```bash
# Scan home region with the DEFAULT profile
oci-perimeter-scan

# Scan all subscribed regions
oci-perimeter-scan --all-regions

# Custom OCI profile and specific region
oci-perimeter-scan --profile PRODUCTION --region eu-frankfurt-1

# Single compartment scope
oci-perimeter-scan --compartment-id ocid1.compartment.oc1..xxx

# Disable specific scanners
oci-perimeter-scan --no-cloud-guard --no-data-science

# Authenticate via Instance Principal (no API key needed)
oci-perimeter-scan --auth instance_principal

# Tune API throttle to avoid 429 rate limits
oci-perimeter-scan --api-throttle-ms 100
```

Run `oci-perimeter-scan --help` for the full list of flags.

### MCP server (Claude Code / Claude Desktop)

```bash
pip install -e ".[mcp]"
```

Once installed and configured (see [`docs/usage-mcp.md`](docs/usage-mcp.md)), you can use natural language with Claude:

> *"Scan the OCI perimeter and tell me which public buckets look suspicious."*

> *"Compare today's scan with yesterday's and highlight new exposures."*

Claude will invoke the appropriate MCP tools, analyze the results, and respond with actionable findings.

---

## Output format

The scanner produces a single JSON file with this structure:

```json
{
  "status": "OK",
  "generated_at_utc": "2026-05-13 15:13:52 UTC",
  "tenancy_id": "ocid1.tenancy.oc1..xxx",
  "regions": ["eu-frankfurt-1"],
  "compartments_count": 13,
  "summary": {
    "total_records": 11,
    "total_public_ips": 4,
    "by_exposure_category": { ... },
    "by_resource_type": { ... },
    "cloud_guard_correlated_records": 0
  },
  "records": [
    {
      "ExposureCategory": "PUBLIC_IP_NUMERIC",
      "PublicIP": "141.147.21.127",
      "Region": "eu-frankfurt-1",
      "CompartmentName": "ROOT_TENANCY",
      "ResourceType": "COMPUTE/VNIC",
      "ResourceName": "postgresql",
      ...
    }
  ]
}
```

See [`examples/`](examples/) for sample outputs.

---

## Documentation

- [`docs/setup.md`](docs/setup.md) — Detailed installation guide
- [`docs/usage-cli.md`](docs/usage-cli.md) — Complete CLI reference
- [`docs/usage-mcp.md`](docs/usage-mcp.md) — MCP server configuration for Claude
- [`docs/permissions.md`](docs/permissions.md) — Required IAM policies

---

## Authentication options

The scanner supports three OCI authentication methods:

| Method | When to use | Configuration |
|--------|-------------|---------------|
| `config_file` *(default)* | Local workstation, on-prem VM, any environment | `~/.oci/config` |
| `instance_principal` | Running from an OCI VM in the target tenant | Dynamic Group + IAM policies |
| `resource_principal` | Running as an OCI Function | Dynamic Group + IAM policies |

```bash
oci-perimeter-scan --auth instance_principal  # no API key needed
```

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

```bash
pip install -e ".[dev]"
ruff check src/
pytest
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Author

Developed and maintained by **[IKI Cloud](https://github.com/ikicloud)**.

For questions and support, open an [issue](https://github.com/ikicloud/oci-perimeter/issues).
