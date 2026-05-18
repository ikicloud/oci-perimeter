# CLI Usage Reference

## Basic usage

```bash
# Activate the virtual environment first
source venv/bin/activate

# Scan home region with DEFAULT profile
oci-perimeter-scan

# Or using Python directly
python -m oci_perimeter_scanner.scanner
```

## Authentication options

```bash
# Config file (default) — reads ~/.oci/config
oci-perimeter-scan --profile DEFAULT
oci-perimeter-scan --profile PRODUCTION

# Instance Principal — for VMs running inside OCI (no API key needed)
oci-perimeter-scan --auth instance_principal

# Custom config file location
oci-perimeter-scan --config-file /path/to/my/config --profile MYPROFILE
```

## Scope options

```bash
# Scan home region only (default, fastest)
oci-perimeter-scan

# Scan a specific region
oci-perimeter-scan --region eu-frankfurt-1
oci-perimeter-scan --region us-ashburn-1

# Scan ALL subscribed regions (slowest, most complete)
oci-perimeter-scan --all-regions

# Limit to a single compartment
oci-perimeter-scan --compartment-id ocid1.compartment.oc1..xxx

# Exclude the root tenancy from results
oci-perimeter-scan --no-root-tenancy
```

## Scanner toggles

Each scanner can be disabled individually to speed up the scan or reduce noise.

```bash
# Disable Cloud Guard correlation (use if Cloud Guard is not enabled)
oci-perimeter-scan --no-cloud-guard

# Disable specific resource types
oci-perimeter-scan --no-load-balancers
oci-perimeter-scan --no-network-load-balancers
oci-perimeter-scan --no-object-storage
oci-perimeter-scan --no-dbcs
oci-perimeter-scan --no-fss
oci-perimeter-scan --no-drg
oci-perimeter-scan --no-mysql
oci-perimeter-scan --no-postgresql
oci-perimeter-scan --no-bastion
oci-perimeter-scan --no-waf
oci-perimeter-scan --no-data-science
oci-perimeter-scan --no-big-data

# Include services that are always public by design (Functions, Streaming)
# Disabled by default to reduce noise
oci-perimeter-scan --include-always-public

# Include expired Pre-Authenticated Requests (PARs)
oci-perimeter-scan --include-expired-par
```

## Performance tuning

```bash
# Throttle API calls to avoid 429 rate limits (default: 50ms)
oci-perimeter-scan --api-throttle-ms 100   # slower but safer on busy tenants
oci-perimeter-scan --api-throttle-ms 200   # safest for very large tenants
oci-perimeter-scan --api-throttle-ms 0     # no throttle (fastest, may hit limits)

# DNS timeout for endpoint resolution (default: 5s)
oci-perimeter-scan --dns-timeout 10
```

## Output options

```bash
# Save JSON to a specific directory (default: current directory)
oci-perimeter-scan --output-dir ./reports

# Custom filename prefix (default: oci_perimeter)
oci-perimeter-scan --prefix my_tenant_scan

# Print full JSON to stdout instead of saving to file
oci-perimeter-scan --stdout-json

# Add tenant label to the report
oci-perimeter-scan --tenant-label "ACME Production"

# Suppress stdout summary (only log to stderr)
oci-perimeter-scan --quiet

# Change log level
oci-perimeter-scan --log-level DEBUG
oci-perimeter-scan --log-level WARNING
```

## Common combinations

```bash
# Fast scan: home region, no Cloud Guard, minimal output
oci-perimeter-scan --no-cloud-guard --quiet --output-dir ./reports

# Full audit: all regions, verbose, save to reports/
oci-perimeter-scan --all-regions --tenant-label "ACME Corp" --output-dir ./reports

# Production instance with Instance Principal
oci-perimeter-scan \
  --auth instance_principal \
  --all-regions \
  --tenant-label "ACME Production" \
  --output-dir /var/log/oci-perimeter/ \
  --api-throttle-ms 100

# Pipe JSON to jq for quick analysis
oci-perimeter-scan --stdout-json --quiet | jq '.summary'
oci-perimeter-scan --stdout-json --quiet | jq '.records[] | select(.PublicIP != "") | {ip: .PublicIP, name: .ResourceName}'
```

## Output format

The scanner produces a single JSON file:

```json
{
  "status": "OK",
  "generated_at_utc": "2026-05-15 10:00:00 UTC",
  "tenancy_id": "ocid1.tenancy.oc1..xxx",
  "tenant_label": "ACME Corp",
  "regions": ["eu-frankfurt-1"],
  "compartments_count": 13,
  "summary": {
    "total_records": 11,
    "total_public_ips": 4,
    "by_exposure_category": {
      "PUBLIC_IP_NUMERIC": 3,
      "INTERNET_GATEWAY": 3,
      "OBJECT_STORAGE_PUBLIC_BUCKET": 2,
      "SERVICE_GATEWAY_INVENTORY": 2,
      "MANAGED_SERVICE_DNS_IP|PUBLIC_IP_NUMERIC": 1
    },
    "by_resource_type": { ... },
    "cloud_guard_correlated_records": 0,
    "scan_errors_count": 0
  },
  "scan_errors_count": 0,
  "scan_errors": [],
  "records": [ ... ]
}
```

See `examples/sample-output.json` for a full example with anonymized data.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed successfully |
| 2 | Fatal error (authentication failed, network unreachable, etc.) |

