#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCI Public Perimeter MCP Server
================================
Exposes OCI perimeter scanning as MCP tools for Claude Code / Claude Desktop.

Tools:
  scan_perimeter      - Run a full scan. Stores results in memory, returns summary.
  get_public_ips      - List all public IPs from the last scan.
  get_public_buckets  - List public Object Storage buckets and active PARs.
  get_all_exposures   - All records from last scan, grouped by category.
  find_anomalies      - Highlight suspicious/unexpected exposures.

Usage:
  mcp dev mcp/oci_perimeter_mcp.py        # interactive test (needs Node.js)
  claude                                   # production use via Claude Code
"""

import logging
import sys
from typing import Any, Dict, List, Optional

# ALL logging goes to stderr. stdout is reserved for JSON-RPC protocol.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("oci-perimeter-mcp")

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    log.error('mcp not installed. Run: pip install -e ".[mcp]"')
    sys.exit(2)

try:
    from oci_perimeter_scanner.scanner import run_scan
except ImportError as e:
    log.error(f"Scanner module not found: {e}")
    log.error("Run: pip install -e . from the project root")
    sys.exit(2)


mcp = FastMCP("oci-perimeter")

# ---------------------------------------------------------------------------
# In-memory store for the last scan result.
# The MCP server process stays alive for the entire Claude Code session, so
# scan_perimeter() stores data here and all other tools read from it.
# No disk I/O needed for the query tools.
# ---------------------------------------------------------------------------
_last_scan: Dict[str, Any] = {}


def _records() -> List[Dict[str, Any]]:
    """Return records from the last scan, or empty list if no scan yet."""
    return _last_scan.get("records", [])


def _require_scan() -> Optional[str]:
    """Return an error message if no scan has been run yet, else None."""
    if not _last_scan:
        return (
            "No scan data available. Run scan_perimeter first, then call this tool again."
        )
    return None


# ---------------------------------------------------------------------------
# TOOL 1: scan_perimeter
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_perimeter(
    profile: str = "DEFAULT",
    region: Optional[str] = None,
    all_regions: bool = False,
    compartment_id: Optional[str] = None,
    include_cloud_guard: bool = True,
    include_always_public: bool = False,
    tenant_label: str = "OCI_TENANT",
) -> Dict[str, Any]:
    """
    Run a full OCI public perimeter scan.

    Scans 25+ resource categories: public IPs, Load Balancers, API Gateways,
    Autonomous Databases, OKE clusters, Object Storage public buckets and PARs,
    DB Systems, FSS Mount Targets, Internet Gateways, MySQL/PostgreSQL on public
    subnets, Container Instances, OpenSearch, Bastion sessions, WAF, and more.

    Results are stored in server memory. Call get_public_ips, get_public_buckets,
    get_all_exposures or find_anomalies to query the results without re-scanning.

    Args:
        profile: OCI CLI profile name in ~/.oci/config. Default "DEFAULT".
        region: Specific region to scan (e.g. "eu-frankfurt-1").
                If omitted and all_regions=False, scans the home region only.
        all_regions: Scan ALL subscribed regions. Slower but complete.
        compartment_id: Limit scan to one compartment OCID. Default: full tenant.
        include_cloud_guard: Correlate Cloud Guard findings. Disable if Cloud Guard
                             is not enabled in the tenant (avoids 404 errors).
        include_always_public: Include services that are always public by design
                               (Functions, Streaming). Default False to reduce noise.
        tenant_label: Human-readable tenant label for reference only.

    Returns:
        A compact summary of findings. Use the other tools to drill down.
    """
    log.info(
        f"scan_perimeter: profile={profile} region={region} "
        f"all_regions={all_regions} compartment_id={compartment_id}"
    )

    opts: Dict[str, Any] = {
        "auth": "config_file",
        "config_file": "~/.oci/config",
        "profile": profile,
        "region": region,
        "all_regions": all_regions,
        "compartment_id": compartment_id,
        "no_root_tenancy": False,
        "tenant_label": tenant_label,
        "scan_load_balancers": True,
        "scan_network_load_balancers": True,
        "scan_managed_endpoints": True,
        "scan_object_storage": True,
        "scan_par": True,
        "include_expired_par": False,
        "scan_cloud_guard": include_cloud_guard,
        "scan_compute_secondary_vnics": True,
        "scan_dbcs": True,
        "scan_fss": True,
        "scan_drg": True,
        "scan_service_gateway": True,
        "scan_internet_gateway": True,
        "scan_local_peering": True,
        "scan_mysql": True,
        "scan_postgresql": True,
        "scan_container_instances": True,
        "scan_functions": include_always_public,
        "scan_integration": True,
        "scan_analytics": True,
        "scan_data_science": True,
        "scan_golden_gate": True,
        "scan_opensearch": True,
        "scan_streaming": include_always_public,
        "scan_big_data": True,
        "scan_bastion": True,
        "scan_waf": True,
        "scan_health_checks": True,
        "scan_vss": True,
        "include_always_public": include_always_public,
        "include_unresolved": True,
        "dns_timeout": 5.0,
        "api_throttle_ms": 50,
    }

    try:
        result = run_scan(opts)
    except Exception as exc:
        log.exception("scan_perimeter failed")
        return {
            "status": "ERROR",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }

    # Store full result in memory for the other tools
    _last_scan.clear()
    _last_scan.update(result)

    n = result["summary"]["total_records"]
    n_ip = result["summary"]["total_public_ips"]
    n_err = result["scan_errors_count"]
    log.info(f"scan_perimeter done: {n} records, {n_ip} public IPs, {n_err} errors")

    # Return a compact summary — NOT the full records list.
    # Claude reads this and then calls the specific query tools.
    return {
        "status": "OK",
        "generated_at_utc": result["generated_at_utc"],
        "tenancy_id": result["tenancy_id"],
        "regions": result["regions"],
        "compartments_count": result["compartments_count"],
        "summary": result["summary"],
        "scan_errors_count": n_err,
        "tip": (
            "Scan complete. Call get_public_ips, get_public_buckets, "
            "get_all_exposures or find_anomalies to explore the results."
        ),
    }


# ---------------------------------------------------------------------------
# TOOL 2: get_public_ips
# ---------------------------------------------------------------------------

@mcp.tool()
def get_public_ips(region: Optional[str] = None) -> Dict[str, Any]:
    """
    Return all public IP addresses found in the last scan.

    Includes: Compute VMs (primary and secondary VNICs), Load Balancers,
    Network Load Balancers, NAT Gateways, API Gateway resolved IPs, and
    any other resource carrying a numeric public IPv4 address.

    Args:
        region: Filter by region name (e.g. "eu-frankfurt-1"). Default: all regions.

    Returns:
        List of public IPs with resource details (type, name, compartment,
        private IP, subnet).
    """
    err = _require_scan()
    if err:
        return {"status": "NO_DATA", "message": err}

    ips = []
    for r in _records():
        ip = r.get("PublicIP", "")
        if not ip:
            continue
        if region and r.get("Region") != region:
            continue
        ips.append({
            "public_ip":      ip,
            "private_ip":     r.get("PrivateIP", ""),
            "resource_type":  r.get("ResourceType", ""),
            "resource_name":  r.get("ResourceName", ""),
            "compartment":    r.get("CompartmentName", ""),
            "region":         r.get("Region", ""),
            "subnet":         r.get("SubnetName", ""),
            "lifetime":       r.get("Lifetime", ""),
            "status":         r.get("LifecycleState", ""),
            "note":           r.get("Note", ""),
        })

    return {
        "status": "OK",
        "scan_time": _last_scan.get("generated_at_utc", ""),
        "filter_region": region,
        "total": len(ips),
        "public_ips": ips,
    }


# ---------------------------------------------------------------------------
# TOOL 3: get_public_buckets
# ---------------------------------------------------------------------------

@mcp.tool()
def get_public_buckets() -> Dict[str, Any]:
    """
    Return all public Object Storage buckets and active Pre-Authenticated
    Requests (PARs) found in the last scan.

    Public buckets have public_access_type != NoPublicAccess and are
    accessible without authentication. PARs grant time-limited access
    to specific objects or entire buckets via a URL.

    Returns:
        Separate lists for public buckets and active PARs, with compartment,
        access type, endpoint URL, and creation date.
    """
    err = _require_scan()
    if err:
        return {"status": "NO_DATA", "message": err}

    buckets = []
    pars = []

    for r in _records():
        cat = r.get("ExposureCategory", "")

        if "OBJECT_STORAGE_PUBLIC_BUCKET" in cat:
            buckets.append({
                "bucket_name":   r.get("BucketName") or r.get("ResourceName", ""),
                "compartment":   r.get("CompartmentName", ""),
                "region":        r.get("Region", ""),
                "access_type":   r.get("AccessType", ""),
                "endpoint":      r.get("Endpoint", ""),
                "time_created":  r.get("TimeCreated", ""),
                "note":          r.get("Note", ""),
            })

        elif "PRE_AUTHENTICATED_REQUEST" in cat:
            pars.append({
                "par_name":      r.get("ResourceName", ""),
                "bucket_name":   r.get("BucketName", ""),
                "object_name":   r.get("ObjectName", ""),
                "access_type":   r.get("AccessType", ""),
                "compartment":   r.get("CompartmentName", ""),
                "region":        r.get("Region", ""),
                "time_expires":  r.get("TimeExpires", ""),
                "time_created":  r.get("TimeCreated", ""),
                "status":        r.get("ExposureStatus", ""),
                "note":          r.get("Note", ""),
            })

    return {
        "status": "OK",
        "scan_time": _last_scan.get("generated_at_utc", ""),
        "public_buckets_count": len(buckets),
        "active_pars_count": len(pars),
        "public_buckets": buckets,
        "active_pars": pars,
    }


# ---------------------------------------------------------------------------
# TOOL 4: get_all_exposures
# ---------------------------------------------------------------------------

@mcp.tool()
def get_all_exposures(
    category: Optional[str] = None,
    compartment: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return all exposures from the last scan, grouped by category.

    Use this for a complete picture of what is publicly exposed: not just
    IPs and buckets, but also Internet Gateways, Service Gateways, DRG
    attachments, Bastion sessions, WAF policies, and more.

    Args:
        category: Filter by exposure category. Examples:
                  "PUBLIC_IP_NUMERIC", "OBJECT_STORAGE_PUBLIC_BUCKET",
                  "INTERNET_GATEWAY", "SERVICE_GATEWAY_INVENTORY",
                  "BASTION_SESSION_ACTIVE", "DRG_ATTACHMENT_EXTERNAL".
                  Default: all categories.
        compartment: Filter by compartment name (partial match). Default: all.
        region: Filter by region. Default: all regions.

    Returns:
        Records grouped by ExposureCategory, with a count per category.
    """
    err = _require_scan()
    if err:
        return {"status": "NO_DATA", "message": err}

    filtered = []
    for r in _records():
        cat = r.get("ExposureCategory", "")
        comp = r.get("CompartmentName", "")
        reg = r.get("Region", "")

        if category and category.upper() not in cat.upper():
            continue
        if compartment and compartment.lower() not in comp.lower():
            continue
        if region and reg != region:
            continue

        filtered.append({
            "category":       cat,
            "status":         r.get("ExposureStatus", ""),
            "public_ip":      r.get("PublicIP", ""),
            "endpoint":       r.get("Endpoint", ""),
            "resource_type":  r.get("ResourceType", ""),
            "resource_name":  r.get("ResourceName", ""),
            "compartment":    comp,
            "region":         reg,
            "bucket":         r.get("BucketName", ""),
            "access_type":    r.get("AccessType", ""),
            "time_created":   r.get("TimeCreated", ""),
            "note":           r.get("Note", ""),
        })

    # Group by category for easier reading
    grouped: Dict[str, List] = {}
    for r in filtered:
        key = r["category"] or "UNKNOWN"
        grouped.setdefault(key, []).append(r)

    counts = {k: len(v) for k, v in grouped.items()}

    return {
        "status": "OK",
        "scan_time": _last_scan.get("generated_at_utc", ""),
        "filters": {
            "category": category,
            "compartment": compartment,
            "region": region,
        },
        "total_matching": len(filtered),
        "count_by_category": counts,
        "exposures_by_category": grouped,
    }


# ---------------------------------------------------------------------------
# TOOL 5: find_anomalies
# ---------------------------------------------------------------------------

@mcp.tool()
def find_anomalies() -> Dict[str, Any]:
    """
    Highlight potentially unexpected or risky exposures from the last scan.

    Checks for:
    - Public Object Storage buckets (data accessible without authentication)
    - Active Pre-Authenticated Requests (time-limited but publicly accessible URLs)
    - Unassigned reserved public IPs (cost waste + unused attack surface)
    - Active Bastion sessions (open tunnels to private resources)
    - FSS Mount Targets on public subnets (NFS potentially reachable from Internet)
    - Internet Gateways enabled on VCNs
    - Cloud Guard correlated records (if Cloud Guard was included in the scan)

    Returns:
        A structured report with findings grouped by risk area, plus a
        plain-language summary for quick reading.
    """
    err = _require_scan()
    if err:
        return {"status": "NO_DATA", "message": err}

    findings: Dict[str, List] = {
        "public_buckets": [],
        "active_pars": [],
        "orphan_public_ips": [],
        "active_bastion_sessions": [],
        "fss_on_public_subnet": [],
        "internet_gateways": [],
        "cloud_guard_flagged": [],
    }

    for r in _records():
        cat = r.get("ExposureCategory", "")
        rtype = r.get("ResourceType", "")
        status = r.get("ExposureStatus", "")

        if "OBJECT_STORAGE_PUBLIC_BUCKET" in cat:
            findings["public_buckets"].append({
                "bucket":      r.get("BucketName") or r.get("ResourceName"),
                "access_type": r.get("AccessType"),
                "compartment": r.get("CompartmentName"),
                "endpoint":    r.get("Endpoint"),
            })

        elif "PRE_AUTHENTICATED_REQUEST" in cat and status == "ACTIVE":
            findings["active_pars"].append({
                "par_name":    r.get("ResourceName"),
                "bucket":      r.get("BucketName"),
                "expires":     r.get("TimeExpires"),
                "access_type": r.get("AccessType"),
                "compartment": r.get("CompartmentName"),
            })

        elif "PUBLIC_IP_NUMERIC" in cat and rtype == "UNASSIGNED":
            findings["orphan_public_ips"].append({
                "public_ip":  r.get("PublicIP"),
                "compartment": r.get("CompartmentName"),
                "lifetime":   r.get("Lifetime"),
            })

        elif cat == "BASTION_SESSION_ACTIVE":
            findings["active_bastion_sessions"].append({
                "session":    r.get("ResourceName"),
                "target_id":  r.get("AssignedEntityID"),
                "expires":    r.get("TimeExpires"),
                "compartment": r.get("CompartmentName"),
            })

        elif cat == "FSS_PUBLIC_MOUNT_TARGET":
            findings["fss_on_public_subnet"].append({
                "mount_target": r.get("ResourceName"),
                "subnet":       r.get("SubnetName"),
                "private_ip":   r.get("PrivateIP"),
                "compartment":  r.get("CompartmentName"),
            })

        elif cat == "INTERNET_GATEWAY":
            findings["internet_gateways"].append({
                "igw_name":  r.get("ResourceName"),
                "vcn_id":    r.get("AssignedEntityID"),
                "compartment": r.get("CompartmentName"),
            })

        if r.get("CloudGuardRiskLevel"):
            findings["cloud_guard_flagged"].append({
                "resource":    r.get("ResourceName"),
                "type":        r.get("ResourceType"),
                "risk":        r.get("CloudGuardRiskLevel"),
                "rule":        r.get("CloudGuardDetectorRule"),
                "compartment": r.get("CompartmentName"),
            })

    counts = {k: len(v) for k, v in findings.items()}
    total = sum(counts.values())

    # Build a plain-language summary
    lines = []
    if findings["public_buckets"]:
        names = ", ".join(f["bucket"] for f in findings["public_buckets"])
        lines.append(f"⚠️  {len(findings['public_buckets'])} public bucket(s): {names}")
    if findings["active_pars"]:
        lines.append(f"⚠️  {len(findings['active_pars'])} active PAR(s) — check expiry dates")
    if findings["orphan_public_ips"]:
        lines.append(f"💸 {len(findings['orphan_public_ips'])} reserved public IP(s) not assigned to any resource")
    if findings["active_bastion_sessions"]:
        lines.append(f"🔓 {len(findings['active_bastion_sessions'])} active Bastion session(s) — open tunnels to private resources")
    if findings["fss_on_public_subnet"]:
        lines.append(f"⚠️  {len(findings['fss_on_public_subnet'])} FSS mount target(s) on public subnets")
    if findings["internet_gateways"]:
        lines.append(f"🌐 {len(findings['internet_gateways'])} Internet Gateway(s) enabled")
    if findings["cloud_guard_flagged"]:
        lines.append(f"🚨 {len(findings['cloud_guard_flagged'])} resource(s) flagged by Cloud Guard")
    if not lines:
        lines.append("✅ No anomalies detected in the last scan.")

    return {
        "status": "OK",
        "scan_time": _last_scan.get("generated_at_utc", ""),
        "total_anomalies": total,
        "summary": "\n".join(lines),
        "counts": counts,
        "details": findings,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("OCI Perimeter MCP Server starting (stdio transport)")
    mcp.run(transport="stdio")

