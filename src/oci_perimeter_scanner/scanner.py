#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCI Public Perimeter Scanner - Tenant Agnostic Standalone Script
=================================================================

Versione standalone della function OCI di mappatura del perimetro pubblico,
pensata per essere eseguita da una qualsiasi workstation/cloud-shell usando
la configurazione standard di OCI CLI (~/.oci/config).

Cosa rileva:
  - Public IP numerici (RESERVED + EPHEMERAL, per region e per AD)
  - Load Balancer pubblici
  - Network Load Balancer pubblici
  - API Gateway con endpoint non-PRIVATE (+ risoluzione DNS)
  - Autonomous Database senza private endpoint (URL SQL Dev Web, APEX, ecc.)
  - OKE cluster con Kubernetes API pubblico
  - Object Storage: bucket pubblici + Pre-Authenticated Request attive
  - Compute con secondary VNIC dotata di Public IP
  - DB System (DBCS) con nodi dotati di Public IP
  - FSS Mount Target esposti su subnet pubblica
  - DRG Attachment di tipo IPSEC/REMOTE_PEERING (perimetro di interconnessione)
  - Service Gateway (inventario perimetro egress managed)
  - Cloud Guard problems filtrati e correlati alle risorse trovate

Output:
  - CSV completo
  - JSON di summary
  - Opzionale: report HTML
  - Opzionale: invio via SMTP

Uso tipico:
  python3 oci_public_perimeter_scan.py --profile DEFAULT
  python3 oci_public_perimeter_scan.py --profile MIOPROFILO --region eu-frankfurt-1
  python3 oci_public_perimeter_scan.py --config-file ~/.oci/config --all-regions
  python3 oci_public_perimeter_scan.py --profile DEFAULT --compartment-id ocid1.compartment.oc1..xxx
  python3 oci_public_perimeter_scan.py --profile DEFAULT --output-dir ./reports --html
"""

import argparse
import csv
import html
import io
import ipaddress
import json
import logging
import os
import smtplib
import socket
import sys
from datetime import datetime, timezone
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import oci
    from oci.pagination import list_call_get_all_results
except ImportError:
    print("ERROR: pacchetto 'oci' non installato. Esegui: pip install oci", file=sys.stderr)
    sys.exit(2)


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

log = logging.getLogger("oci_perimeter")


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )


def log_json(level: int, event: str, **kw: Any) -> None:
    log.log(level, json.dumps({"event": event, **kw}, ensure_ascii=False, default=str))


# ----------------------------------------------------------------------------
# Schema record output
# ----------------------------------------------------------------------------

FIELDS = [
    "ExposureCategory", "ExposureStatus", "PublicIP", "Endpoint", "Region", "CompartmentName",
    "ResourceType", "ResourceName", "Lifetime", "Scope", "LifecycleState", "AssignedEntityType",
    "PrivateIP", "VnicID", "SubnetName", "AvailabilityDomain", "PublicIpDisplayName", "PublicIpOCID",
    "AssignedEntityID", "BucketName", "ObjectName", "AccessType", "TimeExpires", "TimeCreated",
    "Source", "CloudGuardRiskLevel", "CloudGuardDetectorRule", "CloudGuardProblemId", "Note"
]

LABELS = {
    "ExposureCategory": "Categoria",
    "ExposureStatus": "Stato",
    "PublicIP": "IP pubblico",
    "Endpoint": "Endpoint/URL",
    "Region": "Region",
    "CompartmentName": "Compartment",
    "ResourceType": "Tipo risorsa",
    "ResourceName": "Nome risorsa",
    "BucketName": "Bucket",
    "ObjectName": "Oggetto/prefix",
    "AccessType": "Accesso",
    "CloudGuardRiskLevel": "Cloud Guard",
    "CloudGuardDetectorRule": "Regola Cloud Guard",
    "Source": "Sorgente",
    "Note": "Note",
}

FRIENDLY = {
    "PUBLIC_IP_NUMERIC": "IP pubblico numerico",
    "LOAD_BALANCER_PUBLIC_IP": "Load Balancer pubblico",
    "NETWORK_LOAD_BALANCER_PUBLIC_IP": "Network Load Balancer pubblico",
    "MANAGED_SERVICE_DNS_IP": "Endpoint managed pubblico risolto DNS",
    "MANAGED_SERVICE_PUBLIC_ENDPOINT": "Endpoint managed pubblico",
    "OBJECT_STORAGE_PUBLIC_BUCKET": "Bucket Object Storage pubblico",
    "OBJECT_STORAGE_PRE_AUTHENTICATED_REQUEST": "PAR Object Storage attiva",
    "CLOUD_GUARD_PUBLIC_EXPOSURE": "Segnalazione Cloud Guard - esposizione pubblica",
    "DBCS_PUBLIC_NODE": "DB System con nodo pubblico",
    "FSS_PUBLIC_MOUNT_TARGET": "FSS Mount Target su subnet pubblica",
    "DRG_ATTACHMENT_EXTERNAL": "DRG Attachment esterno",
    "SERVICE_GATEWAY_INVENTORY": "Service Gateway (inventario)",
    "COMPUTE_SECONDARY_VNIC_PUBLIC_IP": "Compute secondary VNIC con IP pubblico",
    # Nuove categorie
    "INTERNET_GATEWAY": "Internet Gateway abilitato sul VCN",
    "LOCAL_PEERING_GATEWAY": "Local Peering Gateway VCN-to-VCN",
    "MYSQL_PUBLIC_ENDPOINT": "MySQL HeatWave con endpoint pubblico",
    "POSTGRESQL_PUBLIC_ENDPOINT": "PostgreSQL DB System con endpoint pubblico",
    "EXADATA_PUBLIC_NODE": "Exadata Cloud Service con nodo pubblico",
    "CONTAINER_INSTANCE_PUBLIC": "Container Instance con VNIC pubblica",
    "FUNCTION_PUBLIC_INVOKE": "OCI Function con invoke endpoint pubblico",
    "INTEGRATION_PUBLIC_ENDPOINT": "Integration Cloud con endpoint pubblico",
    "ANALYTICS_PUBLIC_ENDPOINT": "Analytics Cloud con endpoint pubblico",
    "DATA_SCIENCE_PUBLIC_NOTEBOOK": "Data Science notebook session pubblica",
    "GOLDEN_GATE_PUBLIC_DEPLOYMENT": "GoldenGate deployment con endpoint pubblico",
    "OPENSEARCH_PUBLIC_CLUSTER": "OpenSearch cluster pubblico",
    "STREAM_PUBLIC_ENDPOINT": "Streaming (Kafka) con endpoint pubblico",
    "BASTION_SESSION_ACTIVE": "Bastion session attiva (porta esposta)",
    "WAF_POLICY_INVENTORY": "WAF Policy (inventario)",
    "HEALTH_CHECK_PROBE_PUBLIC": "Health Check probe verso target pubblico",
    "VSS_PUBLIC_TARGET": "Vulnerability Scanning target pubblico",
    "BIG_DATA_PUBLIC_CLUSTER": "Big Data Service cluster con scan public",
}


# ----------------------------------------------------------------------------
# Lista categorie "sempre pubbliche per design"
# Servizi managed che hanno un endpoint regionale pubblico autenticato.
# Vengono inclusi solo se richiesto esplicitamente via opzione.
# ----------------------------------------------------------------------------

ALWAYS_PUBLIC_CATEGORIES = {
    "FUNCTION_PUBLIC_INVOKE",      # Functions API gateway è sempre regionale
    "STREAM_PUBLIC_ENDPOINT",      # Streaming bootstrap regionale
}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def g(o: Any, a: str, default: Any = "") -> Any:
    """Get attribute/key safely, returning default if missing or None."""
    try:
        v = o.get(a, default) if isinstance(o, dict) else getattr(o, a, default)
        return default if v is None else v
    except Exception:
        return default


def dt(v: Any) -> str:
    if not v:
        return ""
    try:
        if isinstance(v, str):
            return v
        return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(v)


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def ts_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def is_public_ip(v: Any) -> bool:
    try:
        ip = ipaddress.ip_address(v)
        return ip.version == 4 and ip.is_global
    except Exception:
        return False


def is_expired(v: Any) -> bool:
    if not v:
        return False
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00")) if isinstance(v, str) else v
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc) < datetime.now(timezone.utc)
    except Exception:
        return False


def endpoint_host(e: str) -> str:
    e = (e or "").strip()
    if not e:
        return ""
    if "://" not in e:
        e = "https://" + e
    return urlparse(e).hostname or ""


def endpoint_norm(e: str) -> str:
    e = (e or "").strip()
    return e if "://" in e or not e else "https://" + e


def err_ctx(operation: str, exc: Exception, **ctx: Any) -> Dict[str, Any]:
    return {
        "operation": operation,
        "region": ctx.get("region", ""),
        "compartment": ctx.get("compartment", ""),
        "scope": ctx.get("scope", ""),
        "lifetime": ctx.get("lifetime", ""),
        "availability_domain": ctx.get("availability_domain", ""),
        "endpoint": ctx.get("endpoint", ""),
        "bucket": ctx.get("bucket", ""),
        "status": getattr(exc, "status", ""),
        "code": getattr(exc, "code", ""),
        "message": getattr(exc, "message", str(exc)),
        "opc_request_id": getattr(exc, "opc_request_id", ""),
    }


def list_all_paged(fn, *args, **kw):
    """
    Generic pagination helper for OCI list APIs that use opc-next-page.

    - Throttling proattivo: pausa configurabile tra chiamate API
      (variabile globale _API_THROTTLE_MS, default 50ms).
    - Retry su 429 (TooManyRequests) e 503 (ServiceUnavailable) con backoff
      esponenziale. Max 5 retry: 1s, 2s, 4s, 8s, 16s.
    """
    import time
    max_retries = 5
    out, page = [], None
    while True:
        k = dict(kw)
        if page:
            k["page"] = page

        # Retry loop sulla singola chiamata
        attempt = 0
        while True:
            # Throttle proattivo
            throttle = globals().get("_API_THROTTLE_MS", 50)
            if throttle > 0:
                time.sleep(throttle / 1000.0)
            try:
                r = fn(*args, **k)
                break
            except Exception as exc:
                status = getattr(exc, "status", None)
                if status in (429, 503) and attempt < max_retries:
                    delay = 2 ** attempt
                    log_json(
                        logging.WARNING,
                        "API_RATE_LIMIT_BACKOFF",
                        operation=getattr(fn, "__name__", "list_call"),
                        status=status,
                        attempt=attempt + 1,
                        sleep_seconds=delay,
                    )
                    time.sleep(delay)
                    attempt += 1
                    continue
                # Errore non-retriabile o retry esauriti: rilancia
                raise

        d = r.data
        if isinstance(d, list):
            out.extend(d)
        elif hasattr(d, "items") and d.items is not None:
            out.extend(d.items)
        elif d is not None:
            out.append(d)
        page = r.headers.get("opc-next-page") if getattr(r, "headers", None) else None
        if not page:
            return out


# Throttle globale, impostato da main() in base a --api-throttle-ms
_API_THROTTLE_MS = 50


# ----------------------------------------------------------------------------
# Row management + dedup
# ----------------------------------------------------------------------------

def row(**kw: Any) -> Dict[str, str]:
    r = {f: "" for f in FIELDS}
    r.update({k: "" if v is None else str(v) for k, v in kw.items() if k in r})
    return r


def merge_pipe(a: str, c: str, sep: str = "|") -> str:
    return sep.join(sorted({x for x in (str(a or "") + sep + str(c or "")).split(sep) if x}))


def rec_key(r: Dict[str, str]) -> str:
    if r.get("PublicIP"):
        return "IP:" + r["PublicIP"]
    return "NOIP:" + "|".join([
        r.get("ExposureCategory", ""),
        r.get("Region", ""),
        r.get("CompartmentName", ""),
        r.get("ResourceType", ""),
        r.get("ResourceName", ""),
        r.get("Endpoint", ""),
        r.get("BucketName", ""),
        r.get("ObjectName", ""),
        r.get("AccessType", ""),
    ])


PREFER_RESOURCE_TYPES = [
    "LOAD_BALANCER",
    "NETWORK_LOAD_BALANCER",
    "API_GATEWAY_PUBLIC_ENDPOINT",
    "AUTONOMOUS_DATABASE_PUBLIC_ENDPOINT",
    "OKE_PUBLIC_API_ENDPOINT",
    "DBCS_PUBLIC_NODE",
    "COMPUTE/VNIC",
    "COMPUTE_SECONDARY_VNIC",
    "NAT_GATEWAY",
]


def add_row(rows: Dict[str, Dict[str, str]], r: Dict[str, str]) -> None:
    if r.get("PublicIP") and not is_public_ip(r["PublicIP"]):
        return
    k = rec_key(r)
    old = rows.get(k)
    if not old:
        rows[k] = r
        return
    old["Source"] = merge_pipe(old.get("Source"), r.get("Source"))
    old["ExposureCategory"] = merge_pipe(old.get("ExposureCategory"), r.get("ExposureCategory"))
    for f in FIELDS:
        if not old.get(f) and r.get(f):
            old[f] = r[f]
    for f in ["CloudGuardRiskLevel", "CloudGuardDetectorRule", "CloudGuardProblemId"]:
        if r.get(f):
            old[f] = merge_pipe(old.get(f), r.get(f))
    if r.get("ResourceType") in PREFER_RESOURCE_TYPES and old.get("ResourceType") not in PREFER_RESOURCE_TYPES:
        for f in ["ResourceType", "ResourceName", "AssignedEntityType", "AssignedEntityID", "Endpoint", "SubnetName"]:
            if r.get(f):
                old[f] = r[f]
    if "deduplicato" not in old.get("Note", ""):
        old["Note"] = (old.get("Note", "") + " | Record deduplicato su più sorgenti").strip(" |")


# ----------------------------------------------------------------------------
# Auth + Clients
# ----------------------------------------------------------------------------

def build_auth(args: argparse.Namespace) -> Tuple[Dict[str, Any], Optional[Any], str]:
    """
    Returns (config_dict, signer_or_None, tenancy_id).
    Supports: config file profile, instance principal, resource principal.
    """
    if args.auth == "instance_principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        return {}, signer, signer.tenancy_id
    if args.auth == "resource_principal":
        signer = oci.auth.signers.get_resource_principals_signer()
        return {}, signer, signer.tenancy_id
    # default: config file
    config_path = os.path.expanduser(args.config_file)
    config = oci.config.from_file(file_location=config_path, profile_name=args.profile)
    oci.config.validate_config(config)
    tenancy_id = config["tenancy"]
    return config, None, tenancy_id


def mk_client(builder, config: Dict[str, Any], signer: Optional[Any], region: Optional[str] = None):
    try:
        if signer is not None:
            c = builder(config or {}, signer=signer)
        else:
            c = builder(config)
        if region:
            c.base_client.set_region(region)
        return c
    except Exception as exc:
        log_json(logging.WARNING, "CLIENT_INIT_WARNING", client=builder.__name__, message=str(exc))
        return None


def mk_clients(config: Dict[str, Any], signer: Optional[Any], region: Optional[str] = None) -> Dict[str, Any]:
    """
    Inizializza TUTTI i client OCI necessari per la scansione del perimetro pubblico.
    Ogni client che fallisce viene loggato come WARNING e impostato a None: lo
    scanner che lo userà semplicemente salterà la sua categoria.
    """
    return {
        # Core
        "identity": mk_client(oci.identity.IdentityClient, config, signer, region),
        "network": mk_client(oci.core.VirtualNetworkClient, config, signer, region),
        "compute": mk_client(oci.core.ComputeClient, config, signer, region),
        # Networking advanced
        "lb": mk_client(oci.load_balancer.LoadBalancerClient, config, signer, region),
        "nlb": mk_client(oci.network_load_balancer.NetworkLoadBalancerClient, config, signer, region),
        "waf": mk_client(oci.waf.WafClient, config, signer, region),
        "healthchecks": mk_client(oci.healthchecks.HealthChecksClient, config, signer, region),
        # Database family
        "database": mk_client(oci.database.DatabaseClient, config, signer, region),
        "mysql": mk_client(oci.mysql.DbSystemClient, config, signer, region),
        "nosql": mk_client(oci.nosql.NosqlClient, config, signer, region),
        "psql": mk_client(oci.psql.PostgresqlClient, config, signer, region),
        # Storage
        "object_storage": mk_client(oci.object_storage.ObjectStorageClient, config, signer, region),
        "fss": mk_client(oci.file_storage.FileStorageClient, config, signer, region),
        # Containers & serverless
        "oke": mk_client(oci.container_engine.ContainerEngineClient, config, signer, region),
        "container_instances": mk_client(oci.container_instances.ContainerInstanceClient, config, signer, region),
        "functions": mk_client(oci.functions.FunctionsManagementClient, config, signer, region),
        # API & integration
        "apigw": mk_client(oci.apigateway.GatewayClient, config, signer, region),
        "integration": mk_client(oci.integration.IntegrationInstanceClient, config, signer, region),
        # Analytics & data
        "analytics": mk_client(oci.analytics.AnalyticsClient, config, signer, region),
        "data_science": mk_client(oci.data_science.DataScienceClient, config, signer, region),
        "data_flow": mk_client(oci.data_flow.DataFlowClient, config, signer, region),
        "bds": mk_client(oci.bds.BdsClient, config, signer, region),
        "golden_gate": mk_client(oci.golden_gate.GoldenGateClient, config, signer, region),
        "opensearch": mk_client(oci.opensearch.OpensearchClusterClient, config, signer, region),
        "streaming": mk_client(oci.streaming.StreamAdminClient, config, signer, region),
        # Security
        "cloud_guard": mk_client(oci.cloud_guard.CloudGuardClient, config, signer, region),
        "bastion": mk_client(oci.bastion.BastionClient, config, signer, region),
        "vss": mk_client(oci.vulnerability_scanning.VulnerabilityScanningClient, config, signer, region),
    }


# ----------------------------------------------------------------------------
# Region / compartment discovery
# ----------------------------------------------------------------------------

def list_regions(identity, tenancy_id: str, requested: Optional[str], all_regions: bool) -> List[str]:
    subs = list_call_get_all_results(identity.list_region_subscriptions, tenancy_id).data
    available = sorted({x.region_name for x in subs if g(x, "region_name")})
    if requested:
        return [requested]
    if all_regions:
        return available
    # default: home region
    home = next((x.region_name for x in subs if getattr(x, "is_home_region", False)), None)
    return [home] if home else available[:1]


def list_compartments(identity, tenancy_id: str, requested: Optional[str], include_root: bool
                      ) -> List[Tuple[str, str]]:
    if requested:
        if requested == tenancy_id:
            return [(tenancy_id, "ROOT_TENANCY")]
        c = identity.get_compartment(requested).data
        return [(c.id, c.name)]
    cs = list_call_get_all_results(
        identity.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
        lifecycle_state="ACTIVE",
    ).data
    out = [(c.id, c.name) for c in cs]
    if include_root:
        out.insert(0, (tenancy_id, "ROOT_TENANCY"))
    return out


def list_availability_domains(identity, tenancy_id: str) -> List[str]:
    try:
        return [x.name for x in identity.list_availability_domains(compartment_id=tenancy_id).data if g(x, "name")]
    except Exception:
        return []


# ----------------------------------------------------------------------------
# Enrichment helpers
# ----------------------------------------------------------------------------

def instance_from_vnic(compute, vnic_id: str, compartment_id: str, cache: Dict[str, str]) -> str:
    try:
        atts = list_call_get_all_results(
            compute.list_vnic_attachments,
            compartment_id=compartment_id,
            vnic_id=vnic_id,
        ).data
        if not atts:
            return ""
        iid = g(atts[0], "instance_id")
        if not iid:
            return ""
        if iid not in cache:
            try:
                cache[iid] = compute.get_instance(iid).data.display_name
            except Exception:
                cache[iid] = iid
        return cache[iid]
    except Exception:
        return ""


def public_ip_record(network, compute, pip, region: str, comp: str, cache: Dict[str, Dict]) -> Dict[str, str]:
    atype = g(pip, "assigned_entity_type")
    aid = g(pip, "assigned_entity_id")
    rtype = atype or "UNASSIGNED"
    rname = aid or g(pip, "display_name")
    private_ip = ""
    vnic_id = ""
    subnet = ""
    note = ""

    if atype == "PRIVATE_IP" and aid:
        try:
            priv = cache["priv"].get(aid) or network.get_private_ip(aid).data
            cache["priv"][aid] = priv
            private_ip = g(priv, "ip_address")
            vnic_id = g(priv, "vnic_id")
            rtype = "PRIVATE_IP_ATTACHMENT"
            rname = g(priv, "display_name") or aid
            if vnic_id:
                vnic = cache["vnic"].get(vnic_id) or network.get_vnic(vnic_id).data
                cache["vnic"][vnic_id] = vnic
                sid = g(vnic, "subnet_id")
                if sid:
                    if sid not in cache["subnet"]:
                        try:
                            cache["subnet"][sid] = network.get_subnet(sid).data.display_name
                        except Exception:
                            cache["subnet"][sid] = sid
                    subnet = cache["subnet"][sid]
                # detect primary vs secondary VNIC
                is_primary = g(vnic, "is_primary", True)
                inst = instance_from_vnic(
                    compute,
                    vnic_id,
                    g(priv, "compartment_id", g(pip, "compartment_id")),
                    cache["instance"],
                )
                if inst:
                    rtype = "COMPUTE/VNIC" if is_primary else "COMPUTE_SECONDARY_VNIC"
                    rname = inst
                    if not is_primary:
                        note = (note + " | VNIC secondaria con IP pubblico").strip(" |")
                elif g(vnic, "display_name"):
                    rname = g(vnic, "display_name")
        except Exception as exc:
            note = (note + f" | Errore enrichment PRIVATE_IP: {exc}").strip(" |")
    elif atype == "NAT_GATEWAY" and aid:
        rtype = "NAT_GATEWAY"
        try:
            cache["nat"][aid] = cache["nat"].get(aid) or network.get_nat_gateway(aid).data.display_name
            rname = cache["nat"][aid]
        except Exception as exc:
            note = (note + f" | Errore enrichment NAT_GATEWAY: {exc}").strip(" |")

    return row(
        ExposureCategory="PUBLIC_IP_NUMERIC",
        ExposureStatus=g(pip, "lifecycle_state") or ("ASSIGNED" if aid else "AVAILABLE"),
        PublicIP=g(pip, "ip_address"),
        Region=region,
        CompartmentName=comp,
        ResourceType=rtype,
        ResourceName=rname,
        Lifetime=g(pip, "lifetime"),
        Scope=g(pip, "scope"),
        LifecycleState=g(pip, "lifecycle_state"),
        AssignedEntityType=atype,
        PrivateIP=private_ip,
        VnicID=vnic_id,
        SubnetName=subnet,
        AvailabilityDomain=g(pip, "availability_domain"),
        PublicIpDisplayName=g(pip, "display_name"),
        PublicIpOCID=g(pip, "id"),
        AssignedEntityID=aid,
        TimeCreated=dt(g(pip, "time_created", None)),
        Source="PUBLIC_IP_API",
        Note=note,
    )


# ----------------------------------------------------------------------------
# Scanners
# ----------------------------------------------------------------------------

def scan_public_ips(c, region, comp_id, comp, ad_list, rows, cache, errors):
    calls = [("REGION", "RESERVED", None), ("REGION", "EPHEMERAL", None)]
    calls += [("AVAILABILITY_DOMAIN", "EPHEMERAL", x) for x in ad_list]
    for scope, life, ad in calls:
        try:
            kw = {"lifetime": life}
            if ad:
                kw["availability_domain"] = ad
            pips = list_call_get_all_results(
                c["network"].list_public_ips, scope, comp_id, **kw,
            ).data
            for pip in pips:
                add_row(rows, public_ip_record(c["network"], c["compute"], pip, region, comp, cache))
        except Exception as exc:
            e = err_ctx("list_public_ips", exc, region=region, compartment=comp,
                       scope=scope, lifetime=life, availability_domain=ad or "")
            errors.append(e)
            log_json(logging.ERROR, "SCAN_ERROR", **e)


def scan_load_balancers(lb, region, comp_id, comp, rows, errors):
    if not lb:
        return
    try:
        for x in list_all_paged(lb.list_load_balancers, compartment_id=comp_id):
            for ip in g(x, "ip_addresses", []) or []:
                if g(ip, "is_public", False) and g(ip, "ip_address"):
                    add_row(rows, row(
                        ExposureCategory="LOAD_BALANCER_PUBLIC_IP",
                        ExposureStatus=g(x, "lifecycle_state") or "ACTIVE",
                        PublicIP=g(ip, "ip_address"),
                        Region=region,
                        CompartmentName=comp,
                        ResourceType="LOAD_BALANCER",
                        ResourceName=g(x, "display_name") or g(x, "id"),
                        Scope="REGION",
                        LifecycleState=g(x, "lifecycle_state"),
                        AssignedEntityType="LOAD_BALANCER",
                        SubnetName="|".join(g(x, "subnet_ids", []) or []),
                        AssignedEntityID=g(x, "id"),
                        TimeCreated=dt(g(x, "time_created", None)),
                        Source="LOAD_BALANCER_API",
                        Note="IP rilevato da Load Balancer",
                    ))
    except Exception as exc:
        e = err_ctx("list_load_balancers", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)


def scan_network_load_balancers(nlb, region, comp_id, comp, rows, errors):
    if not nlb:
        return
    try:
        for x in list_all_paged(nlb.list_network_load_balancers, compartment_id=comp_id):
            try:
                x = nlb.get_network_load_balancer(g(x, "id")).data
            except Exception:
                pass
            if g(x, "is_private", False):
                continue
            for ip in g(x, "ip_addresses", []) or []:
                if g(ip, "is_public", False) and g(ip, "ip_address"):
                    add_row(rows, row(
                        ExposureCategory="NETWORK_LOAD_BALANCER_PUBLIC_IP",
                        ExposureStatus=g(x, "lifecycle_state") or "ACTIVE",
                        PublicIP=g(ip, "ip_address"),
                        Region=region,
                        CompartmentName=comp,
                        ResourceType="NETWORK_LOAD_BALANCER",
                        ResourceName=g(x, "display_name") or g(x, "id"),
                        Scope="REGION",
                        LifecycleState=g(x, "lifecycle_state"),
                        AssignedEntityType="NETWORK_LOAD_BALANCER",
                        SubnetName=g(x, "subnet_id"),
                        AssignedEntityID=g(x, "id"),
                        TimeCreated=dt(g(x, "time_created", None)),
                        Source="NETWORK_LOAD_BALANCER_API",
                        Note="IP rilevato da Network Load Balancer",
                    ))
    except Exception as exc:
        e = err_ctx("list_network_load_balancers", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)


def resolve_endpoint_ips(endpoint: str, timeout: float) -> Tuple[List[str], str]:
    host = endpoint_host(endpoint)
    if not host:
        return [], "endpoint vuoto"
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        ips = sorted({r[4][0] for r in socket.getaddrinfo(host, None, socket.AF_INET)})
        pub = [x for x in ips if is_public_ip(x)]
        return pub, "" if pub else "DNS risolto ma senza IPv4 pubblico"
    except Exception as exc:
        return [], str(exc)
    finally:
        socket.setdefaulttimeout(old)


def add_managed_endpoint(rows, region, comp, endpoint, rtype, rname, state, source,
                         rid="", created="", dns_timeout=5.0, include_unresolved=True):
    ep = endpoint_norm(endpoint)
    ips, dns_err = resolve_endpoint_ips(ep, dns_timeout)
    if ips:
        for ip in ips:
            add_row(rows, row(
                ExposureCategory="MANAGED_SERVICE_DNS_IP",
                ExposureStatus="PUBLIC_ENDPOINT_RESOLVED",
                PublicIP=ip,
                Endpoint=ep,
                Region=region,
                CompartmentName=comp,
                ResourceType=rtype,
                ResourceName=rname,
                Lifetime="MANAGED_ENDPOINT",
                Scope="DNS",
                LifecycleState=state,
                AssignedEntityType=rtype,
                AssignedEntityID=rid,
                TimeCreated=created,
                Source=source,
                Note="Endpoint pubblico risolto via DNS",
            ))
    elif include_unresolved:
        add_row(rows, row(
            ExposureCategory="MANAGED_SERVICE_PUBLIC_ENDPOINT",
            ExposureStatus="DNS_NOT_RESOLVED",
            Endpoint=ep,
            Region=region,
            CompartmentName=comp,
            ResourceType=rtype,
            ResourceName=rname,
            Lifetime="MANAGED_ENDPOINT",
            Scope="DNS",
            LifecycleState=state,
            AssignedEntityType=rtype,
            AssignedEntityID=rid,
            TimeCreated=created,
            Source=source,
            Note="Endpoint pubblico trovato ma non risolto in IPv4 pubblico: " + dns_err,
        ))


def scan_api_gateways(apigw, region, comp_id, comp, rows, errors, opts):
    if not apigw:
        return
    try:
        for x in list_all_paged(apigw.list_gateways, compartment_id=comp_id):
            endpoint = g(x, "hostname") or g(x, "endpoint")
            endpoint_type = str(g(x, "endpoint_type", "")).upper()
            if endpoint and endpoint_type != "PRIVATE":
                add_managed_endpoint(
                    rows, region, comp, endpoint,
                    "API_GATEWAY_PUBLIC_ENDPOINT",
                    g(x, "display_name") or g(x, "id"),
                    g(x, "lifecycle_state"),
                    "API_GATEWAY_DNS",
                    g(x, "id"),
                    dt(g(x, "time_created", None)),
                    opts["dns_timeout"], opts["include_unresolved"],
                )
    except Exception as exc:
        e = err_ctx("list_api_gateways", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)


def scan_autonomous_databases(db, region, comp_id, comp, rows, errors, opts):
    if not db:
        return
    try:
        for x in list_all_paged(db.list_autonomous_databases, compartment_id=comp_id):
            if g(x, "private_endpoint") or g(x, "private_endpoint_ip"):
                continue
            conn = g(x, "connection_urls", None)
            endpoints = []
            for a in ["sql_dev_web_url", "apex_url", "database_transforms_url",
                      "graph_studio_url", "machine_learning_user_management_url"]:
                if g(conn, a):
                    endpoints.append(g(conn, a))
            for ep in sorted(set(endpoints)):
                add_managed_endpoint(
                    rows, region, comp, ep,
                    "AUTONOMOUS_DATABASE_PUBLIC_ENDPOINT",
                    g(x, "display_name") or g(x, "db_name") or g(x, "id"),
                    g(x, "lifecycle_state"),
                    "AUTONOMOUS_DATABASE_DNS",
                    g(x, "id"),
                    dt(g(x, "time_created", None)),
                    opts["dns_timeout"], opts["include_unresolved"],
                )
    except Exception as exc:
        e = err_ctx("list_autonomous_databases", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)


def scan_oke_clusters(oke, region, comp_id, comp, rows, errors, opts):
    if not oke:
        return
    try:
        for s in list_all_paged(oke.list_clusters, compartment_id=comp_id):
            x = s
            try:
                x = oke.get_cluster(g(s, "id")).data
            except Exception:
                pass
            ep = g(g(x, "endpoints", None), "kubernetes") or g(g(x, "endpoints", None), "public_endpoint")
            is_public = g(g(x, "endpoint_config", None), "is_public_ip_enabled", None)
            if ep and is_public is not False:
                add_managed_endpoint(
                    rows, region, comp, ep,
                    "OKE_PUBLIC_API_ENDPOINT",
                    g(x, "name") or g(x, "id"),
                    g(x, "lifecycle_state"),
                    "OKE_API_DNS",
                    g(x, "id"),
                    dt(g(x, "time_created", None)),
                    opts["dns_timeout"], opts["include_unresolved"],
                )
    except Exception as exc:
        e = err_ctx("list_oke_clusters", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)


def obj_endpoint(region: str, ns: str, bucket: str) -> str:
    return f"https://objectstorage.{region}.oraclecloud.com/n/{ns}/b/{bucket}/o/"


def scan_object_storage(os_client, ns, region, comp_id, comp, rows, errors, opts):
    if not os_client or not ns:
        return
    try:
        buckets = list_all_paged(os_client.list_buckets, ns, comp_id)
    except Exception as exc:
        e = err_ctx("list_object_storage_buckets", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return

    for buck in buckets:
        name = g(buck, "name")
        if not name:
            continue
        try:
            detail = os_client.get_bucket(ns, name).data
        except Exception:
            detail = buck
        pa = g(detail, "public_access_type") or g(buck, "public_access_type")
        if pa and pa != "NoPublicAccess":
            add_row(rows, row(
                ExposureCategory="OBJECT_STORAGE_PUBLIC_BUCKET",
                ExposureStatus="PUBLIC",
                Endpoint=obj_endpoint(region, ns, name),
                Region=region,
                CompartmentName=comp,
                ResourceType="OBJECT_STORAGE_PUBLIC_BUCKET",
                ResourceName=name,
                LifecycleState="ACTIVE",
                BucketName=name,
                AccessType=pa,
                TimeCreated=dt(g(detail, "time_created", g(buck, "time_created", None))),
                Source="OBJECT_STORAGE_BUCKET_API",
                Note="Bucket con public_access_type diverso da NoPublicAccess",
            ))
        if not opts["scan_par"]:
            continue
        try:
            pars = list_all_paged(os_client.list_preauthenticated_requests, ns, name)
            for p in pars:
                expired = is_expired(g(p, "time_expires", None))
                if expired and not opts["include_expired_par"]:
                    continue
                add_row(rows, row(
                    ExposureCategory="OBJECT_STORAGE_PRE_AUTHENTICATED_REQUEST",
                    ExposureStatus="EXPIRED" if expired else "ACTIVE",
                    Endpoint=obj_endpoint(region, ns, name),
                    Region=region,
                    CompartmentName=comp,
                    ResourceType="OBJECT_STORAGE_PRE_AUTHENTICATED_REQUEST",
                    ResourceName=g(p, "name") or g(p, "id"),
                    BucketName=name,
                    ObjectName=g(p, "object_name"),
                    AccessType=g(p, "access_type"),
                    TimeExpires=dt(g(p, "time_expires", None)),
                    TimeCreated=dt(g(p, "time_created", None)),
                    Source="OBJECT_STORAGE_PAR_API",
                    Note="PAR rilevata. Il token completo non viene riportato nel CSV.",
                ))
        except Exception as exc:
            e = err_ctx("list_object_storage_par", exc, region=region, compartment=comp, bucket=name)
            errors.append(e)
            log_json(logging.ERROR, "SCAN_ERROR", **e)


# ----------------------------------------------------------------------------
# NEW: DBCS - DB System con nodi con Public IP
# ----------------------------------------------------------------------------

def scan_db_systems(db, network, region, comp_id, comp, rows, cache, errors):
    """
    Enumera DB Systems (DBCS) e controlla se i loro DB Nodes hanno una VNIC
    con Public IP. Copre il caso 'Compute Bare Metal/VM dedicato a DB con IP
    pubblico via secondary/primary VNIC' che non viene catturato dagli scan
    Compute classici.
    """
    if not db or not network:
        return
    try:
        systems = list_all_paged(db.list_db_systems, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_db_systems", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return

    for sys_ in systems:
        sys_id = g(sys_, "id")
        sys_name = g(sys_, "display_name") or sys_id
        try:
            nodes = list_all_paged(db.list_db_nodes, compartment_id=comp_id, db_system_id=sys_id)
        except Exception as exc:
            e = err_ctx("list_db_nodes", exc, region=region, compartment=comp)
            errors.append(e)
            log_json(logging.ERROR, "SCAN_ERROR", **e)
            continue
        for n in nodes:
            vnic_id = g(n, "vnic_id")
            if not vnic_id:
                continue
            try:
                vnic = cache["vnic"].get(vnic_id) or network.get_vnic(vnic_id).data
                cache["vnic"][vnic_id] = vnic
            except Exception as exc:
                log_json(logging.WARNING, "DBCS_VNIC_GET_FAIL", vnic=vnic_id, message=str(exc))
                continue
            pub = g(vnic, "public_ip")
            if not pub:
                continue
            sid = g(vnic, "subnet_id")
            subnet_name = ""
            if sid:
                if sid not in cache["subnet"]:
                    try:
                        cache["subnet"][sid] = network.get_subnet(sid).data.display_name
                    except Exception:
                        cache["subnet"][sid] = sid
                subnet_name = cache["subnet"][sid]
            add_row(rows, row(
                ExposureCategory="PUBLIC_IP_NUMERIC",
                ExposureStatus="ASSIGNED",
                PublicIP=pub,
                Region=region,
                CompartmentName=comp,
                ResourceType="DBCS_PUBLIC_NODE",
                ResourceName=f"{sys_name}/{g(n, 'hostname') or g(n, 'id')}",
                Scope="REGION",
                LifecycleState=g(n, "lifecycle_state"),
                AssignedEntityType="DBCS_NODE",
                PrivateIP=g(vnic, "private_ip"),
                VnicID=vnic_id,
                SubnetName=subnet_name,
                AssignedEntityID=sys_id,
                TimeCreated=dt(g(sys_, "time_created", None)),
                Source="DBCS_API",
                Note="DB System node con VNIC pubblica",
            ))


# ----------------------------------------------------------------------------
# NEW: Compute - secondary VNIC con Public IP
# ----------------------------------------------------------------------------

def scan_compute_secondary_vnics(compute, network, region, comp_id, comp, rows, cache, errors):
    """
    Itera le istanze Compute e per ciascuna esamina TUTTE le VNIC (primaria e
    secondarie) cercando public_ip assegnati. Il scan sui Public IP del
    Networking copre solo i PIP gestiti come oggetti OCI; le VNIC secondarie
    con ephemeral IP automatico potrebbero non comparire altrove.
    """
    if not compute or not network:
        return
    try:
        instances = list_all_paged(compute.list_instances, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_instances", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return

    for inst in instances:
        if g(inst, "lifecycle_state") in ("TERMINATED", "TERMINATING"):
            continue
        iid = g(inst, "id")
        iname = g(inst, "display_name") or iid
        try:
            atts = list_all_paged(compute.list_vnic_attachments, compartment_id=comp_id, instance_id=iid)
        except Exception as exc:
            log_json(logging.WARNING, "VNIC_ATTACHMENTS_FAIL", instance=iid, message=str(exc))
            continue
        for att in atts:
            vnic_id = g(att, "vnic_id")
            if not vnic_id:
                continue
            try:
                vnic = cache["vnic"].get(vnic_id) or network.get_vnic(vnic_id).data
                cache["vnic"][vnic_id] = vnic
            except Exception:
                continue
            pub = g(vnic, "public_ip")
            if not pub:
                continue
            is_primary = g(vnic, "is_primary", True)
            sid = g(vnic, "subnet_id")
            subnet_name = ""
            if sid:
                if sid not in cache["subnet"]:
                    try:
                        cache["subnet"][sid] = network.get_subnet(sid).data.display_name
                    except Exception:
                        cache["subnet"][sid] = sid
                subnet_name = cache["subnet"][sid]
            add_row(rows, row(
                ExposureCategory="PUBLIC_IP_NUMERIC",
                ExposureStatus="ASSIGNED",
                PublicIP=pub,
                Region=region,
                CompartmentName=comp,
                ResourceType="COMPUTE/VNIC" if is_primary else "COMPUTE_SECONDARY_VNIC",
                ResourceName=iname,
                Scope="REGION",
                LifecycleState=g(inst, "lifecycle_state"),
                AssignedEntityType="COMPUTE_INSTANCE",
                PrivateIP=g(vnic, "private_ip"),
                VnicID=vnic_id,
                SubnetName=subnet_name,
                AvailabilityDomain=g(inst, "availability_domain"),
                AssignedEntityID=iid,
                TimeCreated=dt(g(inst, "time_created", None)),
                Source="COMPUTE_VNIC_API",
                Note=("VNIC primaria" if is_primary else "VNIC secondaria") + " su istanza Compute",
            ))


# ----------------------------------------------------------------------------
# NEW: FSS Mount Target su subnet pubblica
# ----------------------------------------------------------------------------

def scan_fss_mount_targets(fss, network, identity, region, tenancy_id, comp_id, comp, rows, cache, errors):
    """
    I Mount Target del File Storage Service ricevono un Private IP, ma se la
    subnet è pubblica e c'è una route 0.0.0.0/0 verso Internet Gateway si
    configura un'esposizione raggiungibile. Qui controlliamo se la subnet del
    Mount Target è pubblica (prohibitPublicIpOnVnic=False) e segnaliamo.
    FSS richiede di iterare per AD.
    """
    if not fss or not network or not identity:
        return
    try:
        ads = list_availability_domains(identity, tenancy_id)
    except Exception:
        ads = []
    # list_mount_targets richiede sia compartment_id che availability_domain come positional.
    # Se non riusciamo a recuperare la lista degli AD, saltiamo lo scan FSS per questo compartment.
    if not ads:
        log_json(logging.WARNING, "FSS_SCAN_SKIPPED_NO_ADS", region=region, compartment=comp)
        return
    for ad in ads:
        try:
            mts = list_all_paged(fss.list_mount_targets, comp_id, ad)
        except Exception as exc:
            e = err_ctx("list_mount_targets", exc, region=region, compartment=comp, availability_domain=ad)
            errors.append(e)
            log_json(logging.ERROR, "SCAN_ERROR", **e)
            continue
        for mt in mts:
            sid = g(mt, "subnet_id")
            if not sid:
                continue
            try:
                if sid not in cache.get("subnet_obj", {}):
                    cache.setdefault("subnet_obj", {})[sid] = network.get_subnet(sid).data
                subnet = cache["subnet_obj"][sid]
            except Exception:
                continue
            # subnet pubblica = prohibit_public_ip_on_vnic == False
            prohibit = g(subnet, "prohibit_public_ip_on_vnic", True)
            if prohibit:
                continue
            subnet_name = g(subnet, "display_name") or sid
            private_ip = ""
            ip_ids = g(mt, "private_ip_ids", []) or []
            if ip_ids:
                try:
                    priv = network.get_private_ip(ip_ids[0]).data
                    private_ip = g(priv, "ip_address")
                except Exception:
                    pass
            add_row(rows, row(
                ExposureCategory="FSS_PUBLIC_MOUNT_TARGET",
                ExposureStatus="ON_PUBLIC_SUBNET",
                Endpoint=f"nfs://{private_ip}/" if private_ip else "",
                Region=region,
                CompartmentName=comp,
                ResourceType="FSS_MOUNT_TARGET",
                ResourceName=g(mt, "display_name") or g(mt, "id"),
                LifecycleState=g(mt, "lifecycle_state"),
                AvailabilityDomain=g(mt, "availability_domain"),
                PrivateIP=private_ip,
                SubnetName=subnet_name,
                AssignedEntityID=g(mt, "id"),
                TimeCreated=dt(g(mt, "time_created", None)),
                Source="FSS_API",
                Note="Mount Target su subnet pubblica - verificare route/security rules verso Internet",
            ))


# ----------------------------------------------------------------------------
# NEW: DRG Attachments (perimetro di interconnessione)
# ----------------------------------------------------------------------------

def scan_drg_attachments(network, region, comp_id, comp, rows, errors):
    """
    I DRG Attachment di tipo IPSEC o REMOTE_PEERING_CONNECTION costituiscono
    un perimetro di esposizione verso reti esterne (on-prem o altre region/
    tenancy). Li elenchiamo per inventario di sicurezza.
    """
    if not network:
        return
    try:
        drgs = list_all_paged(network.list_drgs, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_drgs", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for drg in drgs:
        drg_id = g(drg, "id")
        try:
            atts = list_all_paged(network.list_drg_attachments, compartment_id=comp_id, drg_id=drg_id)
        except Exception as exc:
            e = err_ctx("list_drg_attachments", exc, region=region, compartment=comp)
            errors.append(e)
            log_json(logging.ERROR, "SCAN_ERROR", **e)
            continue
        for att in atts:
            att_type = str(g(att, "attachment_type", "")).upper()
            if att_type not in {"IPSEC_TUNNEL", "REMOTE_PEERING_CONNECTION", "VIRTUAL_CIRCUIT"}:
                continue
            add_row(rows, row(
                ExposureCategory="DRG_ATTACHMENT_EXTERNAL",
                ExposureStatus=g(att, "lifecycle_state") or "ACTIVE",
                Region=region,
                CompartmentName=comp,
                ResourceType=f"DRG_ATTACHMENT_{att_type}",
                ResourceName=g(att, "display_name") or g(att, "id"),
                LifecycleState=g(att, "lifecycle_state"),
                AssignedEntityType="DRG",
                AssignedEntityID=g(att, "id"),
                TimeCreated=dt(g(att, "time_created", None)),
                Source="DRG_API",
                Note=f"DRG attachment di tipo {att_type} (perimetro di interconnessione esterno)",
            ))


# ----------------------------------------------------------------------------
# NEW: Service Gateway (inventario perimetro egress managed)
# ----------------------------------------------------------------------------

def scan_service_gateways(network, region, comp_id, comp, rows, errors):
    """
    I Service Gateway permettono traffico privato verso OCI services. Non sono
    esposizioni pubbliche in senso stretto, ma sono parte del perimetro di
    egress controllato e meritano inventario.
    """
    if not network:
        return
    try:
        sgws = list_all_paged(network.list_service_gateways, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_service_gateways", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for sgw in sgws:
        services = g(sgw, "services", []) or []
        svc_names = [g(s, "service_name") for s in services if g(s, "service_name")]
        add_row(rows, row(
            ExposureCategory="SERVICE_GATEWAY_INVENTORY",
            ExposureStatus=g(sgw, "lifecycle_state") or "AVAILABLE",
            Region=region,
            CompartmentName=comp,
            ResourceType="SERVICE_GATEWAY",
            ResourceName=g(sgw, "display_name") or g(sgw, "id"),
            LifecycleState=g(sgw, "lifecycle_state"),
            AssignedEntityID=g(sgw, "id"),
            TimeCreated=dt(g(sgw, "time_created", None)),
            Source="SERVICE_GATEWAY_API",
            Note="Service Gateway abilitato per: " + (", ".join(svc_names) or "n/a"),
        ))


# ----------------------------------------------------------------------------
# NEW: Internet Gateway (presenza = perimetro Internet aperto)
# ----------------------------------------------------------------------------

def scan_internet_gateways(network, region, comp_id, comp, rows, errors):
    if not network:
        return
    try:
        igws = list_all_paged(network.list_internet_gateways, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_internet_gateways", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for igw in igws:
        if not g(igw, "is_enabled", True):
            continue
        add_row(rows, row(
            ExposureCategory="INTERNET_GATEWAY",
            ExposureStatus="ENABLED" if g(igw, "is_enabled", True) else "DISABLED",
            Region=region,
            CompartmentName=comp,
            ResourceType="INTERNET_GATEWAY",
            ResourceName=g(igw, "display_name") or g(igw, "id"),
            LifecycleState=g(igw, "lifecycle_state"),
            AssignedEntityType="VCN",
            AssignedEntityID=g(igw, "vcn_id"),
            TimeCreated=dt(g(igw, "time_created", None)),
            Source="INTERNET_GATEWAY_API",
            Note="Internet Gateway abilitato sul VCN: traffico bidirezionale verso Internet",
        ))


# ----------------------------------------------------------------------------
# NEW: Local Peering Gateway (interconnessione VCN-to-VCN)
# ----------------------------------------------------------------------------

def scan_local_peering_gateways(network, region, comp_id, comp, rows, errors):
    if not network:
        return
    try:
        lpgs = list_all_paged(network.list_local_peering_gateways, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_local_peering_gateways", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for lpg in lpgs:
        if g(lpg, "peering_status") != "PEERED":
            continue
        add_row(rows, row(
            ExposureCategory="LOCAL_PEERING_GATEWAY",
            ExposureStatus=g(lpg, "peering_status") or "AVAILABLE",
            Region=region,
            CompartmentName=comp,
            ResourceType="LOCAL_PEERING_GATEWAY",
            ResourceName=g(lpg, "display_name") or g(lpg, "id"),
            LifecycleState=g(lpg, "lifecycle_state"),
            AssignedEntityType="VCN",
            AssignedEntityID=g(lpg, "vcn_id"),
            TimeCreated=dt(g(lpg, "time_created", None)),
            Source="LPG_API",
            Note=f"LPG peered con peer: {g(lpg, 'peer_id', 'n/a')}",
        ))


# ----------------------------------------------------------------------------
# NEW: MySQL HeatWave DB System con endpoint pubblico
# ----------------------------------------------------------------------------

def scan_mysql_db_systems(mysql, network, region, comp_id, comp, rows, cache, errors):
    if not mysql:
        return
    try:
        systems = list_all_paged(mysql.list_db_systems, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_mysql_db_systems", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for s in systems:
        # MySQL DB System assegna sempre un IP nella subnet del VCN.
        # Se la subnet è pubblica (prohibit_public_ip_on_vnic=False), va segnalato.
        sid = g(s, "subnet_id")
        if not sid or not network:
            continue
        try:
            if sid not in cache.get("subnet_obj", {}):
                cache.setdefault("subnet_obj", {})[sid] = network.get_subnet(sid).data
            subnet = cache["subnet_obj"][sid]
        except Exception:
            continue
        if g(subnet, "prohibit_public_ip_on_vnic", True):
            continue
        endpoints = g(s, "endpoints", []) or []
        ip_addr = ""
        port = ""
        for ep in endpoints:
            if g(ep, "ip_address"):
                ip_addr = g(ep, "ip_address")
                port = g(ep, "port")
                break
        add_row(rows, row(
            ExposureCategory="MYSQL_PUBLIC_ENDPOINT",
            ExposureStatus=g(s, "lifecycle_state") or "ACTIVE",
            Endpoint=f"mysql://{ip_addr}:{port}/" if ip_addr else "",
            Region=region,
            CompartmentName=comp,
            ResourceType="MYSQL_DB_SYSTEM",
            ResourceName=g(s, "display_name") or g(s, "id"),
            LifecycleState=g(s, "lifecycle_state"),
            PrivateIP=ip_addr,
            SubnetName=g(subnet, "display_name"),
            AvailabilityDomain=g(s, "availability_domain"),
            AssignedEntityID=g(s, "id"),
            TimeCreated=dt(g(s, "time_created", None)),
            Source="MYSQL_API",
            Note="MySQL DB System su subnet pubblica - verificare security list/NSG",
        ))


# ----------------------------------------------------------------------------
# NEW: PostgreSQL DB System (managed) con endpoint pubblico
# ----------------------------------------------------------------------------

def scan_postgresql_db_systems(psql, network, region, comp_id, comp, rows, cache, errors):
    if not psql:
        return
    try:
        systems = list_all_paged(psql.list_db_systems, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_postgresql_db_systems", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for s in systems:
        net_details = g(s, "network_details", None)
        sid = g(net_details, "subnet_id") if net_details else g(s, "subnet_id")
        if not sid or not network:
            continue
        try:
            if sid not in cache.get("subnet_obj", {}):
                cache.setdefault("subnet_obj", {})[sid] = network.get_subnet(sid).data
            subnet = cache["subnet_obj"][sid]
        except Exception:
            continue
        if g(subnet, "prohibit_public_ip_on_vnic", True):
            continue
        add_row(rows, row(
            ExposureCategory="POSTGRESQL_PUBLIC_ENDPOINT",
            ExposureStatus=g(s, "lifecycle_state") or "ACTIVE",
            Region=region,
            CompartmentName=comp,
            ResourceType="POSTGRESQL_DB_SYSTEM",
            ResourceName=g(s, "display_name") or g(s, "id"),
            LifecycleState=g(s, "lifecycle_state"),
            SubnetName=g(subnet, "display_name"),
            AssignedEntityID=g(s, "id"),
            TimeCreated=dt(g(s, "time_created", None)),
            Source="POSTGRESQL_API",
            Note="PostgreSQL DB System managed su subnet pubblica",
        ))


# ----------------------------------------------------------------------------
# NEW: Container Instances con VNIC pubbliche
# ----------------------------------------------------------------------------

def scan_container_instances(ci, network, region, comp_id, comp, rows, cache, errors):
    if not ci:
        return
    try:
        items = list_all_paged(ci.list_container_instances, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_container_instances", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for inst in items:
        if g(inst, "lifecycle_state") in ("DELETED", "DELETING"):
            continue
        vnics = g(inst, "vnics", []) or []
        for v in vnics:
            vnic_id = g(v, "vnic_id")
            if not vnic_id or not network:
                continue
            try:
                vnic = cache["vnic"].get(vnic_id) or network.get_vnic(vnic_id).data
                cache["vnic"][vnic_id] = vnic
            except Exception:
                continue
            pub = g(vnic, "public_ip")
            if not pub:
                continue
            add_row(rows, row(
                ExposureCategory="CONTAINER_INSTANCE_PUBLIC",
                ExposureStatus=g(inst, "lifecycle_state") or "ACTIVE",
                PublicIP=pub,
                Region=region,
                CompartmentName=comp,
                ResourceType="CONTAINER_INSTANCE",
                ResourceName=g(inst, "display_name") or g(inst, "id"),
                LifecycleState=g(inst, "lifecycle_state"),
                PrivateIP=g(vnic, "private_ip"),
                VnicID=vnic_id,
                AvailabilityDomain=g(inst, "availability_domain"),
                AssignedEntityID=g(inst, "id"),
                TimeCreated=dt(g(inst, "time_created", None)),
                Source="CONTAINER_INSTANCES_API",
                Note="Container Instance con VNIC pubblica",
            ))


# ----------------------------------------------------------------------------
# NEW: OCI Functions invoke endpoint (managed, sempre regionale pubblico)
# ----------------------------------------------------------------------------

def scan_functions(funcs, region, comp_id, comp, rows, errors, opts):
    if not funcs:
        return
    try:
        apps = list_all_paged(funcs.list_applications, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_function_applications", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for app in apps:
        try:
            fns = list_all_paged(funcs.list_functions, application_id=g(app, "id"))
        except Exception:
            continue
        for fn in fns:
            invoke = g(fn, "invoke_endpoint")
            if not invoke:
                continue
            add_managed_endpoint(
                rows, region, comp, invoke,
                "OCI_FUNCTION",
                f"{g(app, 'display_name')}/{g(fn, 'display_name')}",
                g(fn, "lifecycle_state"),
                "OCI_FUNCTIONS_DNS",
                g(fn, "id"),
                dt(g(fn, "time_created", None)),
                opts["dns_timeout"], opts["include_unresolved"],
            )


# ----------------------------------------------------------------------------
# NEW: Integration Cloud (OIC)
# ----------------------------------------------------------------------------

def scan_integration_instances(integ, region, comp_id, comp, rows, errors, opts):
    if not integ:
        return
    try:
        items = list_all_paged(integ.list_integration_instances, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_integration_instances", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for inst in items:
        # Le istanze OIC hanno sempre un endpoint pubblico, a meno che non siano
        # in un private endpoint. Verifichiamo network_endpoint_details.
        ned = g(inst, "network_endpoint_details", None)
        if ned and g(ned, "network_endpoint_type") == "PRIVATE":
            continue
        url = g(inst, "instance_url")
        if not url:
            continue
        add_managed_endpoint(
            rows, region, comp, url,
            "INTEGRATION_INSTANCE",
            g(inst, "display_name") or g(inst, "id"),
            g(inst, "lifecycle_state"),
            "INTEGRATION_DNS",
            g(inst, "id"),
            dt(g(inst, "time_created", None)),
            opts["dns_timeout"], opts["include_unresolved"],
        )


# ----------------------------------------------------------------------------
# NEW: Analytics Cloud (OAC)
# ----------------------------------------------------------------------------

def scan_analytics_instances(an, region, comp_id, comp, rows, errors, opts):
    if not an:
        return
    try:
        items = list_all_paged(an.list_analytics_instances, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_analytics_instances", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for inst in items:
        ned = g(inst, "network_endpoint_details", None)
        if ned and g(ned, "network_endpoint_type") != "PUBLIC":
            continue
        url = g(inst, "service_url") or g(inst, "url")
        if not url:
            continue
        add_managed_endpoint(
            rows, region, comp, url,
            "ANALYTICS_INSTANCE",
            g(inst, "name") or g(inst, "id"),
            g(inst, "lifecycle_state"),
            "ANALYTICS_DNS",
            g(inst, "id"),
            dt(g(inst, "time_created", None)),
            opts["dns_timeout"], opts["include_unresolved"],
        )


# ----------------------------------------------------------------------------
# NEW: Data Science notebook sessions pubbliche
# ----------------------------------------------------------------------------

def scan_data_science_notebooks(ds, region, comp_id, comp, rows, errors):
    if not ds:
        return
    try:
        items = list_all_paged(ds.list_notebook_sessions, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_data_science_notebooks", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for nb in items:
        config_details = g(nb, "notebook_session_config_details", None)
        # Se non c'è private endpoint configurato, la sessione ha URL pubblico
        if config_details and g(config_details, "private_endpoint_id"):
            continue
        url = g(nb, "notebook_session_url")
        if not url:
            continue
        add_row(rows, row(
            ExposureCategory="DATA_SCIENCE_PUBLIC_NOTEBOOK",
            ExposureStatus=g(nb, "lifecycle_state") or "ACTIVE",
            Endpoint=url,
            Region=region,
            CompartmentName=comp,
            ResourceType="DATA_SCIENCE_NOTEBOOK",
            ResourceName=g(nb, "display_name") or g(nb, "id"),
            LifecycleState=g(nb, "lifecycle_state"),
            AssignedEntityID=g(nb, "id"),
            TimeCreated=dt(g(nb, "time_created", None)),
            Source="DATA_SCIENCE_API",
            Note="Data Science notebook senza private endpoint",
        ))


# ----------------------------------------------------------------------------
# NEW: GoldenGate deployments con endpoint pubblico
# ----------------------------------------------------------------------------

def scan_golden_gate(gg, region, comp_id, comp, rows, errors, opts):
    if not gg:
        return
    try:
        items = list_all_paged(gg.list_deployments, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_golden_gate_deployments", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for d in items:
        if not g(d, "is_public", False):
            continue
        url = g(d, "public_url") or g(d, "private_url")
        add_managed_endpoint(
            rows, region, comp, url or "",
            "GOLDEN_GATE_DEPLOYMENT",
            g(d, "display_name") or g(d, "id"),
            g(d, "lifecycle_state"),
            "GOLDEN_GATE_DNS",
            g(d, "id"),
            dt(g(d, "time_created", None)),
            opts["dns_timeout"], opts["include_unresolved"],
        )


# ----------------------------------------------------------------------------
# NEW: OpenSearch cluster pubblici
# ----------------------------------------------------------------------------

def scan_opensearch_clusters(os_c, network, region, comp_id, comp, rows, cache, errors):
    if not os_c:
        return
    try:
        items = list_all_paged(os_c.list_opensearch_clusters, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_opensearch_clusters", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for cl in items:
        sid = g(cl, "subnet_id")
        if not sid or not network:
            continue
        try:
            if sid not in cache.get("subnet_obj", {}):
                cache.setdefault("subnet_obj", {})[sid] = network.get_subnet(sid).data
            subnet = cache["subnet_obj"][sid]
        except Exception:
            continue
        if g(subnet, "prohibit_public_ip_on_vnic", True):
            continue
        add_row(rows, row(
            ExposureCategory="OPENSEARCH_PUBLIC_CLUSTER",
            ExposureStatus=g(cl, "lifecycle_state") or "ACTIVE",
            Region=region,
            CompartmentName=comp,
            ResourceType="OPENSEARCH_CLUSTER",
            ResourceName=g(cl, "display_name") or g(cl, "id"),
            LifecycleState=g(cl, "lifecycle_state"),
            SubnetName=g(subnet, "display_name"),
            AssignedEntityID=g(cl, "id"),
            TimeCreated=dt(g(cl, "time_created", None)),
            Source="OPENSEARCH_API",
            Note="OpenSearch cluster su subnet pubblica",
        ))


# ----------------------------------------------------------------------------
# NEW: Streaming (Kafka-compatible) endpoint
# ----------------------------------------------------------------------------

def scan_streaming(stream, region, comp_id, comp, rows, errors, opts):
    if not stream:
        return
    try:
        items = list_all_paged(stream.list_streams, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_streams", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for s in items:
        # Streaming è regionale pubblico per design (auth-protected via IAM).
        # Lo includiamo solo se opts richiede di mostrare "always public".
        if not opts.get("include_always_public"):
            continue
        endpoint = g(s, "messages_endpoint")
        if not endpoint:
            continue
        add_managed_endpoint(
            rows, region, comp, endpoint,
            "STREAM",
            g(s, "name") or g(s, "id"),
            g(s, "lifecycle_state"),
            "STREAMING_DNS",
            g(s, "id"),
            dt(g(s, "time_created", None)),
            opts["dns_timeout"], opts["include_unresolved"],
        )


# ----------------------------------------------------------------------------
# NEW: Bastion sessions attive (porta esposta verso target privato)
# ----------------------------------------------------------------------------

def scan_bastions(bast, region, comp_id, comp, rows, errors):
    if not bast:
        return
    try:
        bastions = list_all_paged(bast.list_bastions, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_bastions", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for b in bastions:
        bid = g(b, "id")
        try:
            sessions = list_all_paged(bast.list_sessions, bastion_id=bid)
        except Exception:
            continue
        for s in sessions:
            if g(s, "lifecycle_state") != "ACTIVE":
                continue
            target = g(s, "target_resource_details", None)
            target_resource = g(target, "target_resource_id") if target else ""
            target_port = g(target, "target_resource_port") if target else ""
            add_row(rows, row(
                ExposureCategory="BASTION_SESSION_ACTIVE",
                ExposureStatus="ACTIVE",
                Region=region,
                CompartmentName=comp,
                ResourceType="BASTION_SESSION",
                ResourceName=g(s, "display_name") or g(s, "id"),
                LifecycleState=g(s, "lifecycle_state"),
                AssignedEntityType="BASTION_TARGET",
                AssignedEntityID=target_resource,
                TimeExpires=dt(g(s, "time_expires", None)),
                TimeCreated=dt(g(s, "time_created", None)),
                Source="BASTION_API",
                Note=f"Sessione Bastion attiva verso target porta {target_port}",
            ))


# ----------------------------------------------------------------------------
# NEW: WAF policies (inventario)
# ----------------------------------------------------------------------------

def scan_waf_policies(waf, region, comp_id, comp, rows, errors):
    if not waf:
        return
    try:
        policies = list_all_paged(waf.list_web_app_firewall_policies, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_waf_policies", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for p in policies:
        add_row(rows, row(
            ExposureCategory="WAF_POLICY_INVENTORY",
            ExposureStatus=g(p, "lifecycle_state") or "ACTIVE",
            Region=region,
            CompartmentName=comp,
            ResourceType="WAF_POLICY",
            ResourceName=g(p, "display_name") or g(p, "id"),
            LifecycleState=g(p, "lifecycle_state"),
            AssignedEntityID=g(p, "id"),
            TimeCreated=dt(g(p, "time_created", None)),
            Source="WAF_API",
            Note="WAF Policy (verificare attaccamento a Load Balancer/risorsa)",
        ))


# ----------------------------------------------------------------------------
# NEW: Health Check probe verso target pubblici
# ----------------------------------------------------------------------------

def scan_health_checks(hc, region, comp_id, comp, rows, errors):
    if not hc:
        return
    try:
        monitors = list_all_paged(hc.list_http_monitors, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_health_check_monitors", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for m in monitors:
        targets = g(m, "targets", []) or []
        for t in targets:
            if is_public_ip(t):
                add_row(rows, row(
                    ExposureCategory="HEALTH_CHECK_PROBE_PUBLIC",
                    ExposureStatus="ACTIVE",
                    PublicIP=t,
                    Region=region,
                    CompartmentName=comp,
                    ResourceType="HEALTH_CHECK_MONITOR",
                    ResourceName=g(m, "display_name") or g(m, "id"),
                    LifecycleState="ACTIVE",
                    AssignedEntityID=g(m, "id"),
                    TimeCreated=dt(g(m, "time_created", None)),
                    Source="HEALTH_CHECKS_API",
                    Note="Health Check probe verso target IP pubblico",
                ))


# ----------------------------------------------------------------------------
# NEW: Big Data Service cluster
# ----------------------------------------------------------------------------

def scan_big_data_service(bds, region, comp_id, comp, rows, errors):
    if not bds:
        return
    try:
        items = list_all_paged(bds.list_bds_instances, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_bds_instances", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for inst in items:
        # is_high_availability + is_secure indicano cluster sensibili,
        # ma il flag che ci interessa è cluster_public_key/public IP nodes
        # Per ora segnaliamo tutti i cluster come info, verifica manuale del network
        nodes = g(inst, "nodes", []) or []
        has_public = any(g(n, "ip_address") and is_public_ip(g(n, "ip_address")) for n in nodes)
        if not has_public:
            continue
        for n in nodes:
            ip = g(n, "ip_address")
            if not (ip and is_public_ip(ip)):
                continue
            add_row(rows, row(
                ExposureCategory="BIG_DATA_PUBLIC_CLUSTER",
                ExposureStatus=g(inst, "lifecycle_state") or "ACTIVE",
                PublicIP=ip,
                Region=region,
                CompartmentName=comp,
                ResourceType="BDS_NODE",
                ResourceName=f"{g(inst, 'display_name')}/{g(n, 'display_name') or g(n, 'instance_id')}",
                LifecycleState=g(inst, "lifecycle_state"),
                AssignedEntityID=g(inst, "id"),
                TimeCreated=dt(g(inst, "time_created", None)),
                Source="BDS_API",
                Note="Big Data Service node con IP pubblico",
            ))


# ----------------------------------------------------------------------------
# NEW: Vulnerability Scanning targets pubblici
# ----------------------------------------------------------------------------

def scan_vss_targets(vss, region, comp_id, comp, rows, errors):
    if not vss:
        return
    try:
        targets = list_all_paged(vss.list_host_scan_targets, compartment_id=comp_id)
    except Exception as exc:
        e = err_ctx("list_vss_targets", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)
        return
    for t in targets:
        add_row(rows, row(
            ExposureCategory="VSS_PUBLIC_TARGET",
            ExposureStatus=g(t, "lifecycle_state") or "ACTIVE",
            Region=region,
            CompartmentName=comp,
            ResourceType="VSS_HOST_SCAN_TARGET",
            ResourceName=g(t, "display_name") or g(t, "id"),
            LifecycleState=g(t, "lifecycle_state"),
            AssignedEntityID=g(t, "id"),
            TimeCreated=dt(g(t, "time_created", None)),
            Source="VSS_API",
            Note="Vulnerability Scanning target configurato",
        ))


# ----------------------------------------------------------------------------
# Cloud Guard
# ----------------------------------------------------------------------------

def cg_interesting(rule: str, labels: str) -> bool:
    t = f"{rule} {labels}".upper()
    return any(x in t for x in [
        "INSTANCE_WITH_PUBLIC_IP", "INSTANCE_PUBLICLY_ACCESSIBLE",
        "PUBLIC", "INTERNET", "BUCKET", "OBJECT",
        "ENDPOINT", "GATEWAY", "LOAD_BALANCER",
    ])


def scan_cloud_guard(cg, region, comp_id, comp, findings, errors, state):
    """
    Esegue lo scan Cloud Guard.

    Usa un 'circuit breaker' tramite il dict `state`:
    se rilevo che Cloud Guard non è abilitato/autorizzato nel tenant (404 o
    403 ricorrenti), imposto state['disabled']=True e i compartment successivi
    saltano lo scan senza loggare errori.
    """
    if not cg or state.get("disabled"):
        return
    try:
        problems = list_all_paged(cg.list_problems, compartment_id=comp_id, lifecycle_state="ACTIVE")
        for p in problems:
            labels = "|".join(g(p, "labels", []) or [])
            rule = g(p, "detector_rule_id")
            if cg_interesting(rule, labels):
                findings.append({
                    "Region": region,
                    "CompartmentName": comp,
                    "Risk": g(p, "risk_level"),
                    "Rule": rule,
                    "ResourceType": g(p, "resource_type"),
                    "ResourceName": g(p, "resource_name"),
                    "ResourceId": g(p, "resource_id"),
                    "ProblemId": g(p, "id"),
                })
    except Exception as exc:
        status = getattr(exc, "status", None)
        code = getattr(exc, "code", None)
        # 404 + 'Authorization failed or requested resource not found' tipico
        # quando Cloud Guard non è abilitato nel tenant. 403 quando manca la
        # policy. In entrambi i casi è inutile riprovare sugli altri compartment.
        if status in (403, 404):
            state["disabled"] = True
            log_json(
                logging.WARNING,
                "CLOUD_GUARD_DISABLED_AUTO",
                region=region,
                first_compartment=comp,
                status=status,
                code=code,
                reason=("Cloud Guard non abilitato nel tenant o policy IAM mancante; "
                        "salto il check sui restanti compartment."),
            )
            return
        # Altri errori (transient/network/...): logghiamoli normalmente
        e = err_ctx("list_cloud_guard_problems", exc, region=region, compartment=comp)
        errors.append(e)
        log_json(logging.ERROR, "SCAN_ERROR", **e)


def correlate_cloud_guard(rows: Dict[str, Dict[str, str]], findings: List[Dict[str, Any]]) -> None:
    for f in findings:
        matched = False
        for r in rows.values():
            same_name = f["ResourceName"] and r.get("ResourceName") == f["ResourceName"]
            same_id = f["ResourceId"] and f["ResourceId"] in {
                r.get("AssignedEntityID"), r.get("VnicID"), r.get("PublicIpOCID"),
            }
            if same_name or same_id:
                r["CloudGuardRiskLevel"] = merge_pipe(r.get("CloudGuardRiskLevel"), f["Risk"])
                r["CloudGuardDetectorRule"] = merge_pipe(r.get("CloudGuardDetectorRule"), f["Rule"])
                r["CloudGuardProblemId"] = merge_pipe(r.get("CloudGuardProblemId"), f["ProblemId"])
                n = "Cloud Guard segnala esposizione/rischio pubblico sulla risorsa"
                if n not in r.get("Note", ""):
                    r["Note"] = (r.get("Note", "") + " | " + n).strip(" |")
                matched = True
        if not matched:
            add_row(rows, row(
                ExposureCategory="CLOUD_GUARD_PUBLIC_EXPOSURE",
                ExposureStatus="ACTIVE",
                Region=f["Region"],
                CompartmentName=f["CompartmentName"],
                ResourceType=f["ResourceType"],
                ResourceName=f["ResourceName"],
                AssignedEntityID=f["ResourceId"],
                Source="CLOUD_GUARD_API",
                CloudGuardRiskLevel=f["Risk"],
                CloudGuardDetectorRule=f["Rule"],
                CloudGuardProblemId=f["ProblemId"],
                Note="Segnalazione Cloud Guard non correlata automaticamente a un IP/endpoint del report",
            ))


# ----------------------------------------------------------------------------
# Main scan orchestration
# ----------------------------------------------------------------------------

def collect_all(config, signer, tenancy_id, regions_list, comps, opts, errors):
    rows: Dict[str, Dict[str, str]] = {}
    findings: List[Dict[str, Any]] = []

    for region in regions_list:
        log_json(logging.INFO, "SCAN_REGION_START", region=region, compartments=len(comps))
        c = mk_clients(config, signer, region)
        ad_list = list_availability_domains(c["identity"], tenancy_id) if c.get("identity") else []
        ns = ""
        if c.get("object_storage") and opts["scan_object_storage"]:
            try:
                ns = c["object_storage"].get_namespace().data
            except Exception as exc:
                e = err_ctx("get_object_storage_namespace", exc, region=region, compartment="TENANCY")
                errors.append(e)
                log_json(logging.ERROR, "SCAN_ERROR", **e)

        cache = {"priv": {}, "vnic": {}, "subnet": {}, "instance": {}, "nat": {}, "subnet_obj": {}}
        # Circuit breaker per Cloud Guard: se non è disponibile nel tenant,
        # disabilita il check per tutti i compartment successivi della region.
        cg_state: Dict[str, Any] = {"disabled": False}

        for comp_id, comp in comps:
            log_json(logging.INFO, "SCAN_COMPARTMENT", region=region, compartment=comp)

            if c.get("network") and c.get("compute"):
                scan_public_ips(c, region, comp_id, comp, ad_list, rows, cache, errors)

            if opts["scan_load_balancers"]:
                scan_load_balancers(c.get("lb"), region, comp_id, comp, rows, errors)
            if opts["scan_network_load_balancers"]:
                scan_network_load_balancers(c.get("nlb"), region, comp_id, comp, rows, errors)

            if opts["scan_managed_endpoints"]:
                scan_api_gateways(c.get("apigw"), region, comp_id, comp, rows, errors, opts)
                scan_autonomous_databases(c.get("database"), region, comp_id, comp, rows, errors, opts)
                scan_oke_clusters(c.get("oke"), region, comp_id, comp, rows, errors, opts)

            if opts["scan_object_storage"]:
                scan_object_storage(c.get("object_storage"), ns, region, comp_id, comp, rows, errors, opts)

            if opts["scan_compute_secondary_vnics"]:
                scan_compute_secondary_vnics(c.get("compute"), c.get("network"),
                                             region, comp_id, comp, rows, cache, errors)
            if opts["scan_dbcs"]:
                scan_db_systems(c.get("database"), c.get("network"),
                                region, comp_id, comp, rows, cache, errors)
            if opts["scan_fss"]:
                scan_fss_mount_targets(c.get("fss"), c.get("network"), c.get("identity"),
                                       region, tenancy_id, comp_id, comp, rows, cache, errors)
            if opts["scan_drg"]:
                scan_drg_attachments(c.get("network"), region, comp_id, comp, rows, errors)
            if opts["scan_service_gateway"]:
                scan_service_gateways(c.get("network"), region, comp_id, comp, rows, errors)

            # --- Networking gateways aggiuntivi ---
            if opts["scan_internet_gateway"]:
                scan_internet_gateways(c.get("network"), region, comp_id, comp, rows, errors)
            if opts["scan_local_peering"]:
                scan_local_peering_gateways(c.get("network"), region, comp_id, comp, rows, errors)

            # --- Database family estesa ---
            if opts["scan_mysql"]:
                scan_mysql_db_systems(c.get("mysql"), c.get("network"),
                                      region, comp_id, comp, rows, cache, errors)
            if opts["scan_postgresql"]:
                scan_postgresql_db_systems(c.get("psql"), c.get("network"),
                                           region, comp_id, comp, rows, cache, errors)

            # --- Container & serverless ---
            if opts["scan_container_instances"]:
                scan_container_instances(c.get("container_instances"), c.get("network"),
                                         region, comp_id, comp, rows, cache, errors)
            if opts["scan_functions"]:
                scan_functions(c.get("functions"), region, comp_id, comp, rows, errors, opts)

            # --- Integration & analytics ---
            if opts["scan_integration"]:
                scan_integration_instances(c.get("integration"), region, comp_id, comp, rows, errors, opts)
            if opts["scan_analytics"]:
                scan_analytics_instances(c.get("analytics"), region, comp_id, comp, rows, errors, opts)
            if opts["scan_data_science"]:
                scan_data_science_notebooks(c.get("data_science"), region, comp_id, comp, rows, errors)
            if opts["scan_golden_gate"]:
                scan_golden_gate(c.get("golden_gate"), region, comp_id, comp, rows, errors, opts)
            if opts["scan_opensearch"]:
                scan_opensearch_clusters(c.get("opensearch"), c.get("network"),
                                         region, comp_id, comp, rows, cache, errors)
            if opts["scan_streaming"]:
                scan_streaming(c.get("streaming"), region, comp_id, comp, rows, errors, opts)
            if opts["scan_big_data"]:
                scan_big_data_service(c.get("bds"), region, comp_id, comp, rows, errors)

            # --- Security & inventory ---
            if opts["scan_bastion"]:
                scan_bastions(c.get("bastion"), region, comp_id, comp, rows, errors)
            if opts["scan_waf"]:
                scan_waf_policies(c.get("waf"), region, comp_id, comp, rows, errors)
            if opts["scan_health_checks"]:
                scan_health_checks(c.get("healthchecks"), region, comp_id, comp, rows, errors)
            if opts["scan_vss"]:
                scan_vss_targets(c.get("vss"), region, comp_id, comp, rows, errors)

            if opts["scan_cloud_guard"]:
                scan_cloud_guard(c.get("cloud_guard"), region, comp_id, comp, findings, errors, cg_state)

    correlate_cloud_guard(rows, findings)

    return sorted(
        rows.values(),
        key=lambda r: (
            r["Region"], r["CompartmentName"], r["ExposureCategory"],
            r["ResourceType"], r["ResourceName"], r["PublicIP"], r["Endpoint"],
        ),
    )


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------

def build_csv(records: List[Dict[str, str]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS)
    w.writeheader()
    w.writerows(records)
    return buf.getvalue()


def count_by(records: List[Dict[str, str]], field: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in records:
        k = r.get(field) or "N/A"
        out[k] = out.get(k, 0) + 1
    return out


def make_summary(records: List[Dict[str, str]]) -> Dict[str, Any]:
    return {
        "total_records": len(records),
        "total_public_ips": len({r["PublicIP"] for r in records if r.get("PublicIP")}),
        "by_region": count_by(records, "Region"),
        "by_exposure_category": count_by(records, "ExposureCategory"),
        "by_exposure_status": count_by(records, "ExposureStatus"),
        "by_resource_type": count_by(records, "ResourceType"),
        "by_source": count_by(records, "Source"),
        "cloud_guard_correlated_records": sum(1 for r in records if r.get("CloudGuardDetectorRule")),
    }


def html_table(title: str, data: Dict[str, int], friendly: bool = False) -> str:
    if not data:
        return ""
    s = [
        f"<h3>{html.escape(title)}</h3>",
        "<table border='1' cellspacing='0' cellpadding='5' style='border-collapse:collapse;font-size:12px;'>",
        "<tr style='background-color:#f2f2f2;'><th>Voce</th><th>Totale</th></tr>",
    ]
    for k, v in sorted(data.items()):
        label = FRIENDLY.get(k, k) if friendly else k
        s.append(f"<tr><td>{html.escape(label)}</td><td>{v}</td></tr>")
    s.append("</table>")
    return "\n".join(s)


def build_html(records, sm, regs, comp_count, errors, tenant_label, max_rows=200):
    p = [
        "<html><body style='font-family:Arial,sans-serif;font-size:13px;color:#222;'>",
        "<h2>Report perimetro pubblico/esposto OCI</h2>",
        f"<p><b>Tenant:</b> {html.escape(tenant_label)}<br>",
        f"<b>Generato:</b> {html.escape(now_str())}<br>",
        f"<b>Region analizzate:</b> {html.escape(', '.join(regs))}<br>",
        f"<b>Compartment analizzati:</b> {comp_count}<br>",
        f"<b>Totale esposizioni rilevate:</b> {sm['total_records']}<br>",
        f"<b>IP pubblici numerici univoci:</b> {sm['total_public_ips']}<br>",
        f"<b>Record con riscontro Cloud Guard:</b> {sm['cloud_guard_correlated_records']}<br>",
        f"<b>Errori scansione:</b> {len(errors)}</p>",
        html_table("Riepilogo per categoria", sm["by_exposure_category"], True),
        html_table("Riepilogo per stato", sm["by_exposure_status"]),
        html_table("Riepilogo per tipo risorsa", sm["by_resource_type"]),
        html_table("Riepilogo per sorgente", sm["by_source"]),
    ]
    if records:
        visible = ["ExposureCategory", "ExposureStatus", "PublicIP", "Endpoint", "Region",
                   "CompartmentName", "ResourceType", "ResourceName", "BucketName",
                   "ObjectName", "AccessType", "CloudGuardRiskLevel", "CloudGuardDetectorRule",
                   "Source", "Note"]
        p.append("<h3>Dettaglio esposizioni</h3>")
        if len(records) > max_rows:
            p.append(f"<p>Mostrate le prime {max_rows} righe su {len(records)}. CSV completo allegato.</p>")
        p.append(
            "<table border='1' cellspacing='0' cellpadding='5' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='background-color:#343a40;color:white;'>"
            + "".join(f"<th>{html.escape(LABELS.get(f, f))}</th>" for f in visible)
            + "</tr>"
        )
        for r in records[:max_rows]:
            tds = []
            for f in visible:
                v = FRIENDLY.get(r.get(f, ""), r.get(f, "")) if f == "ExposureCategory" else r.get(f, "")
                tds.append(f"<td>{html.escape(str(v or ''))}</td>")
            p.append("<tr>" + "".join(tds) + "</tr>")
        p.append("</table>")
    else:
        p.append("<p style='color:#28a745;'><b>Nessuna esposizione pubblica rilevata.</b></p>")
    p.append("</body></html>")
    return "\n".join(p)


def send_mail(args, csv_body, html_body, filename, summary):
    to = [x.strip() for x in args.mail_to.split(",") if x.strip()]
    subject = (
        f"{args.mail_subject_prefix} {args.tenant_label} - "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')} - "
        f"esposizioni={summary['total_records']}"
    )
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = args.mail_from
    msg["To"] = ", ".join(to)
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    att = MIMEApplication(csv_body.encode("utf-8-sig"), _subtype="csv")
    att.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(att)
    with smtplib.SMTP(args.smtp_host, args.smtp_port) as s:
        if args.smtp_starttls:
            s.starttls()
        if args.smtp_user and args.smtp_pass:
            s.login(args.smtp_user, args.smtp_pass)
        s.sendmail(args.mail_from, to, msg.as_string())
    return {"sent": True, "to": to, "subject": subject, "attachment": filename}


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="OCI Public Perimeter Scanner - tenant agnostic standalone",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Auth
    grp_auth = ap.add_argument_group("Autenticazione")
    grp_auth.add_argument("--auth", choices=["config_file", "instance_principal", "resource_principal"],
                          default="config_file",
                          help="Metodo di autenticazione (default: config_file)")
    grp_auth.add_argument("--config-file", default="~/.oci/config",
                          help="Path al file di config OCI CLI (default: ~/.oci/config)")
    grp_auth.add_argument("--profile", default="DEFAULT",
                          help="Profilo nel config file (default: DEFAULT)")

    # Scope
    grp_scope = ap.add_argument_group("Scope di scansione")
    grp_scope.add_argument("--region", help="Singola region da scansionare (es. eu-frankfurt-1)")
    grp_scope.add_argument("--all-regions", action="store_true",
                           help="Scansiona tutte le region sottoscritte (default: solo home region)")
    grp_scope.add_argument("--compartment-id",
                           help="Limita a un singolo compartment (default: tutto il tenant)")
    grp_scope.add_argument("--no-root-tenancy", action="store_true",
                           help="Escludi il root tenancy dalla scansione")

    # Toggle scanner
    grp_toggle = ap.add_argument_group("Tipi di scansione (default: tutti attivi)")
    grp_toggle.add_argument("--no-load-balancers", action="store_true")
    grp_toggle.add_argument("--no-network-load-balancers", action="store_true")
    grp_toggle.add_argument("--no-managed-endpoints", action="store_true",
                            help="Disabilita API Gateway, Autonomous DB, OKE")
    grp_toggle.add_argument("--no-object-storage", action="store_true")
    grp_toggle.add_argument("--no-par", action="store_true",
                            help="Disabilita scansione Pre-Authenticated Request")
    grp_toggle.add_argument("--include-expired-par", action="store_true",
                            help="Includi PAR scadute")
    grp_toggle.add_argument("--no-cloud-guard", action="store_true")
    grp_toggle.add_argument("--no-compute-secondary-vnics", action="store_true")
    grp_toggle.add_argument("--no-dbcs", action="store_true")
    grp_toggle.add_argument("--no-fss", action="store_true")
    grp_toggle.add_argument("--no-drg", action="store_true")
    grp_toggle.add_argument("--no-service-gateway", action="store_true")
    # Nuove categorie aggiuntive
    grp_toggle.add_argument("--no-internet-gateway", action="store_true")
    grp_toggle.add_argument("--no-local-peering", action="store_true")
    grp_toggle.add_argument("--no-mysql", action="store_true")
    grp_toggle.add_argument("--no-postgresql", action="store_true")
    grp_toggle.add_argument("--no-container-instances", action="store_true")
    grp_toggle.add_argument("--no-functions", action="store_true")
    grp_toggle.add_argument("--no-integration", action="store_true")
    grp_toggle.add_argument("--no-analytics", action="store_true")
    grp_toggle.add_argument("--no-data-science", action="store_true")
    grp_toggle.add_argument("--no-golden-gate", action="store_true")
    grp_toggle.add_argument("--no-opensearch", action="store_true")
    grp_toggle.add_argument("--no-streaming", action="store_true")
    grp_toggle.add_argument("--no-big-data", action="store_true")
    grp_toggle.add_argument("--no-bastion", action="store_true")
    grp_toggle.add_argument("--no-waf", action="store_true")
    grp_toggle.add_argument("--no-health-checks", action="store_true")
    grp_toggle.add_argument("--no-vss", action="store_true")
    grp_toggle.add_argument("--include-always-public", action="store_true",
                            help="Includi anche servizi managed sempre pubblici "
                                 "per design (Streaming, Functions, OCIR, ecc.). "
                                 "Default: esclusi per ridurre il rumore.")
    grp_toggle.add_argument("--no-unresolved-endpoints", action="store_true",
                            help="Escludi endpoint managed non risolvibili in DNS")
    grp_toggle.add_argument("--dns-timeout", type=float, default=5.0,
                            help="Timeout DNS in secondi (default: 5)")
    grp_toggle.add_argument("--api-throttle-ms", type=int, default=50,
                            help="Pausa tra chiamate API (millisecondi) per "
                                 "evitare rate-limit 429. Default: 50. "
                                 "Aumenta a 100-200 se vedi molti 429.")

    # Output
    grp_out = ap.add_argument_group("Output")
    grp_out.add_argument("--output-dir", default=".",
                         help="Directory di output (default: .)")
    grp_out.add_argument("--prefix", default="oci_perimeter",
                         help="Prefisso filename (default: oci_perimeter)")
    grp_out.add_argument("--stdout-json", action="store_true",
                         help="Scrivi il JSON completo su stdout invece che su file")
    grp_out.add_argument("--tenant-label", default="OCI_TENANT",
                         help="Etichetta tenant nel report (default: OCI_TENANT)")

    # Misc
    grp_misc = ap.add_argument_group("Altro")
    grp_misc.add_argument("--log-level", default="INFO",
                          choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    grp_misc.add_argument("--quiet", action="store_true",
                          help="Sopprime il summary JSON su stdout")

    return ap.parse_args()


def build_opts_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Converte il Namespace di argparse in un dict di opzioni "puro".

    Questo dict è la forma canonica per chiamare run_scan(). Lo usano sia main()
    (CLI) sia il server MCP, che costruisce il dict direttamente dai parametri
    del tool invece che da argparse.
    """
    return {
        # Auth & scope
        "auth": args.auth,
        "config_file": args.config_file,
        "profile": args.profile,
        "region": args.region,
        "all_regions": args.all_regions,
        "compartment_id": args.compartment_id,
        "no_root_tenancy": args.no_root_tenancy,
        "tenant_label": args.tenant_label,
        # Scanner toggles
        "scan_load_balancers": not args.no_load_balancers,
        "scan_network_load_balancers": not args.no_network_load_balancers,
        "scan_managed_endpoints": not args.no_managed_endpoints,
        "scan_object_storage": not args.no_object_storage,
        "scan_par": not args.no_par,
        "include_expired_par": args.include_expired_par,
        "scan_cloud_guard": not args.no_cloud_guard,
        "scan_compute_secondary_vnics": not args.no_compute_secondary_vnics,
        "scan_dbcs": not args.no_dbcs,
        "scan_fss": not args.no_fss,
        "scan_drg": not args.no_drg,
        "scan_service_gateway": not args.no_service_gateway,
        "scan_internet_gateway": not args.no_internet_gateway,
        "scan_local_peering": not args.no_local_peering,
        "scan_mysql": not args.no_mysql,
        "scan_postgresql": not args.no_postgresql,
        "scan_container_instances": not args.no_container_instances,
        "scan_functions": (not args.no_functions) and args.include_always_public,
        "scan_integration": not args.no_integration,
        "scan_analytics": not args.no_analytics,
        "scan_data_science": not args.no_data_science,
        "scan_golden_gate": not args.no_golden_gate,
        "scan_opensearch": not args.no_opensearch,
        "scan_streaming": (not args.no_streaming) and args.include_always_public,
        "scan_big_data": not args.no_big_data,
        "scan_bastion": not args.no_bastion,
        "scan_waf": not args.no_waf,
        "scan_health_checks": not args.no_health_checks,
        "scan_vss": not args.no_vss,
        "include_always_public": args.include_always_public,
        "include_unresolved": not args.no_unresolved_endpoints,
        # Tuning
        "dns_timeout": args.dns_timeout,
        "api_throttle_ms": args.api_throttle_ms,
    }


def run_scan(opts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Esegue uno scan completo del perimetro pubblico OCI e ritorna il risultato
    come dict serializzabile JSON.

    Funzione PURA: non scrive su disco, non stampa su stdout, non legge argv.
    Tutti i parametri vengono dal dict `opts` (vedi build_opts_from_args()).

    Usata sia dalla CLI (main) che dal server MCP. Il logging su stderr resta
    attivo perché è side-effect "innocuo" rispetto al protocollo MCP (che usa
    stdout per JSON-RPC).

    Returns:
        dict con chiavi: status, generated_at_utc, tenancy_id, tenant_label,
        regions, compartments_count, summary, scan_errors_count, scan_errors,
        records.

    Raises:
        RuntimeError se l'autenticazione o la discovery falliscono. Errori
        non fatali durante lo scan dei singoli compartment vengono raccolti
        nel campo `scan_errors` del risultato.
    """
    # Throttle globale per anti rate-limit 429
    global _API_THROTTLE_MS
    _API_THROTTLE_MS = max(0, int(opts.get("api_throttle_ms", 50)))

    # Auth — ricostruisco un mini-namespace per build_auth() che accetta args
    auth_ns = argparse.Namespace(
        auth=opts.get("auth", "config_file"),
        config_file=opts.get("config_file", "~/.oci/config"),
        profile=opts.get("profile", "DEFAULT"),
    )
    try:
        config, signer, tenancy_id = build_auth(auth_ns)
    except Exception as exc:
        log_json(logging.ERROR, "AUTH_ERROR", message=str(exc))
        raise RuntimeError(f"OCI authentication failed: {exc}") from exc

    log_json(logging.INFO, "AUTH_OK", auth=auth_ns.auth, tenancy=tenancy_id)

    # Discovery
    identity = mk_client(oci.identity.IdentityClient, config, signer)
    if not identity:
        raise RuntimeError("Failed to initialize OCI Identity client")

    try:
        regions_list = list_regions(
            identity, tenancy_id,
            opts.get("region"), opts.get("all_regions", False),
        )
        comps = list_compartments(
            identity, tenancy_id,
            opts.get("compartment_id"),
            not opts.get("no_root_tenancy", False),
        )
    except Exception as exc:
        log_json(logging.ERROR, "DISCOVERY_ERROR", message=str(exc))
        raise RuntimeError(f"OCI discovery failed: {exc}") from exc

    log_json(logging.INFO, "DISCOVERY_OK", regions=regions_list, compartments=len(comps))

    # collect_all si aspetta opts con le sole chiavi scan_* / include_* / dns_timeout
    errors: List[Dict[str, Any]] = []
    records = collect_all(config, signer, tenancy_id, regions_list, comps, opts, errors)
    summary = make_summary(records)
    summary["scan_errors_count"] = len(errors)

    return {
        "status": "OK",
        "generated_at_utc": now_str(),
        "tenancy_id": tenancy_id,
        "tenant_label": opts.get("tenant_label", "OCI_TENANT"),
        "regions": regions_list,
        "compartments_count": len(comps),
        "summary": summary,
        "scan_errors_count": len(errors),
        "scan_errors": errors,
        "records": records,
    }


def main() -> int:
    """
    Entry point CLI. Parsa argv, costruisce opts, chiama run_scan(), gestisce
    output su file/stdout. Tutta la logica di scan è in run_scan() per essere
    riutilizzabile dal server MCP.
    """
    args = parse_args()
    setup_logging(args.log_level)

    # Costruisco le opzioni per run_scan()
    opts = build_opts_from_args(args)

    # Esecuzione
    try:
        output = run_scan(opts)
    except RuntimeError as exc:
        log_json(logging.ERROR, "SCAN_FAILED", message=str(exc))
        return 2

    # Output JSON unico
    json_body = json.dumps(output, ensure_ascii=False, indent=2, default=str)
    stamp = ts_compact()

    if args.stdout_json:
        sys.stdout.write(json_body)
    else:
        out_dir = Path(os.path.expanduser(args.output_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / f"{args.prefix}_{stamp}.json"
        json_path.write_text(json_body, encoding="utf-8")
        log_json(logging.INFO, "JSON_WRITTEN", path=str(json_path), records=len(output["records"]))

        # Summary breve a video (a meno di --quiet)
        if not args.quiet:
            short = {k: output[k] for k in (
                "status", "generated_at_utc", "tenancy_id", "regions",
                "compartments_count", "summary", "scan_errors_count",
            )}
            short["json_report_path"] = str(json_path)
            print(json.dumps(short, ensure_ascii=False, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())

