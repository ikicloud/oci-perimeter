# Required IAM Policies

The scanner needs **read-only** access to OCI resources. No write permissions are required — it never modifies, creates, or deletes anything.

## Option A — Broad read access (simplest)

Grants read access to all resources in the tenancy. Easiest to set up, recommended for initial evaluation.

```
allow group <YOUR_GROUP> to read all-resources in tenancy
allow group <YOUR_GROUP> to inspect compartments in tenancy
```

## Option B — Granular per-service policies (recommended for production)

Grants read access only to the specific services the scanner queries.

```
# Core networking
allow group <YOUR_GROUP> to read virtual-network-family in tenancy

# Compute
allow group <YOUR_GROUP> to read instance-family in tenancy

# Load balancing
allow group <YOUR_GROUP> to read load-balancers in tenancy
allow group <YOUR_GROUP> to read network-load-balancers in tenancy

# API Gateway
allow group <YOUR_GROUP> to read api-gateway-family in tenancy

# Database family
allow group <YOUR_GROUP> to read autonomous-database-family in tenancy
allow group <YOUR_GROUP> to read database-family in tenancy

# Storage
allow group <YOUR_GROUP> to read object-family in tenancy
allow group <YOUR_GROUP> to read file-family in tenancy

# Containers
allow group <YOUR_GROUP> to read cluster-family in tenancy
allow group <YOUR_GROUP> to read container-instances in tenancy

# Integration & analytics
allow group <YOUR_GROUP> to read integration-instance in tenancy
allow group <YOUR_GROUP> to read analytics-instance in tenancy
allow group <YOUR_GROUP> to read data-science-family in tenancy
allow group <YOUR_GROUP> to read golden-gate-family in tenancy
allow group <YOUR_GROUP> to read opensearch-family in tenancy
allow group <YOUR_GROUP> to read streaming in tenancy
allow group <YOUR_GROUP> to read bds-instance in tenancy

# Security
allow group <YOUR_GROUP> to read cloud-guard-family in tenancy
allow group <YOUR_GROUP> to read bastion-family in tenancy
allow group <YOUR_GROUP> to read waf-family in tenancy
allow group <YOUR_GROUP> to read vss-family in tenancy
allow group <YOUR_GROUP> to read healthchecks in tenancy

# MySQL
allow group <YOUR_GROUP> to read mysql-family in tenancy

# PostgreSQL
allow group <YOUR_GROUP> to read postgresql-family in tenancy
```

## Option C — Instance Principal (no API key needed)

If you run the scanner from an OCI VM inside the target tenant, you can use Instance Principal authentication — no API key file required.

### 1. Create a Dynamic Group

In OCI Console → Identity → Dynamic Groups → Create:

```
Name: OCI-PERIMETER-SCANNER-DG
Matching rule: instance.id = '<your-vm-ocid>'
```

Or to match all instances in a compartment:

```
All { instance.compartment.id = '<compartment-ocid>' }
```

### 2. Add policies for the Dynamic Group

```
allow dynamic-group OCI-PERIMETER-SCANNER-DG to read all-resources in tenancy
allow dynamic-group OCI-PERIMETER-SCANNER-DG to inspect compartments in tenancy
```

### 3. Run with instance_principal auth

```bash
oci-perimeter-scan --auth instance_principal
```

## Notes

- All policies are **read-only** (`read`, `inspect`, `list`). The scanner never calls mutating APIs.
- `inspect compartments` is always required to discover the compartment tree.
- Cloud Guard requires the tenancy-level policy even if you scan a specific compartment.
- If Cloud Guard is not enabled in your tenancy, use `--no-cloud-guard` to suppress 404 errors.

