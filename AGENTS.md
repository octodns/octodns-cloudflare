# Developer Agent Guide for octoDNS Cloudflare Provider

This repository contains the Cloudflare provider for octoDNS. It enables planning, syncing, and applying DNS record states directly to Cloudflare's DNS API.

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components

- **Provider Classes**:
  - [CloudflareProvider](file:///home/ross/octodns/octodns-cloudflare/octodns_cloudflare/__init__.py) (defined in [octodns_cloudflare/__init__.py](file:///home/ross/octodns/octodns-cloudflare/octodns_cloudflare/__init__.py)): The primary DNS sync provider. Handles auth (API keys or bearer tokens), pagination, rate limiting, and zone/record updates.
  - [CloudflareInternalProvider](file:///home/ross/octodns/octodns-cloudflare/octodns_cloudflare/__init__.py): Specialized provider for internal operations.
- **Processors**: Located in [octodns_cloudflare/processor/filter.py](file:///home/ross/octodns/octodns-cloudflare/octodns_cloudflare/processor/filter.py):
  - `TagAllowListFilter` / `TagRejectListFilter`: Filter records based on Cloudflare tags.
  - `ProxyCNAME`: Ensures CNAME targets match proxy requirements.
  - `TtlToProxy`: Automatically translates TTL values to proxy configurations.
- **Custom Records & Behaviors**:
  - `URLFWD`: Cloudflare-specific URL forwarding implemented using Cloudflare Page Rules or Redirect Rules.

### Key Workflows & Features

1. **Supported Record Types**: `ALIAS`, `A`, `AAAA`, `CAA`, `CNAME`, `DS`, `LOC`, `MX`, `NAPTR`, `NS`, `PTR`, `SSHFP`, `SRV`, `TLSA`, `TXT`, `HTTPS`, `SVCB`, and `URLFWD`.
2. **Cloudflare CDN Proxying**: Supports the `proxied` attribute on `A`, `AAAA`, `ALIAS`, and `CNAME` records. Enabling this proxies the traffic through Cloudflare's network. Configured via the `octodns.cloudflare.proxied` metadata namespace.
3. **Record Annotations**: Supports tags and comments on Cloudflare records, configured through `octodns.cloudflare.tags` and `octodns.cloudflare.comment`.
4. **Dynamic Routing**: Not supported (`SUPPORTS_DYNAMIC=False`, `SUPPORTS_GEO=False`).
5. **Dynamic Subnets**: Not supported (`SUPPORTS_DYNAMIC_SUBNETS=False`).
6. **Pool Value Status**: Not supported (`SUPPORTS_POOL_VALUE_STATUS=False`).

## Development & Testing

- **Setup Script**: Run `./script/bootstrap` to create a virtual environment, install runtime and development dependencies (including `black`, `isort`, `pyflakes`, and `pytest`), and configure pre-commit hooks.
- **Test Suite**: Run unit tests using `pytest` via `./script/test` (or `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-cloudflare/tests).
- **Code Coverage**: Verify code coverage using `./script/coverage`.

## Key Constraints & Behaviors

- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
