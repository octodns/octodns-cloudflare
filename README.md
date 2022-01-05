## CloudflareProvider provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Cloudflare](https://www.cloudflare.com/dns/).

### Installation

#### Command line

```
pip install octodns_cloudflare
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns_cloudflare==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns_cloudflare.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_powerdns
```

### Configuration

```yaml
providers:
  cloudflare:
    class: octodns_cloudflare.CloudflareProvider
    # The api key (required)
    # Your Cloudflare account email address (required, optional if using token)
    email: env/CLOUDFLARE_EMAIL
    token: env/CLOUDFLARE_TOKEN
    # Import CDN enabled records as CNAME to {}.cdn.cloudflare.net. Records
    # ending at .cdn.cloudflare.net. will be ignored when this provider is
    # not used as the source and the cdn option is enabled.
    #
    # See: https://support.cloudflare.com/hc/en-us/articles/115000830351
    #cdn: false
    # Optional. Default: 4. Number of times to retry if a 429 response
    # is received.
    #retry_count: 4
    # Optional. Default: 300. Number of seconds to wait before retrying.
    #retry_period: 300
    # Optional. Default: 50. Number of zones per page.
    #zones_per_page: 50
    # Optional. Default: 100. Number of dns records per page.
    #records_per_page: 100
```

Note: The "proxied" flag of "A", "AAAA" and "CNAME" records can be managed via the YAML provider like so:

```yaml
name:
    octodns:
        cloudflare:
            proxied: true
    ttl: 120
    type: A
    value: 1.2.3.4
```

### Support Information

#### Records

CloudflareProvider supports A, AAAA, ALIAS, CAA, CNAME, LOC, MX, NS, PTR, SPF, SRV, TXT, and URLFWD. There are restrictions on CAA tag support.

#### Dynamic

CloudflareProvider does not support dynamic records.

### Developement

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
