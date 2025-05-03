## v1.0.0 - 2024-??-?? - ???

Noteworthy Changes:

* Complete removal of SPF record support, records should be transitioned to TXT
  values before updating to this version.

Changes:

* Address pending octoDNS 2.x deprecations, require minimum of 1.5.x
* Correctly quote and chunk TXT records to match Cloudflare's internal behavior

## v0.0.9 - 2025-02-06 - Unknown nameservers are a thing

* Handle cases where Cloudflare doesn't return a zones name servers.

## v0.0.8 - 2025-02-06 - More options

* Add support for optionally retrying requests that hit 403 errors
* Add a zone_id lookup fallback when deleting records
* Add support for setting Cloudflare plan type for zones

## v0.0.7 - 2024-08-20 - DS always come second

* Create DS records after their sibling NS records to appease Cloudflare's
  validations
* Throw an error when trying to create a DS without a coresponding NS,
  `strict_supports: false` will omit the DS instead
* Add support for SVCB and HTTPS record types

## v0.0.6 - 2024-05-22 - Deal with unknowns and make more knowns

* Fix handling of unsupported record types during apply
* DS record type support

## v0.0.5 - 2024-04-15 - Comment on your proxying and ttls

* TtlToProxy processor added to enable the proxied flag based on a sentinel
  ttl value. Useful when the source is not YamlProvider
* Add support for comments & tags via octodns.cloudflare.comment|tags
* ProxyCNAME processor added to aid in supporting Cloudflare prixed values
  with non-Cloudflare DNS providers by directing them to the relevant
  .cdn.cloudflare.net. CNAME / ALIAS value.

## v0.0.4 - 2024-02-08 - Know your zones

* Support for Provider.list_zones to enable dynamic zone config when operating
  as a source
* Support for auto-ttl without proxied as records can be configured that way,
  see auto-ttl in README.md for more info
* Fix bug in handling of empty strings/content on TXT records
* Make the minumum supported TTL configurable.

## v0.0.3 - 2023-09-20 - All the commits fit to release

* SPF records can no longer be created,
  https://github.com/octodns/octodns-cloudflare/issues/28
* NAPTR and SSHFP support added
* All HTTP requests include a meaningful user-agent.
* AccountID filter support
* API token auth method/doc

## v0.0.2 - 2022-12-25 - Holiday Edition

* Added support for TLSA record type
* Switched to pytest and updated everything to latest template setup

## v0.0.1 - 2022-01-05 - Moving

#### Nothworthy Changes

* Initial extraction of CloudflareProvider from octoDNS core

#### Stuff

Nothing
