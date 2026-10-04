Certificate validators
======================

These extensions allow custom TLS certificate validation.

The SPIFFE validator requires exactly one URI SAN containing a valid, non-root SPIFFE ID.
Other SAN types may coexist with that URI, but are not used for SPIFFE identity matching.
The URI's trust domain selects its validation bundle; additional URI SANs cannot select
one domain's roots while matching another domain's identity.

An explicitly empty ``inline_string`` or ``inline_bytes`` in a typed SPIFFE
``trust_domains`` entry creates a store with no trust anchors. Peers for that domain fail
validation, without falling back to another domain or system roots. An unset data source,
an empty file, or malformed nonempty PEM remains a configuration error.

Native TCP TLS sockets using typed ``trust_domains`` and the default handshaker track pending
handshakes and established connections. A validation-context update rechecks the original peer
chain against the current selected domain's roots and CRLs, including TLS peer purpose and both
the original endpoint restriction and the current configured SAN matcher. Peers rejected by the
current policy close without flushing on their owning worker dispatcher. Still-valid peers remain
connected. A pending handshake must pass the current policy before reporting ``Connected``;
resumed mapped sessions are refused.

This update mechanism does not provide instantaneous fleet-wide revocation, schedule certificate
or CRL expiry independently of context updates, or affect other TLS endpoints. It requires a
native owning worker and applies only to synchronous typed SPIFFE validation with the default
handshaker. Default validators, custom handshakers and file-backed SPIFFE bundle providers retain
their previous session behavior. Removing an SDS Secret resource is distinct from publishing an
explicit empty domain store: the native SDS API acknowledges such removal while retaining the
referenced secret. Producers must deliver the denying validation context through the maintained
secret-update path.

.. toctree::
  :glob:
  :maxdepth: 2

  ../../extensions/transport_sockets/tls/cert_validator/*/v3/*
