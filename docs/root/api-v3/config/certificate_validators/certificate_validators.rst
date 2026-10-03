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
an empty file, or malformed nonempty PEM remains a configuration error. This controls new
certificate validation; it does not revalidate established TLS connections.

.. toctree::
  :glob:
  :maxdepth: 2

  ../../extensions/transport_sockets/tls/cert_validator/*/v3/*
