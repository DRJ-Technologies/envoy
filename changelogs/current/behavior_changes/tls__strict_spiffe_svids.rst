SPIFFE certificate validation now rejects missing, multiple, or malformed URI SANs, including root-only SPIFFE IDs.
An explicitly empty inline trust-domain bundle is accepted as a zero-anchor store that denies certificate validation.
