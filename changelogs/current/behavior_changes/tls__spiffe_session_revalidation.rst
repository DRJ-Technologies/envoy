tls: native TCP TLS sockets using the typed SPIFFE validator and the default handshaker now
  revalidate pending handshakes and established sessions when their validation context changes.
  Peers rejected by the current domain-specific store, CRLs or identity restrictions are closed
  without flushing. Mapped session resumption is refused. Typed SPIFFE validation also enforces
  transport SAN overrides and role-specific TLS certificate purpose. Default TLS validators,
  custom handshakers and file-backed SPIFFE bundle providers retain their existing behavior.
