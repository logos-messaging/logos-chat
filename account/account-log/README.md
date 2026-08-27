# account-log

The append-only signed log an account uses to endorse keys and data, plus its
canonical encoding.

Protocol only: no identity type, no transport, no opinion about what a context
means. Those belong to `account-traits` and the protocols above it.

```text
SignedAccountLog          payload + account signature over its exact bytes
└── EncodedAccountLog     the log as canonical bytes (wire form)
    └── AccountLog        the log as validated entries (working form)
        └── AccountEntry      Add { context, data } | Remove { index } | Unknown
            └── EntryData     Ed25519Key | Text | Unknown
```

Wire format and invariants: see the spec (TODO: link once published).

## Status

Work in progress. `codec.rs` is unimplemented.
