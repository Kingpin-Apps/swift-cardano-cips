# CIP-30 Security Model

Three gates sit between an incoming JS RPC and any wallet action. They
compose; each one denies by default; you turn them on as you wire up the
wallet.

## Overview

``CIP30WebBridge`` exposes a Swift wallet to a `WKWebView` as
`window.cardano.<walletKey>`, matching the JS surface dApps already speak.
Wallet integrators are responsible for the consent UI; the library is
responsible for making sure that consent decisions are scoped correctly
and that nothing slips past the gates.

## Gate 1 — Identifier validation

`walletKey` and `messageHandlerName` must match `^[A-Za-z0-9_]{1,64}$`.
The bridge `init` throws ``CIP30WebBridgeError/invalidIdentifier(name:value:)``
on anything else, so a misconfigured wallet can't accidentally inject JS
into pages via the wallet name.

```swift
// Fine.
let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")

// Throws CIP30WebBridgeError.invalidIdentifier.
let bridge = try CIP30WebBridge(initial: initial, walletKey: "swift.wallet")
```

## Gate 2 — Origin policy

Every RPC is gated by a ``CIP30OriginPolicy``. Default is
``CIP30OriginPolicy/mainFrameOnly``, which refuses any request from an
iframe (ad, embed, third-party widget). Use
``CIP30OriginPolicy/allowOrigins(_:)`` to permit specific embedded dApps;
use ``CIP30OriginPolicy/custom(_:)`` for anything else.

```swift
// Default: only the main frame can talk to the wallet.
let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")

// Allow a known embedded dApp.
let bridge = try CIP30WebBridge(
    initial: initial,
    walletKey: "swiftWallet",
    originPolicy: .allowOrigins(["https://app.example"])
)
```

Enable state is tracked **per origin**. `enable()` for
`https://app-a.example` does not authorize `https://attacker.example`.
Call ``CIP30WebBridge/invalidate(origin:)`` when the user disconnects a
single dApp, ``CIP30WebBridge/invalidateAll()`` on app sign-out.

## Gate 3 — Per-operation approval

A successful `enable()` doesn't grant unbounded signing. Every
`signTx` / `signData` / `submitTx` request is run through a
``CIP30ApprovalPolicy``. Default is ``CIP30ApprovalPolicy/denyAll`` —
the reference key-store provider will refuse everything until you supply
a policy that prompts a user.

```swift
let approvals = CIP30ApprovalPolicy(
    approveSignTx: { tx, _, ctx in
        await MyConsentUI.confirmSignTx(tx, requestedBy: ctx?.origin)
    },
    approveSignData: { addr, payload, ctx in
        await MyConsentUI.confirmSignData(addr, payload, requestedBy: ctx?.origin)
    },
    approveSubmitTx: { _, ctx in
        await MyConsentUI.confirmSubmitTx(requestedBy: ctx?.origin)
    }
)
```

The closures receive the origin in their ``CIP30RequestContext`` so the
UI sheet can show *who* is asking, not just *what*.

``CIP30ApprovalPolicy/allowAll`` exists for tests and developer
harnesses. Don't ship it.

## Transport

The bridge uses `WKScriptMessageHandlerWithReply` (iOS 14 / macOS 11+),
so the shim contains no global resolver functions on `window`.
Predictable RPC ids and global `window.__cip30_*` callbacks — both
reachable by any script in the page — were removed.

Refused requests come back as a JSON error envelope (`{code, info}`, or
`{maxSize, info}` for ``PaginateError``) carried in the rejection's
`Error.message`; the shim re-parses it so dApp `catch` handlers receive
the structured object the spec asks for.

## What the host app owns

The library is refuse-by-default. The host app supplies:

- The consent / approval UI behind every closure.
- ``CIP30WebBridge/invalidate(origin:)`` calls when the user explicitly
  disconnects a dApp.
- ``CIP30WebBridge/invalidateAll()`` on app sign-out, if applicable.
- The ``CIP30OriginPolicy`` that matches your embedding model.
  ``CIP30OriginPolicy/mainFrameOnly`` is the safe choice for "load
  arbitrary dApps in a webview"; relax it only when the embedding model
  demands it.
- A ``CIP30DataSource`` (UTxOs, submit) for the reference
  ``KeyStoreCIP30Provider``. The library doesn't ship chain access.

## See Also

- <doc:CIP30-Overview>
- ``CIP30WebBridge``
- ``CIP30OriginPolicy``
- ``CIP30ApprovalPolicy``
- ``CIP30RequestContext``
