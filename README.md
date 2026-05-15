# SwiftCardanoCIPs - Swift implementation of Cardano Improvement Proposals

This repository contains Swift implementation of Cardano Improvement Proposals (CIPs) and depends upon SwiftCardanoCore library.

## Usage
To add SwiftCardanoCIPs as dependency to your Xcode project, select `File` > `Swift Packages` > `Add Package Dependency`, enter its repository URL: `https://github.com/Kingpin-Apps/swift-cardano-cips.git` and import `SwiftCardanoCIPs`.

Then, to use it in your source code, add:

```swift
import SwiftCardanoCIPs
```

## CIP-30 web-bridge security model

`CIP30WebBridge` exposes a Swift wallet to a `WKWebView` as `window.cardano.<walletKey>`,
matching the JS surface dApps already speak. Wallet integrators are responsible for the
consent UI; the library is responsible for making sure that consent decisions are scoped
correctly and that nothing slips past the gates.

There are three independent gates between an incoming RPC and any wallet action:

1. **Identifier validation** — `walletKey` and `messageHandlerName` must match
   `^[A-Za-z0-9_]{1,64}$`. The bridge `init` throws `CIP30WebBridgeError.invalidIdentifier`
   on anything else, so a misconfigured wallet can't accidentally inject JS into pages
   via the wallet name.
2. **Origin policy** — every RPC is gated by a `CIP30OriginPolicy`. Default is
   `.mainFrameOnly`, which refuses any request from an iframe (ad, embed, third-party
   widget). Use `.allowOrigins([...])` to permit specific embedded dApps; use `.custom`
   for anything else.
3. **Per-operation approval** — `KeyStoreCIP30Provider` consults a `CIP30ApprovalPolicy`
   before signing or submitting. The default is `.denyAll`. Real wallets must supply a
   policy whose closures pop a UI sheet, hit biometrics, etc. `.allowAll` exists for
   tests and developer harnesses only.

Enable state is tracked **per origin**. `enable()` for `https://app-a.example` does not
authorize `https://attacker.example`. `bridge.invalidate(origin:)` and
`bridge.invalidateAll()` clear the state when the user disconnects a dApp or signs out.

The transport itself uses `WKScriptMessageHandlerWithReply` (iOS 14 / macOS 11+), so the
shim contains no global resolver functions on `window`. Predictable RPC ids and global
`window.__cip30_*` callbacks — both reachable by any script in the page — were removed.
Refused requests come back as a JSON error envelope (`{code, info}`, or `{maxSize, info}`
for `PaginateError`) carried in the rejection's `Error.message`; the shim re-parses it so
dApp `catch` handlers receive the structured object the spec asks for.

### Minimal wiring

```swift
import SwiftCardanoCIPs

let info = WalletInfo(name: "SwiftWallet", icon: "data:image/png;base64,...")

// Real wallets gate sensitive operations behind a consent UI. .allowAll is for tests.
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

let initial = KeyStoreCIP30Initial(
    info: info,
    consent: { extensions, ctx in
        await MyConsentUI.confirmEnable(origin: ctx.origin, extensions: extensions)
    },
    makeProvider: { extensions, _ in
        try KeyStoreCIP30Provider(
            info: info,
            paymentKey: paymentSK,
            stakeKey: stakeSK,
            network: .mainnet,
            dataSource: myChainDataSource,
            grantedExtensions: extensions,
            policy: approvals
        )
    }
)

// Default originPolicy = .mainFrameOnly. Override with .allowOrigins(["https://app.example"])
// only if you intentionally embed a dApp inside a parent page that should also be a wallet
// client.
let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")
bridge.attach(to: webView)
```

### What the dApp sees

Once attached, the dApp can use the standard CIP-30 entry point:

```js
const api = await window.cardano.swiftWallet.enable();
const network = await api.getNetworkId();
const witnessSet = await api.signTx(txCborHex, false /* partialSign */);
```

### Things the host app is on the hook for

- Implementing the consent / approval UI. The library will refuse-by-default if you don't.
- Calling `bridge.invalidate(origin:)` when the user explicitly disconnects a dApp.
- Calling `bridge.invalidateAll()` on app sign-out, if applicable.
- Choosing an `originPolicy` that matches your embedding model. Default `.mainFrameOnly`
  is the safe choice for "load arbitrary dApps in a webview."

