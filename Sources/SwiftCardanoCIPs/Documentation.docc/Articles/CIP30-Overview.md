# CIP-30 dApp Connector

Stand up a CIP-30 wallet that dApps can drive from a `WKWebView` over the
standard `window.cardano.<walletKey>` interface.

## Overview

[CIP-30](https://cips.cardano.org/cip/CIP-0030) is the
dApp-Wallet web bridge: a JS interface dApps already speak.
`SwiftCardanoCIPs` ships three pieces:

- ``CIP30WebBridge`` — injects a JS shim into a `WKWebView` and routes RPC
  calls to a Swift backend.
- A pair of protocols — ``CIP30Initial`` (unauthenticated; `info`, `enable`,
  `isEnabled`) and ``CIP30Provider`` (post-`enable`; all the chain queries
  and signing methods).
- A reference implementation —  ``KeyStoreCIP30Initial`` and
  ``KeyStoreCIP30Provider`` — backed by a single payment / stake key pair
  plus your ``CIP30DataSource`` chain access.

For the security model — origin scoping, identifier validation,
per-operation approval — see <doc:CIP30-Security>.

## A typical setup

```swift
import SwiftCardanoCIPs

let info = WalletInfo(name: "SwiftWallet", icon: "data:image/png;base64,...")

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

let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")
bridge.attach(to: webView)
```

The dApp side is the standard CIP-30 surface:

```js
const api = await window.cardano.swiftWallet.enable();
const network = await api.getNetworkId();
const balance = await api.getBalance();
const witnessSet = await api.signTx(txCborHex, false /* partialSign */);
```

## Plugging in chain data

`KeyStoreCIP30Provider` doesn't ship its own chain access. Provide a
``CIP30DataSource``:

```swift
struct BlockfrostSource: CIP30DataSource {
    let client: BlockfrostClient

    func utxos(for address: String) async throws -> [UTxO] { … }
    func submit(_ tx: Data) async throws -> String { … }
}
```

`utxos(for:)` is consulted whenever the dApp asks for UTxOs / balance /
collateral; `submit(_:)` is what `submitTx` calls after the approval
policy clears.

## Plugging in a custom provider

If your wallet needs multi-address support, an external signer (HSM,
hardware wallet), or a chain interface that doesn't fit ``CIP30DataSource``,
implement the ``CIP30Provider`` protocol directly and return it from your
``CIP30Initial`` `enable(extensions:context:)` instead of using the
key-store reference.

`CIP30WebBridge` only talks to the protocols — it doesn't know or care that
the key-store version exists.

## Errors over the wire

dApp `catch` blocks get the structured CIP-30 errors (`{code, info}` or
`{maxSize, info}` for ``PaginateError``), not raw Swift error strings. The
JS shim re-parses the JSON envelope the Swift side sends, so dApps see the
shape the spec asks for.

The error enums to know:

- ``APIError`` — generic refused / internal error / account-change.
- ``TxSignError`` — `signTx` failures.
- ``DataSignError`` — `signData` failures (including the "address has no
  payment key" case the spec requires).
- ``TxSendError`` — `submitTx` failures.
- ``PaginateError`` — `getUtxos`/`getUsedAddresses` page out of range.

## See Also

- <doc:CIP30-Security>
- ``CIP30WebBridge``
- ``CIP30Initial``
- ``CIP30Provider``
- ``KeyStoreCIP30Initial``
- ``KeyStoreCIP30Provider``
