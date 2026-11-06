# ``SwiftCardanoCIPs``

Swift implementations of Cardano Improvement Proposals: message signing,
hardware-wallet transaction checks, asset fingerprints, policy keys,
voting and pool-key registration, governance metadata and IDs, and a
CIP-30 dApp bridge for `WKWebView`.

## Overview

`SwiftCardanoCIPs` is built on
[`SwiftCardanoCore`](https://github.com/Kingpin-Apps/swift-cardano-core)
and exposes one entry point per CIP. Most are pure value APIs (static
functions on a CIP-named type), and a couple — most notably CIP-100 and
the CIP-30 web bridge — own a small amount of state.

The package implements these CIPs:

| CIP | What you get | Entry point |
| --- | --- | --- |
| [CIP-8](https://cips.cardano.org/cip/CIP-0008) | COSE_Sign1 message signing and verification | ``CIP8`` |
| [CIP-14](https://cips.cardano.org/cip/CIP-0014) | `asset1…` fingerprints for native assets | ``CIP14`` |
| [CIP-21](https://cips.cardano.org/cip/CIP-0021) | Whether hardware wallets can sign a transaction, and writing a body the way they ask | `CIP21` (in `SwiftCardanoCIP21`) |
| [CIP-30](https://cips.cardano.org/cip/CIP-0030) | dApp connector for `WKWebView`, plus a reference key-store wallet | ``CIP30WebBridge`` |
| [CIP-36](https://cips.cardano.org/cip/CIP-0036) | Catalyst voting registration and deregistration metadata | ``CIP36`` |
| [CIP-88](https://cips.cardano.org/cip/CIP-0088) | Stake pool Calidus key registration metadata | ``CIP88`` |
| [CIP-100](https://cips.cardano.org/cip/CIP-0100) | Signing and verifying governance metadata documents | ``CIP100`` |
| [CIP-119](https://cips.cardano.org/cip/CIP-0119) | DRep metadata schema | ``DRepMetadata`` |
| [CIP-129](https://cips.cardano.org/cip/CIP-0129) | Bech32 IDs for DReps, committee keys and Calidus keys | ``CIP129`` |
| [CIP-1855](https://cips.cardano.org/cip/CIP-1855) | Minting-policy key paths, scripts and policy IDs | ``CIP1855`` |

CIP-21 is its own product, `SwiftCardanoCIP21`, with no dependencies, so
transaction builders can use it alone. `SwiftCardanoCIPs` re-exports it,
so `import SwiftCardanoCIPs` also gives you `CIP21`, `CIP21Report` and
the other CIP-21 types. Their reference documentation is under the
`SwiftCardanoCIP21` module.

```swift
import SwiftCardanoCIPs

let signed = try CIP8.sign(
    message: "hello dApp",
    signingKey: .signingKey(paymentSK),
    attachCoseKey: true
)
```

## Topics

### Message signing

- ``CIP8``
- ``SignedMessage``
- ``VerificationResult``
- ``CIP8Error``

### Native assets

- ``CIP14``
- ``PolicyIdType``
- ``AssetNameType``
- ``CIP14Error``

### Minting-policy keys (CIP-1855)

- ``CIP1855``
- ``CIP1855Error``

### dApp connector (CIP-30)

- <doc:CIP30-Overview>
- ``CIP30WebBridge``
- ``CIP30Initial``
- ``CIP30Provider``
- ``WalletInfo``
- ``CIP30RequestContext``
- ``CIP30OriginPolicy``
- ``CIP30WebBridgeError``

### CIP-30 reference key-store implementation

- ``KeyStoreCIP30Initial``
- ``KeyStoreCIP30Provider``
- ``CIP30DataSource``
- ``CIP30ApprovalPolicy``

### CIP-30 RPC types

- ``Paginate``
- ``Extension``
- ``DataSignature``
- ``APIError``
- ``TxSignError``
- ``DataSignError``
- ``TxSendError``
- ``PaginateError``
- ``CIP30ErrorEnvelope``

### Catalyst voting (CIP-36)

- ``CIP36``
- ``CIP36/Delegation``
- ``CIP36Error``

### Pool Calidus key (CIP-88)

- ``CIP88``
- ``CIP88Error``

### Governance metadata (CIP-100)

- ``CIP100``
- ``CIP100/Witness``
- ``CIP100/Author``
- ``CIP100/VerificationResult``
- ``CIP100Error``

### DRep metadata (CIP-119)

- ``DRepMetadata``
- ``ImageObject``
- ``Reference``
- ``CIP119Error``

### Governance credential IDs (CIP-129)

- ``CIP129``
- ``CIP129Error``

### Articles

- <doc:GettingStarted>
- <doc:CIP8-MessageSigning>
- <doc:CIP30-Overview>
- <doc:CIP30-Security>
- <doc:Governance-Metadata>
