# ``SwiftCardanoCIPs``

Swift implementations of Cardano Improvement Proposals — message signing,
voting registration, asset fingerprinting, governance metadata, and a
CIP-30 dApp bridge for `WKWebView`.

## Overview

`SwiftCardanoCIPs` is built on
[`SwiftCardanoCore`](https://github.com/Kingpin-Apps/swift-cardano-core)
and exposes one entry point per CIP. Most are pure value APIs (static
functions on a CIP-named type), and a couple — most notably CIP-100 and
the CIP-30 web bridge — own a small amount of state.

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
