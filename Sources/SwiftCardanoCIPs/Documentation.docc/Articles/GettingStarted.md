# Getting Started

Install `SwiftCardanoCIPs`, import it, and pick the CIP you need.

## Installation

### Swift Package Manager

```swift
.package(url: "https://github.com/Kingpin-Apps/swift-cardano-cips.git", from: "0.3.3")
```

then in your target:

```swift
.target(
    name: "MyApp",
    dependencies: [
        .product(name: "SwiftCardanoCIPs", package: "swift-cardano-cips")
    ]
)
```

### Xcode

`File` → `Add Package Dependencies…` → enter
`https://github.com/Kingpin-Apps/swift-cardano-cips.git` → add the
`SwiftCardanoCIPs` library to your target.

### Import

```swift
import SwiftCardanoCIPs
```

## Platforms

| Platform   | Minimum    |
| ---------- | ---------- |
| iOS        | 16         |
| macOS      | 14         |
| tvOS       | 16         |
| watchOS    | 9          |
| visionOS   | 1          |
| Linux      | Swift 6.1+ |

``CIP30WebBridge`` is only available where `WebKit` is — iOS, macOS,
visionOS.

## A typical message signing

```swift
import SwiftCardanoCIPs
import SwiftCardanoCore

let paymentSK = try PaymentSigningKey.fromTextEnvelope(envelopeJSON)

let signed = try CIP8.sign(
    message: "hello dApp",
    signingKey: .signingKey(paymentSK),
    attachCoseKey: true,
    network: .mainnet
)

let result = try CIP8.verify(signedMessage: signed)
precondition(result.verified)
```

For more on ``CIP8``, see <doc:CIP8-MessageSigning>.

## Building a wallet bridge

```swift
let bridge = try CIP30WebBridge(
    initial: keyStoreCIP30Initial,
    walletKey: "swiftWallet"
)
bridge.attach(to: webView)
```

The dApp side calls `window.cardano.swiftWallet.enable()` and gets the
standard CIP-30 API. For the security model, see
<doc:CIP30-Security>.

## Topics

- <doc:CIP8-MessageSigning>
- <doc:CIP30-Overview>
- <doc:CIP30-Security>
- <doc:Governance-Metadata>
