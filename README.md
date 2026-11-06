# SwiftCardanoCIPs

[![CI](https://img.shields.io/github/actions/workflow/status/Kingpin-Apps/swift-cardano-cips/swift.yml?branch=main&label=CI&logo=github)](https://github.com/Kingpin-Apps/swift-cardano-cips/actions/workflows/swift.yml)
[![Release](https://img.shields.io/github/v/release/Kingpin-Apps/swift-cardano-cips?display_name=tag&sort=semver&logo=github)](https://github.com/Kingpin-Apps/swift-cardano-cips/releases)
[![Swift Package Index](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKingpin-Apps%2Fswift-cardano-cips%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/Kingpin-Apps/swift-cardano-cips)
[![Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKingpin-Apps%2Fswift-cardano-cips%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/Kingpin-Apps/swift-cardano-cips)
[![License](https://img.shields.io/github/license/Kingpin-Apps/swift-cardano-cips)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/Kingpin-Apps/swift-cardano-cips/main?logo=github)](https://github.com/Kingpin-Apps/swift-cardano-cips/commits/main)

Swift implementations of Cardano Improvement Proposals, built on
[swift-cardano-core](https://github.com/Kingpin-Apps/swift-cardano-core).
Use it to sign messages, check transactions for hardware wallets, register
voting/Calidus keys, encode native-asset fingerprints, derive minting-policy
keys and policy IDs, sign and verify governance metadata, derive CIP-129
governance IDs, and stand up a CIP-30 wallet for a `WKWebView` dApp surface.

| CIP   | What you get                                                                 | Type   |
| ----- | ---------------------------------------------------------------------------- | ------ |
| [CIP-8](#cip-8--message-signing)   | COSE_Sign1 message signing / verification with optional COSE_Key      | sign   |
| [CIP-21](#cip-21--hardware-wallet-transactions) | Whether hardware wallets can sign a transaction, and writing a body the way they ask | tx    |
| [CIP-14](#cip-14--native-asset-fingerprint) | `asset1…` bech32 fingerprints for native assets                | utility |
| [CIP-30](#cip-30--dapp-connector-for-wkwebview) | `window.cardano.<wallet>` bridge for `WKWebView`, plus a reference key-store provider | bridge |
| [CIP-36](#cip-36--catalyst-voting-registration) | Catalyst voting registration & deregistration metadata          | tx-meta |
| [CIP-88](#cip-88--calidus-pool-key-registration) | Pool-operator Calidus key registration                         | tx-meta |
| [CIP-100](#cip-100--governance-metadata-signing) | Sign / verify governance JSON-LD metadata documents            | sign   |
| [CIP-119](#cip-119--drep-metadata) | DRep metadata schema (built on CIP-100)                                     | schema |
| [CIP-129](#cip-129--governance-credential-bech32) | `drep1…` / `cc_cold1…` / `cc_hot1…` / `calidus1…` IDs            | utility |
| [CIP-1855](#cip-1855--minting-policy-keys) | Minting-policy key derivation path, native script and policy ID | utility |

## Installation

### Swift Package Manager

Add the package as a dependency in `Package.swift`:

```swift
.package(url: "https://github.com/Kingpin-Apps/swift-cardano-cips.git", from: "0.4.1")
```

then in your target:

```swift
.target(name: "MyApp", dependencies: [
    .product(name: "SwiftCardanoCIPs", package: "swift-cardano-cips")
])
```

### Xcode

`File` → `Add Package Dependencies…` → enter
`https://github.com/Kingpin-Apps/swift-cardano-cips.git` → add the
`SwiftCardanoCIPs` library to your target.

If you only need CIP-21, depend on the `SwiftCardanoCIP21` product
instead. `SwiftCardanoCIPs` re-exports it, so you don't need both.

### Import

```swift
import SwiftCardanoCIPs
```

## Platforms

| Platform   | Minimum   |
| ---------- | --------- |
| iOS        | 16        |
| macOS      | 14        |
| tvOS       | 16        |
| watchOS    | 9         |
| visionOS   | 1         |
| Linux      | Swift 6.1+ |

`CIP30WebBridge` is only available where `WebKit` exists (iOS, macOS,
visionOS).

## CIP-8 — message signing

[`CIP-8`](https://cips.cardano.org/cip/CIP-0008) signs an arbitrary payload
with a payment or stake key, producing a COSE_Sign1 envelope a wallet bridge
or off-chain verifier can validate.

```swift
let signed = try CIP8.sign(
    message: "hello dApp",
    signingKey: .signingKey(paymentSK),
    attachCoseKey: true,
    network: .mainnet
)

let result = try CIP8.verify(signedMessage: signed)
assert(result.verified)
assert(result.message == "hello dApp")
```

Notes:

- Same input produces a **byte-identical** signed message every time —
  signing routes through libsodium's deterministic Ed25519 (RFC 8032), not
  CryptoKit's hedged variant. This matches `cardano-signer.js` output
  exactly, which CIP-30 dApp bridges and offline signing tools rely on.
- Stake keys must be passed as `StakeSigningKey` or
  `StakeExtendedSigningKey` to derive a stake address. Anything else is
  treated as a payment key.
- `attachCoseKey: true` ships the public COSE_Key alongside the signature
  (CIP-30 `signData` shape). `attachCoseKey: false` embeds the verification
  key in the protected header (kid).
- `verify` returns `verified == false` when the signature doesn't match the
  key or the address doesn't belong to the key. That holds for a 32-byte key
  and for a 64-byte extended key (key plus chain code) in the `kid` header,
  which is checked against its first 32 bytes.
- `verify` treats its input as untrusted: a malformed message (bad hex or
  CBOR, no `address` header, an algorithm other than EdDSA, a detached
  payload, a missing or malformed key) throws a `CIP8Error` and never traps.
  Address bytes that don't decode throw the address decoding error.

## CIP-21 — hardware wallet transactions

[`CIP-21`](https://cips.cardano.org/cip/CIP-0021) sets out how a
transaction must be written for Ledger, Trezor and Keystone to sign it. It
is its own product, `SwiftCardanoCIP21`, with no dependencies, so a
transaction builder can use it without the rest of this package.

```swift
import SwiftCardanoCIP21

let report = try CIP21.report(transactionCBOR)
report.mode          // .ordinary, .multisig, .plutus or .poolRegistration
report.isCompatible  // false: report.findings says why, and whether each is fixable

let body = try CIP21.compatibleBody(bodyCBOR)
```

- `report` reads the CBOR as written: canonical encoding, empty
  collections, sets tagged 258 everywhere or nowhere, certificates hardware
  wallets refuse, and a pool registration that is not alone.
- `compatibleBody` writes a body canonically, leaves out empty collections
  and tags every set. The bytes change, and with them the transaction id and
  the size the fee is charged on, so call it while building, before the fee
  is worked out. `swift-cardano-txbuilder` does this with
  `cip21Compatible`. Rewriting the body of a transaction that is already
  built leaves its fee sized for other bytes, and the node refuses it.

## CIP-14 — native asset fingerprint

[`CIP-14`](https://cips.cardano.org/cip/CIP-0014) derives the `asset1…`
fingerprint exchanges and explorers display for native tokens.

```swift
let fingerprint = try CIP14.encodeAsset(
    policyId: .hexString("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373"),
    assetName: .hexString("504154415445")
)
// "asset13n25uv0yaf5kus35fm2k86cqy60z58d9xmde92"
```

Inputs accept several forms, so you don't have to pre-convert: the policy
as `.policyId(PolicyID)`, `.data(Data)` or `.hexString(String)`, and the
asset name as `.assetName(AssetName)`, `.data(Data)` or
`.hexString(String)`. Returns `nil` if bech32 encoding fails.

## CIP-30 — dApp connector for WKWebView

[`CIP-30`](https://cips.cardano.org/cip/CIP-0030) is the
dApp-Wallet web bridge. `CIP30WebBridge` injects a JS shim into a
`WKWebView` as `window.cardano.<walletKey>`, so dApps can call
`enable()`, `signTx`, `signData`, `submitTx`, etc. without changes.

### Security model

Three independent gates sit between an incoming RPC and any wallet action:

1. **Identifier validation** — `walletKey` and `messageHandlerName` must
   match `^[A-Za-z0-9_]{1,64}$`. The bridge `init` throws
   `CIP30WebBridgeError.invalidIdentifier` on anything else, so a
   misconfigured wallet can't accidentally inject JS into pages via the
   wallet name.
2. **Origin policy** — every RPC is gated by a `CIP30OriginPolicy`. Default
   is `.mainFrameOnly`, which refuses any request from an iframe (ad,
   embed, third-party widget). Use `.allowOrigins([...])` to permit specific
   embedded dApps; use `.custom` for anything else.
3. **Per-operation approval** — `KeyStoreCIP30Provider` consults a
   `CIP30ApprovalPolicy` before signing or submitting. The default is
   `.denyAll`. Real wallets must supply a policy whose closures pop a UI
   sheet, hit biometrics, etc. `.allowAll` exists for tests and developer
   harnesses only.

Enable state is tracked **per origin**. `enable()` for
`https://app-a.example` does not authorize `https://attacker.example`.
`bridge.invalidate(origin:)` and `bridge.invalidateAll()` clear the state
when the user disconnects a dApp or signs out.

The transport itself uses `WKScriptMessageHandlerWithReply`
(iOS 14 / macOS 11+), so the shim contains no global resolver functions on
`window`. Predictable RPC ids and global `window.__cip30_*` callbacks —
both reachable by any script in the page — were removed. Refused requests
come back as a JSON error envelope (`{code, info}`, or `{maxSize, info}`
for `PaginateError`) carried in the rejection's `Error.message`; the shim
re-parses it so dApp `catch` handlers receive the structured object the
spec asks for.

### Minimal wiring

```swift
import SwiftCardanoCIPs

let info = WalletInfo(name: "SwiftWallet", icon: "data:image/png;base64,...")

// Real wallets gate sensitive operations behind a consent UI.
// .allowAll is for tests.
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

// Default originPolicy = .mainFrameOnly. Override with
// .allowOrigins(["https://app.example"]) only if you intentionally embed
// a dApp inside a parent page that should also be a wallet client.
let bridge = try CIP30WebBridge(initial: initial, walletKey: "swiftWallet")
bridge.attach(to: webView)
```

### What the dApp sees

Once attached, the dApp uses the standard CIP-30 entry point:

```js
const api = await window.cardano.swiftWallet.enable();
const network = await api.getNetworkId();
const witnessSet = await api.signTx(txCborHex, false /* partialSign */);
```

### What the host app owns

- Implementing the consent / approval UI. The library will
  refuse-by-default if you don't.
- Calling `bridge.invalidate(origin:)` when the user explicitly disconnects
  a dApp.
- Calling `bridge.invalidateAll()` on app sign-out, if applicable.
- Choosing an `originPolicy` that matches your embedding model. Default
  `.mainFrameOnly` is the safe choice for "load arbitrary dApps in a
  webview."
- Implementing `CIP30DataSource` (`utxos(for: Address)` and `submit(_:)`)
  to surface UTxOs and submit transactions for `KeyStoreCIP30Provider`.
  The library doesn't ship chain access. Without a data source, `getUtxos`
  and `getBalance` throw `APIError.internalError` and `submitTx` throws
  `TxSendError.failure`.

`KeyStoreCIP30Provider` is a single-address reference wallet. Its
`getUtxos` ignores the `amount` argument, and `getCollateral` returns `nil`.
Implement your own `CIP30Provider` if you need more.

## CIP-36 — Catalyst voting registration

[`CIP-36`](https://cips.cardano.org/cip/CIP-0036) registers a stake
credential for Catalyst voting. Build the auxiliary metadata, attach it to
your transaction, and the on-chain witness establishes voting power.

```swift
let aux = try CIP36.makeRegistration(
    delegations: [
        CIP36.Delegation(votingKey: catalystVKey32, weight: 1)
    ],
    stakeSigningKey: .signingKey(stakeSK),
    rewardsAddress: rewardsAddr,
    nonce: currentSlotHeight,
    votingPurpose: 0
)
```

Use `CIP36.makeDeregistration(...)` to revoke a prior registration.

Gotchas:

- Voting keys are exactly **32 bytes** (CIP-36 vote keys, not stake keys).
- `nonce` must strictly increase per on-chain registration for the same
  stake credential — typical pattern is the current slot height.
- Field `2` carries the raw 32-byte stake verification key, not its
  28-byte Blake2b-224 hash.

## CIP-88 — Calidus pool key registration

[`CIP-88` v2 / CIP-151](https://cips.cardano.org/cip/CIP-0088) lets a
pool operator delegate online signing authority (governance votes, hot key
ops, etc.) to a separate Calidus key without exposing the cold key.

```swift
let aux = try CIP88.makeCalidusRegistration(
    calidusPublicKey: calidusEd25519_32bytes,
    poolSigningKey: .signingKey(coldKey),
    nonce: currentSlotHeight
)
```

Behavior matches `cardano-signer.js --cip88`: the signature covers the
Blake2b-256 of the hex-encoded payload CBOR, not of the raw CBOR bytes.

## CIP-100 — governance metadata signing

[`CIP-100`](https://cips.cardano.org/cip/CIP-0100) is the JSON-LD framework
used by CIP-108 (governance actions), CIP-119 (DRep metadata), and friends.
Documents are canonicalized with RDFC-1.0 and signed by one or more authors
with Ed25519 witnesses embedded in the document itself.

```swift
let signed = try await CIP100.signMetadata(
    document: jsonBytes,
    signingKey: .signingKey(authorSK),
    authorName: "Alice"
)

let result = try await CIP100.verifyMetadata(signed)
assert(result.allValid)
```

For HSM-style workflows, derive the hash to sign externally:

```swift
let hash = try await CIP100.canonicalBodyHash(of: jsonBytes)
let signature = try myHSM.signEd25519(hash)
```

Then add the author entry to the document's `authors` array yourself, in
the shape `signMetadata` writes: `{"name": …, "witness": {"witnessAlgorithm":
"ed25519", "publicKey": <hex>, "signature": <hex>}}`. There is no API that
writes it for you.

Notes:

- Async because JSON-LD canonicalization is.
- Signing and verifying hash the `body` only: they keep `@context` and
  `body`, drop every other top-level field (`authors`, `hashAlgorithm`, …),
  canonicalize, then hash, as CIP-100's test vector does. So prior
  signatures don't change the hash, and a document with no `body` throws
  `CIP100Error.missingField("body")`. The official CIP-100 example's author
  witness verifies.
- `verifyMetadata` checks every author in document order; read
  `result.authorResults[i].valid` for each one.
- `canonicalBodyHash` is the hash the witnesses sign. It is not the
  on-chain anchor hash, which covers the raw bytes of the published
  document.
- Public keys and signatures are **hex strings** in the JSON, not raw
  bytes.

## CIP-119 — DRep metadata

[`CIP-119`](https://cips.cardano.org/cip/CIP-0119) defines the DRep
metadata schema (name, image, objectives, motivations, qualifications,
references). It builds on CIP-100 — sign it the same way.

```swift
let dRep = DRepMetadata(
    paymentAddress: nil,
    givenName: "Alice",
    image: nil,
    objectives: "Govern with the long-term interests of stakers in mind.",
    motivations: "I've worked in protocol governance for five years.",
    qualifications: nil,
    references: [
        Reference(type: "Other", label: "Twitter", uri: "https://twitter.com/alice")
    ],
    doNotList: false
)

guard let json = try dRep.toJSON() else { … }
let signed = try await CIP100.signMetadata(
    document: Data(json.utf8),
    signingKey: .signingKey(dRepSK),
    authorName: "Alice"
)

```

The on-chain anchor hash is the Blake2b-256 of exactly the bytes you
publish, so compute it over `signed`. `dRep.hash()` hashes the unsigned
`toJSON()` string (not a canonical form), so it only matches the anchor if
you publish that unsigned document as it is.

`toJSON()` escapes every string, so any text (quotes, backslashes,
newlines, emoji) gives valid JSON. It writes only the body fields you set:
an unset `paymentAddress`, `image`, `objectives`, `motivations`,
`qualifications`, `references` or image `sha256` is left out, and an empty
`references` array is written as `[]`. `doNotList: true` is written as the
boolean `"doNotList": true`; `false` is left out, since CIP-119 reads a
missing `doNotList` as `false`. A fully filled-in document keeps the layout
of CIP-119's `examples/drep.jsonld` byte for byte, so its hash matches.

## CIP-129 — governance credential bech32

[`CIP-129`](https://cips.cardano.org/cip/CIP-0129) defines the
human-readable identifiers for DRep, constitutional-committee, and Calidus
credentials.

```swift
let drepId = try CIP129.encode(
    keyHash: drepKeyHash,  // 28-byte Blake2b-224 hash of the DRep verification key
    as: .drep,
    isScript: false
)
// "drep1…"

let (prefix, hash, isScript) = try CIP129.decode("drep1…")
```

Prefixes: `.drep`, `.ccCold`, `.ccHot`, `.calidus`. Key hash is always 28
bytes. `calidus` has no script form.

## CIP-1855 — minting-policy keys

[`CIP-1855`](https://cips.cardano.org/cip/CIP-1855) defines the HD
derivation path for minting-policy keys, `m/1855'/1815'/policy_ix'`.

```swift
let path = try CIP1855.policyKeyPath(policyIndex: 0)  // "m/1855'/1815'/0'"

let script = CIP1855.mintingPolicyScript(keyHash: policyKeyHash)
let policyID = try CIP1855.policyID(keyHash: policyKeyHash)
```

Without `invalidBefore` the script is a bare `sig` script. With
`invalidBefore: slot` it becomes `all [ invalid_before(slot), sig ]`: the
policy can only be used from that slot onwards (cardano-cli's `"after"`).
It does not make the policy expire. Pass the same `invalidBefore` to
`policyID` as to `mintingPolicyScript`, or the IDs won't match.

## Documentation

Full API reference is in the DocC catalog, published on the
[Swift Package Index](https://swiftpackageindex.com/Kingpin-Apps/swift-cardano-cips).
To build it locally, open the package in Xcode and choose
`Product` → `Build Documentation`.

## Contributing

Tests live alongside each module:

```bash
swift test
```

The CI workflow runs the suite on macOS and on Linux (Swift 6.3). The
CIP-30 unit tests drive the bridge with synthesized request contexts; on
macOS, integration tests also load the JS shim into a real `WKWebView`
to check the shim and the per-origin gating.

## License

[MIT](LICENSE)
