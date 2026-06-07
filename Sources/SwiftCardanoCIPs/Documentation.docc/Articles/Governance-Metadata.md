# Governance Metadata

Sign and verify CIP-100 / CIP-119 governance JSON-LD documents — DRep
metadata, governance-action rationales, and friends.

## Overview

[CIP-100](https://cips.cardano.org/cip/CIP-0100) is the framework: a JSON-LD
document plus an `authors` array, each entry containing an Ed25519 witness
over the RDFC-1.0-canonicalized body. CIP-108 (governance action
rationales), [CIP-119](https://cips.cardano.org/cip/CIP-0119) (DRep
metadata), and CIP-136 use the same framework with their own schemas
layered on top.

The CIP-100 implementation handles the signing and verification flow.
The CIP-119 implementation provides a typed schema for DRep metadata.

### What gets signed

CIP-100 specifies that the canonical body excludes the `authors` field —
otherwise each new author would invalidate every prior signature.
``CIP100/signMetadata(document:signingKey:authorName:)`` strips the field,
canonicalizes, signs the hash, and appends the new author entry to the
document it returns.

``CIP100/verifyMetadata(_:)`` does the same canonicalization, hashes the
body once, and verifies every author witness in parallel against the
shared hash.

## DRep metadata example

```swift
let dRep = DRepMetadata(
    paymentAddress: nil,
    givenName: "Alice",
    image: ImageObject(
        contentUrl: "https://example.com/avatar.png",
        sha256: "…"
    ),
    objectives: "Govern with the long-term interests of stakers in mind.",
    motivations: "I've worked in protocol governance for five years.",
    qualifications: nil,
    references: [
        Reference(type: "Other", label: "Twitter", uri: "https://twitter.com/alice")
    ],
    doNotList: false
)

guard let json = dRep.toJSON() else { fatalError("encode failed") }

let signed = try await CIP100.signMetadata(
    document: Data(json.utf8),
    signingKey: .signingKey(dRepSK),
    authorName: "Alice"
)

// blake2b-256 of canonical JSON — what you put in the on-chain anchor.
let anchorHash = try dRep.hash()
```

## Verifying

```swift
let result = try await CIP100.verifyMetadata(signed)
precondition(result.allValid)
for author in result.authorResults {
    print(author.name ?? "<anonymous>", author.verified)
}
```

``CIP100/VerificationResult/canonicalBodyHash`` is exposed so you can
compare it against an on-chain anchor hash.

## HSM / external signer flow

If the signing key lives in an HSM or a hardware wallet, pre-compute the
hash, sign it externally, and assemble the author entry yourself:

```swift
let hash = try await CIP100.canonicalBodyHash(of: jsonBytes)
let signature = try myHSM.signEd25519(hash)
// Then construct an Author with a Witness manually and append.
```

## Gotchas

- The flow is `async` — JSON-LD canonicalization is asynchronous.
- Public keys and signatures in the JSON are **hex strings**, not raw
  bytes.
- DRep metadata's `givenName` is required. Everything else is optional —
  unset values omit their fields in the serialized JSON.
- `hash()` digests the canonical JSON form, which is what the on-chain
  governance anchor expects.

## See Also

- ``CIP100``
- ``CIP119Error``
- ``DRepMetadata``
- ``CIP100/Author``
- ``CIP100/Witness``
