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

CIP-100 witnesses sign the document's `body`, so adding an author never
invalidates earlier signatures.
``CIP100/signMetadata(document:signingKey:authorName:)`` keeps only
`@context` and `body` (dropping `authors`, `hashAlgorithm` and any other
top-level field), canonicalizes that with RDFC-1.0 (URDNA2015), hashes it
with Blake2b-256, signs the hash, and appends the new author entry to the
document it returns. This is the procedure in CIP-100's `test-vector.md`,
and it reproduces that example's published hash and signature. A document
with no `body` throws ``CIP100Error/missingField(_:)``.

``CIP100/verifyMetadata(_:)`` does the same canonicalization, hashes the
document once, and checks every author witness, in document order,
against that hash.

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

guard let json = try dRep.toJSON() else { fatalError("encode failed") }

let signed = try await CIP100.signMetadata(
    document: Data(json.utf8),
    signingKey: .signingKey(dRepSK),
    authorName: "Alice"
)
```

`signed` holds the document bytes to publish. The on-chain anchor hash is
the Blake2b-256 of exactly the bytes you publish, so compute it over
`signed`. ``DRepMetadata/hash()`` hashes the unsigned `toJSON()` output,
so it only matches the anchor if you publish that unsigned document as it
is.

## Verifying

```swift
let result = try await CIP100.verifyMetadata(signed)
precondition(result.allValid)
for author in result.authorResults {
    print(author.name ?? "<anonymous>", author.valid)
}
```

``CIP100/VerificationResult/canonicalBodyHash`` is the hash every witness
signs. It is not the on-chain anchor hash, which covers the raw document
bytes.

## HSM / external signer flow

If the signing key lives in an HSM or a hardware wallet, pre-compute the
hash, sign it externally, and assemble the author entry yourself:

```swift
let hash = try await CIP100.canonicalBodyHash(of: jsonBytes)
let signature = try myHSM.signEd25519(hash)
```

Then add the author entry to the document's `authors` array yourself, in
the same shape `signMetadata` writes:

```json
{
  "name": "Alice",
  "witness": {
    "witnessAlgorithm": "ed25519",
    "publicKey": "<32-byte public key, hex>",
    "signature": "<64-byte signature, hex>"
  }
}
```

``CIP100/Author`` and ``CIP100/Witness`` model this shape, but there is no
API that writes them into a document for you.

## Gotchas

- The flow is `async` — JSON-LD canonicalization is asynchronous.
- Public keys and signatures in the JSON are **hex strings**, not raw
  bytes.
- DRep metadata's `givenName` is required. Everything else is optional,
  and ``DRepMetadata/toJSON()`` leaves out what you didn't set (an empty
  `references` array is still written as `[]`). Every string is
  JSON-escaped. `doNotList` is written as `"doNotList": true` when set;
  `false` is left out, since CIP-119 reads a missing `doNotList` as
  `false`. When decoding, the boolean and the schema's `"true"` / `"false"`
  strings are both accepted.
- A fully filled-in ``DRepMetadata`` gives the same bytes as CIP-119's
  `examples/drep.jsonld`, so ``DRepMetadata/hash()`` matches that file.
- ``DRepMetadata/hash()`` is the Blake2b-256 of the `toJSON()` string
  bytes. It is not a canonical (JSON-LD) hash.

## See Also

- ``CIP100``
- ``CIP119Error``
- ``DRepMetadata``
- ``CIP100/Author``
- ``CIP100/Witness``
