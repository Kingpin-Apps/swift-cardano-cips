# CIP-8 Message Signing

Sign arbitrary payloads and verify them with deterministic Ed25519,
producing the COSE_Sign1 envelope CIP-30 dApps and `cardano-signer.js`
already speak.

## Overview

[CIP-8](https://cips.cardano.org/cip/CIP-0008) wraps an Ed25519 signature
in a COSE_Sign1 structure with a protected header that names the algorithm
and the Cardano address of the signer. Optionally the public key travels
alongside the signature as a separate COSE_Key, which is the shape CIP-30's
`signData` expects.

`SwiftCardanoCIPs` ships ``CIP8/sign(message:signingKey:attachCoseKey:network:)``
and ``CIP8/verify(signedMessage:)`` static methods. There's no instance
state — pass a key and a payload, get bytes back.

### Determinism

Same input produces a **byte-identical** signed message every time.
Signing routes through libsodium's deterministic Ed25519 (RFC 8032), not
CryptoKit's hedged variant, so:

- `cardano-signer.js` and `SwiftCardanoCIPs` produce identical signatures
  for the same payload and key.
- Offline signing tools can store and replay envelopes.
- CIP-30 dApps that expect the same wallet to return the same output for
  the same input do.

## Signing a string

```swift
let signed = try CIP8.sign(
    message: "hello dApp",
    signingKey: .signingKey(paymentSK),
    attachCoseKey: true,
    network: .mainnet
)
```

Returns a ``SignedMessage`` with:

- ``SignedMessage/signature`` — hex of the COSE_Sign1 envelope
  (without the leading `0xD2` CBOR tag, matching the CIP-30 wire shape).
- ``SignedMessage/key`` — hex of the COSE_Key when `attachCoseKey: true`,
  otherwise `nil` (the verification key is then embedded in the protected
  header as `kid`).

## Signing raw bytes

For payloads that aren't UTF-8 strings — for example a CIP-30 `signData`
request — use the `Data` overload:

```swift
let signed = try CIP8.sign(
    payload: payloadBytes,
    signingKey: .signingKey(paymentSK),
    attachCoseKey: true
)
```

## Stake key vs payment key

The signing function looks at the runtime type of the key inside the
`SigningKeyType` enum (defined in `SwiftCardanoCore`):

- `StakeSigningKey` / `StakeExtendedSigningKey` → signing address is the
  stake address.
- Anything else (including a `PaymentSigningKey`) → signing address is the
  payment-only enterprise address.

If you want a stake address in the protected header, the key must be
typed as a stake key — a `SigningKey` typed-erased to something else
falls into the payment branch.

## Verifying

```swift
let result = try CIP8.verify(signedMessage: signed)
precondition(result.verified)
print(result.message)         // "hello dApp"
print(result.signingAddress)  // The address embedded in the protected header
```

`verify` checks two things, both of which must hold for ``VerificationResult/verified``
to be `true`:

1. The Ed25519 signature is valid for the COSE Sig_structure.
2. The address in the protected header is the address derived from the
   verification key used to sign.

## Errors

`verify` takes untrusted input, such as a dApp's or wallet's signed message,
so a malformed message throws rather than trapping. ``CIP8Error`` covers the
structure:

- ``CIP8Error/decodingError(_:)`` — the signature isn't hex, isn't a single
  CBOR item, isn't a four-element COSE_Sign1 array, or has a protected header
  that isn't a map, an unprotected header that isn't a map, or a detached
  (`null`) payload.
- ``CIP8Error/invalidSignature(_:)`` — the algorithm isn't EdDSA (-8), or the
  signature isn't a byte string.
- ``CIP8Error/invalidAddress(_:)`` — there is no `address` header, or it isn't
  a non-empty byte string.
- ``CIP8Error/invalidKey(_:)`` — there is no attached COSE_Key and no `kid`,
  the `kid` isn't 32 or 64 bytes, or the attached COSE_Key isn't an OKP
  Ed25519 key with a 32-byte `x`.

Address bytes that are present but don't decode throw the address decoding
error from `SwiftCardanoCore`, so catch `Error` rather than only ``CIP8Error``.

A signature that doesn't match the key, or an address that doesn't belong to
the signing key, surfaces as ``VerificationResult/verified`` = `false`, not as
a throw. Messages signed by this package carry a 32-byte key. A message from
elsewhere may carry a 64-byte extended key (key plus chain code) in `kid`;
the first 32 bytes are the public key for both the signature and the address
check.

## See Also

- ``CIP8``
- ``SignedMessage``
- ``VerificationResult``
- <doc:CIP30-Overview>
