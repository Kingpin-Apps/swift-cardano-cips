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

``CIP8Error`` covers the cases where the inputs are structurally invalid —
unparseable hex, an unsupported key shape, an address that can't be
decoded. Real signature mismatches surface as
``VerificationResult/verified`` = `false`, not as a throw.

## See Also

- ``CIP8``
- ``SignedMessage``
- ``VerificationResult``
- <doc:CIP30-Overview>
