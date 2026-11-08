## 0.5.2 (2026-11-08)

## 0.5.1 (2026-11-08)

## 0.5.0 (2026-11-08)

### Fix

- **cip100**: refuse non-UTF-8 documents and bound CIP-119 JSON depth
- **cip14**: decode hex strictly and check policy and name lengths
- **cip30**: keep revocations through pending enables and sign the requested address
- **cip21**: throw on huge lengths, invalid text, stray breaks and deep nesting

## 0.4.5 (2026-11-08)

### Fix

- check CIP-100 nesting depth before JSONSerialization parses it

## 0.4.4 (2026-11-08)

### Fix

- **cip100**: bound canonicalization, hash strictly and count every listed author
- **cip8**: return the exact signed payload and bind stake keys by envelope type
- **cip36**: sign the label-wrapped sign_data that CIP-36 verifiers rebuild

## 0.4.3 (2026-11-07)

## 0.4.2 (2026-11-06)

### Fix

- **cip119**: escape DRep metadata JSON and write doNotList
- **cip100**: hash only the body and its context for author witnesses
- **cip30**: reject malformed pagination instead of trapping
- **cip8**: throw on malformed signed messages instead of trapping
- **cip8**: write the unprotected header as a map, not null

## 0.4.1 (2026-10-30)

### Fix

- **cip36**: encode a delegation weight without trapping on 32-bit Int
- build against swift-cardano-core 0.10

## 0.4.0 (2026-10-07)

### Feat

- **cip21**: check transactions for hardware wallets, and write bodies the CIP-21 way

## 0.3.8 (2026-06-13)

### Feat

- add CIP-1855 minting policy key support

## 0.3.7 (2026-06-07)

### Fix

- security patches

## 0.3.6 (2026-06-07)

### Fix

- update swift-cose to latest

## 0.3.5 (2026-06-06)

### Fix

- update docs and fix test

## 0.3.4 (2026-06-06)

### Fix

- improve cross platform
- add more CIPs for signer

## 0.3.3 (2026-05-31)

### Fix

- update SwiftCOSE to latest

## 0.3.2 (2026-05-29)

### Fix

- use correct name and handle test warning

## 0.3.1 (2026-05-29)

### Fix

- update dependencies

## 0.3.0 (2026-05-26)

### Feat

- migrate to CBORCodable

## 0.2.2 (2026-05-15)

### Fix

- improve cip30 implementation

## 0.2.1 (2026-05-11)

### Fix

- improve platform compatibility

## 0.2.0 (2026-05-09)

### Feat

- add CIP30 capabilities

## 0.1.2 (2025-08-24)

### Fix

- update core and cose

## 0.1.1 (2025-08-24)

### Fix

- update to new usage
- update packages
