# CAWG Identity Assertion Module

This directory contains the CAWG-related TypeScript code currently implemented in this repository for identity assertions and ICA (Identity Claims Aggregation) credentials.

## Current Scope

The CAWG module currently provides:

- Type definitions for CAWG payloads and credentials.
- Utility functions for CBOR serialization/deserialization, padding checks, and signer payload conversions.
- Identity assertion validation entry points.
- ICA credential creation and validation utilities.
- DID resolution support for `did:web` and `did:jwk` through a shared resolver instance.

## Public Exports (from `src/cawg/index.ts`)

- All types from `types.ts`
- All helpers from `utils.ts`
- `validateIdentityAssertion()` and `isWellFormedIdentityAssertion()`
- `createIcaCredential()` and `validateIcaCredential()`
- `didResolver`
- Constants:
  - `CAWG_VERSION = '1.2'`
  - `CAWG_RELEASE_DATE = '2025-12-15'`
  - `DEFAULT_ASSERTION_LABEL = 'cawg.identity'`
  - `MAX_TSTR_LENGTH = 4096`

## File Layout

```text
cawg/
├── index.ts
├── types.ts
├── utils.ts
├── validator.ts
├── identity-claims-aggregation.ts
└── did-resolver.ts
```

## Usage Notes

### 1) Creating an ICA credential

```typescript
import { createIcaCredential } from '@trustnxt/c2pa-ts/cawg';

const credential = createIcaCredential(
  issuerDid,
  {
    verifiedIdentities: [
      {
        type: 'cawg.social_media',
        name: 'Sample Creator',
        username: 'sample-creator',
        uri: 'https://example.com/sample-creator',
        provider: {
          id: 'https://example.com',
          name: 'Example Identity Provider',
        },
        verifiedAt: new Date().toISOString(),
      },
    ],
  },
  signerPayload,
  new Date(),
);
```

### 2) Building identity assertions in manifests

Identity assertion construction is currently done through `IdentityAssertion` (manifest assertion class), for example with:

- `setSignerPayload(...)`
- `setSignature(...)`

See `tests/ica-signing.test.ts` for end-to-end examples with JPEG signing and validation.

### 3) Validating identity assertions and ICA credentials

- `validateIdentityAssertion(...)` validates identity assertion structure and references.
- `validateIcaCredential(...)` validates ICA COSE/VC structures and C2PA binding consistency.

## Implemented Helpers

`utils.ts` currently includes helpers such as:

- `serializeSignerPayload()` / `deserializeSignerPayload()`
- `serializeIdentityAssertion()` / `deserializeIdentityAssertion()`
- `calculatePaddingSize()` and `validatePadding()`
- `signerPayloadToC2paAssetBinding()` / `c2paAssetBindingToSignerPayload()`
- `generateUniqueLabel()`
- `extractAssertionLabel()` and `isHardBindingAssertion()`

## Current Limitations

The following behaviors are present in code and should be considered work in progress:

- In `validator.ts`, parts of `expected_countersigners` and claim-generator extraction are marked TODO.
- In `identity-claims-aggregation.ts`, issuer trust verification currently returns `true` (stubbed behavior).
- Multibase DID key material parsing is not implemented.
- Revocation checking is scaffolded but not fully implemented.

## Testing Coverage in Repository

Current tests include ICA and identity assertion scenarios in `tests/ica-signing.test.ts`, including:

- ICA credential embedding in an identity assertion
- `did:jwk` issuer handling with resolver mocking
- Multi-role identity assertion payloads
- Optional identity assertion fields (`expected_partial_claim`, `expected_claim_generator`, `pad2`)

## References

- [CAWG Identity Assertion Specification v1.2](https://creator-assertions.github.io/identity/1.2/)
- [C2PA Technical Specification](https://c2pa.org/specifications/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052: COSE](https://www.rfc-editor.org/rfc/rfc9052.html)

---

Implementation status: Active development
Last updated: May 4, 2026
Specification target: CAWG Identity Assertion v1.2
