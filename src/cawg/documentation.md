# CAWG implementation document

## Fully supported:
- Status codes:
    - cawg.identity.trusted
    - cawg.identity.well-formed
    - cawg.identity.cbor.invalid
    - cawg.identity.assertion.mismatch
    - cawg.identity.hard_binding_missing
    - cawg.identity.hard_binding_incorrect
    - cawg.identity.sig_type.unknown
    - cawg.identity.pad.invalid
    - cawg.ica.credential_valid
    - cawg.ica.invalid_cose_sign1
    - cawg.ica.invalid_alg
    - cawg.ica.invalid_content_type
    - cawg.ica.invalid_verifiable_credential
    - cawg.ica.invalid_issuer
    - cawg.ica.did_unsupported_method
    - cawg.ica.did_unavailable
    - cawg.ica.invalid_did_document
    - cawg.ica.untrusted_issuer
    - cawg.ica.signature_mismatch
    - cawg.ica.time_stamp.validated
    - cawg.ica.time_stamp.invalid
    - cawg.ica.valid_from.missing
    - cawg.ica.valid_from.invalid
    - cawg.ica.valid_until.invalid
    - cawg.ica.signer_payload.mismatch
    - cawg.ica.verified_identities.missing
    - cawg.ica.verified_identities.invalid
- DIDs
    - did:web
    - did:jwk
- Algortithms  
    - ES256
    - Ed25519

## Should work
- Algorithms 
    - ES384,
    - ES512,
    - PS256,
    - PS384,
    - PS512,
- DIDs 
    - did:key

## Partially supported:
- X509 certificates for COSE_SIGN1
- ExpectedPartialClaim
- ExpectedClaimGenerator
- ExpectedCountersigners
- Status codes:
    - cawg.identity.expected_partial_claim.mismatch
    - cawg.identity.expected_claim_generator.mismatch
    - cawg.identity.unexpected_countersigner
    - cawg.identity.expected_countersigner.missing

## Not supported:
- validateCountersignerCredentials
- Multiple identity assertions
- Certificate revocation (OCSP)
- Status codes:
    - cawg.identity.assertion.duplicate
    - cawg.identity.credential_revoked
    - cawg.identity.expected_countersigner.mismatch
    - cawg.ica.revocation.unsupported
    - cawg.ica.revocation.unavailable
    - cawg.ica.credential.not_revoked
    - cawg.ica.credential.revoked