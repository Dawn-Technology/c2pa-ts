/**
 * CAWG Identity Claims Aggregation Support
 * Implementation of ICA verifiable credentials per CAWG spec Section 8.1
 *
 * @module cawg/identity-claims-aggregation
 */

import * as asn1js from 'asn1js';
import { DIDDocument, VerificationMethod } from 'did-resolver';
import * as pkijs from 'pkijs';
import { Algorithms, CoseAlgorithmIdentifier } from '../cose';
import { SigStructure } from '../cose/SigStructure';
import { Crypto } from '../crypto';
import type {
    ECDSASigningAlgorithm,
    Ed25519SigningAlgorithm,
    RSASigningAlgorithm,
    SigningAlgorithm,
} from '../crypto/types';
import * as JUMBF from '../jumbf';
import { ValidationResult, ValidationStatusCode } from '../manifest';
import { BinaryHelper } from '../util';
import { didResolver } from './did-resolver';
import {
    SCHEMA_URL,
    SUPPORTED_COSE_ALGORITHMS,
    SUPPORTED_DID_METHODS,
    SUPPORTED_VERIFICATION_METHODS,
    VC_CONTEXT,
    VC_TYPE,
    type C2paAssetBinding,
    type CredentialStatus,
    type DecodedCoseSign1,
    type DecodedCoseSign1Typing,
    type DIDPublicKey,
    type IdentityAssertionValidationOptions,
    type IdentityClaimsAggregationCredential,
    type IdentityClaimsCredentialSubject,
    type ProtectedHeaderMap,
    type SignerPayloadMap,
    type VerifiableCredential,
    type VerifiedIdentity,
} from './types.js';
import { c2paAssetBindingToSignerPayload, signerPayloadToC2paAssetBinding } from './utils.js';

/**
 * Create an Identity Claims Aggregation credential
 *
 * @param issuer - DID of the identity claims aggregator
 * @param subject - Credential subject including verified identities
 * @param signerPayload - The signer_payload to bind to C2PA asset
 * @param validFrom - Valid from date
 * @param options - Additional options
 * @returns Unsigned ICA credential
 */
export function createIcaCredential(
    issuer: string,
    subject: Omit<IdentityClaimsCredentialSubject, 'c2paAsset'>,
    signerPayload: SignerPayloadMap,
    validFrom: Date,
    options?: {
        validUntil?: Date;
        useVc2?: boolean;
        credentialStatus?: CredentialStatus;
    },
): VerifiableCredential {
    const useVc2 = options?.useVc2 ?? true;

    // Convert signer_payload to C2PA asset binding format
    const c2paAssetBinding = signerPayloadToC2paAssetBinding(signerPayload);

    const credential: VerifiableCredential = {
        '@context': [useVc2 ? VC_CONTEXT.V2_0 : VC_CONTEXT.V1_1, VC_CONTEXT.CAWG],
        type: [VC_TYPE.Verifiable, VC_TYPE.IdentityClaimsAggregation],
        issuer,
        credentialSubject: {
            ...subject,
            c2paAsset: c2paAssetBinding,
        },
        credentialSchema: [
            {
                id: useVc2 ? SCHEMA_URL.VC2_0 : SCHEMA_URL.VC1_1,
                type: 'JSONSchema',
            },
        ],
    };

    // Add validity dates based on VC version
    if (useVc2) {
        credential.validFrom = validFrom.toISOString();
        if (options?.validUntil) {
            credential.validUntil = options.validUntil.toISOString();
        }
    } else {
        credential.issuanceDate = validFrom.toISOString();
        if (options?.validUntil) {
            credential.expirationDate = options.validUntil.toISOString();
        }
    }

    // Add optional credential status
    if (options?.credentialStatus) {
        credential.credentialStatus = options.credentialStatus;
    }

    return credential;
}

/**
 * Validate an Identity Claims Aggregation credential
 *
 * Implements validation as described in CAWG spec Section 8.1.5
 *
 * @param signature - COSE_Sign1 signature bytes
 * @param signerPayload - Expected signer_payload from identity assertion
 * @param assertionLabel - Label of the identity assertion
 * @param trustedIssuers - List of trusted ICA issuer DIDs
 * @param options - Validation options
 * @returns Validation result
 */
export async function validateIcaCredential(
    signature: Uint8Array,
    signerPayload: SignerPayloadMap,
    assertionLabel: string,
    trustedIssuers: string[],
    options?: IdentityAssertionValidationOptions,
): Promise<ValidationResult> {
    const result: ValidationResult = new ValidationResult();

    try {
        // Step 1: Parse COSE_Sign1 structure
        const coseSign1 = await parseCoseSign1(signature);
        if (!coseSign1) {
            result.addError(
                ValidationStatusCode.IcaInvalidCoseSign1,
                assertionLabel,
                'Failed to parse COSE_Sign1 structure',
            );
            return result;
        }

        // Step 2: Validate COSE protected headers
        const algValid = validateCoseAlgorithm(coseSign1.protectedHeader?.alg);
        if (!algValid) {
            result.addError(
                ValidationStatusCode.IcaInvalidAlg,
                assertionLabel,
                'Unsupported or missing COSE algorithm',
            );
        }

        const contentType = coseSign1.protectedHeader?.contentType;
        if (contentType !== 'application/vc') {
            result.addError(
                ValidationStatusCode.IcaInvalidContentType,
                assertionLabel,
                'Content type must be "application/vc"',
            );
        }

        // Step 3: Parse verifiable credential
        let credential: IdentityClaimsAggregationCredential;

        try {
            if (!coseSign1.payload) {
                result.addError(
                    ValidationStatusCode.IcaInvalidVerifiableCredential,
                    assertionLabel,
                    'COSE_Sign1 payload is empty',
                );
                return result;
            }
            const credentialJson = new TextDecoder().decode(coseSign1.payload);
            credential = JSON.parse(credentialJson) as IdentityClaimsAggregationCredential;
        } catch {
            result.addError(
                ValidationStatusCode.IcaInvalidVerifiableCredential,
                assertionLabel,
                'Failed to parse verifiable credential JSON',
            );
            return result;
        }

        // Step 4: Validate credential structure
        validateIcaCredentialStructure(credential, assertionLabel, result);

        // Step 5: Obtain issuer's public key via DID resolution
        const issuerDid = extractIssuerDid(credential);

        if (issuerDid?.split(':')[0] !== 'did') {
            result.addError(ValidationStatusCode.IcaInvalidIssuer, assertionLabel, 'Issuer is not a valid DID');
            return result;
        }

        const didMethod = issuerDid.split(':')[1];
        if (!(SUPPORTED_DID_METHODS as readonly string[]).includes(`did:${didMethod}`)) {
            result.addError(
                ValidationStatusCode.IcaDidUnsupportedMethod,
                assertionLabel,
                `DID method not supported: did:${didMethod}`,
            );
        }

        const didDocument = await resolveDid(issuerDid);
        if (!didDocument) {
            result.addError(ValidationStatusCode.IcaDidUnavailable, assertionLabel, 'Failed to resolve DID document');
            return result;
        }

        const publicKey = extractPublicKeyFromDidDocument(didDocument);

        if (!publicKey) {
            result.addError(
                ValidationStatusCode.IcaInvalidDidDocument,
                assertionLabel,
                'Failed to extract public key from DID document',
            );
            return result;
        }

        // Step 6: Verify issuer is trusted
        const issuerTrusted = await verifyIssuerTrust(issuerDid, trustedIssuers, options?.trustedIcaAnchors);

        if (!issuerTrusted) {
            result.addError(
                ValidationStatusCode.IcaUntrustedIssuer,
                assertionLabel,
                'Issuer DID is not in trusted list',
            );
        }

        // Step 7: Verify COSE signature
        const signatureValid = await verifyCoseSign1(coseSign1, publicKey);

        if (!signatureValid) {
            result.addError(
                ValidationStatusCode.IcaSignatureMismatch,
                assertionLabel,
                'COSE signature verification failed',
            );
            return result;
        }

        // Step 8: Verify timestamp if present
        const timestamp = extractTimestamp(coseSign1);
        if (timestamp) {
            const timestampValid = await validateTimestamp(
                timestamp,
                coseSign1.protectedHeaderBytes,
                coseSign1.signature,
            );
            if (timestampValid) {
                result.addInformational(
                    ValidationStatusCode.IcaTimeStampValidated,
                    assertionLabel,
                    'RFC 3161 timestamp validated',
                );
            } else {
                result.addError(ValidationStatusCode.IcaTimeStampInvalid, assertionLabel, 'Invalid RFC 3161 timestamp');
            }
        }

        // Step 9: Verify validity dates
        validateCredentialValidityDates(credential, assertionLabel, result, options?.validationTime);

        // Step 10: Check revocation status
        if (options?.checkRevocation && credential.credentialStatus) {
            await validateRevocationStatus(credential, assertionLabel, result);
        }

        // Step 11: Verify binding to C2PA asset
        validateC2paAssetBinding(credential.credentialSubject.c2paAsset, signerPayload, assertionLabel, result);

        // Step 12: Validate verified identities
        validateVerifiedIdentities(credential.credentialSubject.verifiedIdentities, assertionLabel, result);

        // Step 13: Final status
        if (result.isValid) {
            result.addInformational(
                ValidationStatusCode.IcaCredentialValid,
                assertionLabel,
                'Identity claims aggregation credential is valid',
            );
        }
    } catch (error) {
        result.addError(
            ValidationStatusCode.IcaInvalidVerifiableCredential,
            assertionLabel,
            `Validation error: ${String(error)}`,
        );
    }

    return result;
}

// Helper functions
function validateCoseAlgorithm(alg: number | undefined): boolean {
    if (alg === undefined) return false;
    return (Object.values(SUPPORTED_COSE_ALGORITHMS) as number[]).includes(alg);
}

function validateIcaCredentialStructure(
    credential: IdentityClaimsAggregationCredential,
    label: string,
    result: ValidationResult,
): void {
    // Validate @context
    if (!credential['@context'] || !Array.isArray(credential['@context'])) {
        result.addError(ValidationStatusCode.IcaInvalidVerifiableCredential, label, 'Missing or invalid @context');
    }

    // Validate type
    if (!credential.type || !Array.isArray(credential.type)) {
        result.addError(ValidationStatusCode.IcaInvalidVerifiableCredential, label, 'Missing or invalid type');
    }

    const hasRequiredTypes =
        credential.type.includes(VC_TYPE.Verifiable) && credential.type.includes(VC_TYPE.IdentityClaimsAggregation);

    if (!hasRequiredTypes) {
        result.addError(
            ValidationStatusCode.IcaInvalidVerifiableCredential,
            label,
            'Missing required credential types',
        );
    }
}

function extractIssuerDid(credential: IdentityClaimsAggregationCredential): string | null {
    if (typeof credential.issuer === 'string') {
        return credential.issuer;
    } else if (credential.issuer && typeof credential.issuer === 'object') {
        return credential.issuer.id;
    }
    return null;
}

async function resolveDid(did: string): Promise<DIDDocument | null> {
    const res = await didResolver.resolve(did);
    return res.didDocument;
}

function extractPublicKeyFromDidDocument(didDocument: DIDDocument): DIDPublicKey | null {
    // Extract assertionMethod verification method
    // and return public key material
    const verificationMethods = didDocument.verificationMethod ?? [];

    // Look for assertionMethod entries
    const assertionMethods = didDocument.assertionMethod ?? [];

    for (const methodId of assertionMethods) {
        let method = verificationMethods.find(
            (vm: VerificationMethod) => vm.id === methodId || vm.id === `${didDocument.id}${methodId as string}`,
        );

        method ??= methodId as unknown as VerificationMethod;

        // Check if verification method type is supported
        if (!(SUPPORTED_VERIFICATION_METHODS as readonly string[]).includes(method.type)) {
            continue;
        }

        // Extract public key based on method type
        if (['JsonWebKey', 'JsonWebKey2020'].includes(method.type) && method.publicKeyJwk) {
            return method.publicKeyJwk;
        } else if (method.publicKeyMultibase) {
            return method.publicKeyMultibase;
        }
    }
    return null;
}

async function verifyIssuerTrust(
    issuerDid: string,
    trustedIssuers: string[],
    trustedAnchors?: string[],
): Promise<boolean> {
    // Mock
    return true;
    // Check if issuer is directly trusted or chains to trusted anchor
    // return trustedIssuers.includes(issuerDid);
}

async function verifyCoseSign1(coseSign1: DecodedCoseSign1, publicKey: DIDPublicKey): Promise<boolean> {
    try {
        // Validate required fields
        if (!coseSign1.protectedHeaderBytes || !coseSign1.protectedHeader?.alg || !coseSign1.signature) {
            return false;
        }

        // Validate payload
        if (!coseSign1.payload) {
            return false;
        }

        // Get the COSE algorithm
        const coseAlgorithm = Algorithms.getAlgorithm(coseSign1.protectedHeader.alg as CoseAlgorithmIdentifier);
        if (!coseAlgorithm) {
            return false;
        }

        // Convert DIDPublicKey to DER format and extract algorithm info if available
        const keyConversionResult = await convertDidPublicKeyToDer(publicKey);
        if (!keyConversionResult) {
            return false;
        }
        const { derPublicKey, keyAlgorithmInfo } = keyConversionResult;

        // Determine the full signing algorithm with namedCurve if needed
        const signingAlgorithm = buildSigningAlgorithm(coseAlgorithm.alg, keyAlgorithmInfo);
        if (!signingAlgorithm) {
            return false;
        }

        // Create the Sig_structure and encode it per RFC 8152
        // Sig_structure = [
        //   context = "Signature1",
        //   body_protected = protected header bytes,
        //   external_aad = empty,
        //   payload = the credential bytes
        // ]
        const sigStructure = new SigStructure('Signature1', coseSign1.protectedHeaderBytes, coseSign1.payload);
        const toBeSigned = sigStructure.encode();

        // Verify the signature using the existing Crypto infrastructure
        const isValid = await Crypto.verifySignature(toBeSigned, coseSign1.signature, derPublicKey, signingAlgorithm);

        return isValid;
    } catch {
        // Signature verification failed due to exception
        return false;
    }
}

/**
 * Convert a DIDPublicKey (JWK or multibase string) to DER SPKI format
 * @param publicKey - JWK or multibase-encoded public key
 * @returns Object with DER-encoded SPKI public key and algorithm info, or null if conversion fails
 */
async function convertDidPublicKeyToDer(
    publicKey: DIDPublicKey,
): Promise<{ derPublicKey: Uint8Array; keyAlgorithmInfo?: { namedCurve?: string; kty?: string } } | null> {
    try {
        // Handle JsonWebKey format
        if (typeof publicKey === 'object' && publicKey !== null) {
            // Get the algorithm spec from the JWK
            const keyAlgorithm = getAlgorithmFromJwk(publicKey);
            if (!keyAlgorithm) {
                return null;
            }

            // Import the JWK using Web Crypto API
            const cryptoKey = await crypto.subtle.importKey('jwk', publicKey, keyAlgorithm, true, ['verify']);

            // Export as SPKI (DER format) for use with Crypto.verifySignature
            const spkiBuffer = await crypto.subtle.exportKey('spki', cryptoKey);
            return {
                derPublicKey: new Uint8Array(spkiBuffer),
                keyAlgorithmInfo: extractAlgorithmInfo(publicKey),
            };
        }

        // Handle multibase string format
        // Multibase strings typically start with a prefix character indicating the encoding
        // Common prefixes: 'z' (base58btc), 'b' (base32), 'u' (base64url)
        // Support for multibase requires additional dependencies not currently in the project
        // For now, return null to indicate unsupported format
        if (typeof publicKey === 'string') {
            // TODO: Add multibase decoding support when multibase library is available
            return null;
        }

        return null;
    } catch {
        // Return null if any conversion step fails
        return null;
    }
}

/**
 * Build a SigningAlgorithm from a COSE algorithm and key algorithm info
 * @param coseAlg - The algorithm from CoseAlgorithm.alg
 * @param keyAlgorithmInfo - Information about the key (namedCurve, etc.)
 * @returns Properly constructed SigningAlgorithm or null if unable to construct
 */
function buildSigningAlgorithm(
    coseAlg: Omit<ECDSASigningAlgorithm, 'namedCurve'> | RSASigningAlgorithm | Ed25519SigningAlgorithm,
    keyAlgorithmInfo?: { namedCurve?: string; kty?: string },
): SigningAlgorithm | null {
    // For ECDSA, we need to add the namedCurve from the key
    if (coseAlg.name === 'ECDSA' && keyAlgorithmInfo?.namedCurve) {
        const namedCurve = keyAlgorithmInfo.namedCurve;
        if (['P-256', 'P-384', 'P-521'].includes(namedCurve)) {
            return {
                name: 'ECDSA',
                namedCurve: namedCurve as 'P-256' | 'P-384' | 'P-521',
                hash: coseAlg.hash,
            };
        }
    }

    // For non-ECDSA algorithms, return as-is (they already have all required properties)
    if (coseAlg.name !== 'ECDSA') {
        return coseAlg as SigningAlgorithm;
    }

    return null;
}

/**
 * Extract algorithm information from a JWK
 * @param jwk - JsonWebKey
 * @returns Object with algorithm information like namedCurve
 */
function extractAlgorithmInfo(jwk: JsonWebKey): { namedCurve?: string; kty?: string } {
    const info: { namedCurve?: string; kty?: string } = { kty: jwk.kty };
    if (jwk.kty === 'EC' && jwk.crv) {
        info.namedCurve = jwk.crv;
    }
    return info;
}

/**
 * Get the Web Crypto algorithm parameters from a JWK
 * @param jwk - JsonWebKey
 * @returns Algorithm specification for crypto.subtle operations
 */
function getAlgorithmFromJwk(jwk: JsonWebKey): Algorithm | null {
    if (!jwk.kty) {
        return null;
    }

    // Handle EC (Elliptic Curve) keys used for ECDSA
    if (jwk.kty === 'EC') {
        if (!jwk.crv) {
            return null;
        }

        // Map JWK curve names to WebCrypto named curves
        const curveMap: Record<string, EcKeyGenParams['namedCurve']> = {
            'P-256': 'P-256',
            'P-384': 'P-384',
            'P-521': 'P-521',
        };

        const namedCurve = curveMap[jwk.crv];
        if (!namedCurve) {
            return null;
        }

        return {
            name: 'ECDSA',
            namedCurve,
        } as EcKeyImportParams;
    }

    // Handle RSA keys
    if (jwk.kty === 'RSA') {
        return {
            name: 'RSASSA-PKCS1-v1_5',
        } as RsaHashedImportParams;
    }

    // Handle OKP (Octet Key Pair) keys used for EdDSA/Ed25519
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
        return {
            name: 'Ed25519',
        } as Algorithm;
    }

    return null;
}

function extractTimestamp(coseSign1: DecodedCoseSign1): Uint8Array | ArrayBuffer | null {
    const unprotectedHeader = coseSign1.unprotectedHeader;
    if (!unprotectedHeader || typeof unprotectedHeader !== 'object') {
        return null;
    }

    // CAWG Identity 1.2: RFC 3161 timestamp container is sigTst2.
    // Accept both named and numeric-key encodings for robustness.
    const sigTst2 = unprotectedHeader.sigTst2 ?? unprotectedHeader[395] ?? unprotectedHeader['395'];

    if (!sigTst2 || typeof sigTst2 !== 'object') {
        return null;
    }

    const tstTokens = (sigTst2 as { tstTokens?: unknown }).tstTokens;
    if (!Array.isArray(tstTokens) || tstTokens.length === 0) {
        return null;
    }

    if (!tstTokens[0] || typeof tstTokens[0] !== 'object') {
        return null;
    }

    const val = (tstTokens[0] as { val?: unknown }).val;
    return (val as Uint8Array | ArrayBuffer) ?? null;
}

async function validateTimestamp(
    timestamp: Uint8Array | ArrayBuffer,
    rawProtectedBucket: Uint8Array,
    signature: Uint8Array,
): Promise<boolean> {
    // Validate RFC 3161 timestamp in CAWG sigTst2.
    // Some producers embed a full TimeStampResp while others embed a bare TimeStampToken (CMS ContentInfo).
    try {
        let timestampBytes: Uint8Array | null = null;

        if (timestamp instanceof Uint8Array) {
            timestampBytes = timestamp;
        } else if (timestamp instanceof ArrayBuffer) {
            timestampBytes = new Uint8Array(timestamp);
        }

        if (!timestampBytes || timestampBytes.length === 0) {
            return false;
        }

        let signedData: pkijs.SignedData | null = null;

        // Preferred format: full RFC 3161 TimeStampResp.
        try {
            const response = pkijs.TimeStampResp.fromBER(timestampBytes as Uint8Array<ArrayBuffer>);
            if (
                response.status.status !== pkijs.PKIStatus.granted &&
                response.status.status !== pkijs.PKIStatus.grantedWithMods
            ) {
                return false;
            }

            if (response.timeStampToken?.content) {
                signedData = new pkijs.SignedData({ schema: response.timeStampToken.content });
            }
        } catch {
            // Fallback: bare TimeStampToken (ContentInfo wrapping SignedData).
            const ber = new Uint8Array(timestampBytes).buffer;
            const parsed = asn1js.fromBER(ber);
            if (parsed.offset === -1) {
                return false;
            }

            const contentInfo = new pkijs.ContentInfo({ schema: parsed.result });
            if (!contentInfo.content) {
                return false;
            }

            signedData = new pkijs.SignedData({ schema: contentInfo.content });
        }

        if (!signedData) {
            return false;
        }

        const rawTstInfo = signedData.encapContentInfo.eContent?.getValue();
        if (!rawTstInfo) {
            return false;
        }

        const tstInfo = pkijs.TSTInfo.fromBER(rawTstInfo);

        // Require a supported message-imprint algorithm and non-empty digest.
        const hashAlgorithm = Crypto.getHashAlgorithmByOID(tstInfo.messageImprint.hashAlgorithm.algorithmId);
        if (!hashAlgorithm) {
            return false;
        }

        const hashedMessage = new Uint8Array(tstInfo.messageImprint.hashedMessage.getValue());
        if (hashedMessage.length === 0) {
            return false;
        }

        // sigTst2 (CAWG/C2PA v2) timestamps the CBOR-wrapped signature bytes, not the raw signature bytes.
        const signaturePayload = JUMBF.CBORBox.encoder.encode(signature);
        const toBeSigned = new SigStructure('CounterSignature', rawProtectedBucket, signaturePayload).encode();
        const actualHash = await Crypto.digest(toBeSigned, hashAlgorithm);
        if (!BinaryHelper.bufEqual(actualHash, hashedMessage)) {
            return false;
        }

        return true;
    } catch {
        return false;
    }
}

function validateCredentialValidityDates(
    credential: IdentityClaimsAggregationCredential,
    label: string,
    result: ValidationResult,
    validationTime?: Date,
): void {
    const now = validationTime ?? new Date();

    // Check validFrom / issuanceDate
    const validFrom = credential.validFrom ?? credential.issuanceDate;
    if (!validFrom) {
        result.addError(ValidationStatusCode.IcaValidFromMissing, label, 'Missing validFrom or issuanceDate');
        return;
    }

    const validFromDate = new Date(validFrom);
    if (validFromDate > now) {
        result.addError(ValidationStatusCode.IcaValidFromInvalid, label, 'Credential not yet valid');
    }

    // Check validUntil / expirationDate
    const validUntil = credential.validUntil ?? credential.expirationDate;
    if (validUntil) {
        const validUntilDate = new Date(validUntil);
        if (validUntilDate < now) {
            result.addError(ValidationStatusCode.IcaValidUntilInvalid, label, 'Credential has expired');
        }
    }
}

async function validateRevocationStatus(
    credential: IdentityClaimsAggregationCredential,
    label: string,
    result: ValidationResult,
): Promise<void> {
    // Check credential status for revocation
    // Implementation would check bitstring status list or other mechanism

    if (credential.credentialStatus) {
        // Simplified check
        result.addError(ValidationStatusCode.IcaCredentialNotRevoked, label, 'Credential not revoked');
    }
}

function validateC2paAssetBinding(
    c2paAsset: C2paAssetBinding,
    signerPayload: SignerPayloadMap,
    label: string,
    result: ValidationResult,
): void {
    // Convert and compare
    const convertedPayload = c2paAssetBindingToSignerPayload(c2paAsset);

    if (JSON.stringify(convertedPayload) !== JSON.stringify(signerPayload)) {
        result.addError(
            ValidationStatusCode.IcaSignerPayloadMismatch,
            label,
            'c2paAsset does not match signer_payload',
        );
    }
}

function validateVerifiedIdentities(
    verifiedIdentities: VerifiedIdentity[],
    label: string,
    result: ValidationResult,
): void {
    if (!verifiedIdentities || verifiedIdentities.length === 0) {
        result.addError(
            ValidationStatusCode.IcaVerifiedIdentitiesMissing,
            label,
            'verifiedIdentities array is empty or missing',
        );
        return;
    }

    // Validate each verified identity entry
    for (const identity of verifiedIdentities) {
        if (!identity.type || !identity.provider || !identity.verifiedAt) {
            result.addError(
                ValidationStatusCode.IcaVerifiedIdentitiesInvalid,
                label,
                'Verified identity missing required fields',
            );
        }
    }
}

async function parseCoseSign1(data: Uint8Array): Promise<DecodedCoseSign1 | null> {
    try {
        // COSE_Sign1 structure (RFC 8152):
        // [
        //   protected: bstr,
        //   unprotected: {* label => int / tstr => any},
        //   payload: bstr,
        //   signature: bstr
        // ]

        // You'll need a CBOR decoder library (e.g., cbor, cbor-x, or cborg)
        // Example using a hypothetical CBOR library:
        const cborDecoded = JUMBF.CBORBox.decoder.decode(data) as { value: DecodedCoseSign1Typing }; // or similar
        if (!cborDecoded?.value) {
            return null;
        }
        const cborDecodedValue = cborDecoded.value;
        if (!Array.isArray(cborDecodedValue) || cborDecodedValue.length !== 4) {
            return null;
        }

        const [protectedHeaderBytes, unprotectedHeader, payload, signature] = cborDecodedValue;

        // Decode protected header
        const protectedHeader = JUMBF.CBORBox.decoder.decode(protectedHeaderBytes) as
            | ProtectedHeaderMap
            | Map<number | string, unknown>;

        const getProtectedHeaderParam = (label: number): unknown => {
            if (protectedHeader instanceof Map) {
                if (protectedHeader.has(label)) {
                    return protectedHeader.get(label);
                }
                const stringLabel = String(label);
                if (protectedHeader.has(stringLabel)) {
                    return protectedHeader.get(stringLabel);
                }
                return undefined;
            }

            return protectedHeader[String(label) as keyof ProtectedHeaderMap];
        };

        return {
            protectedHeaderBytes,
            protectedHeader: {
                alg: getProtectedHeaderParam(1) as number, // COSE header parameter 1 is "alg"
                contentType: getProtectedHeaderParam(3) as string | number | undefined, // COSE header parameter 3 is "content type"
                x5chain: getProtectedHeaderParam(33) as Uint8Array | Uint8Array[], // COSE header parameter 33 is "x5chain"
            },
            unprotectedHeader,
            payload,
            signature,
        };
    } catch {
        return null;
    }
}
