/**
 * Local Identity Signer
 * Creates CAWG identity assertions using local cryptographic keys
 *
 * Implements signing of CAWG identity assertions using local key material.
 * Supports ECDSA, RSA-PSS, and Ed25519 algorithms for signing.
 *
 * @module cawg/local-identity-signer
 */
import { NamedActorRole, SignatureType, VerifiedIdentity } from '../cawg';
import { bytesToBase64Url, privateJwkToPublicJwk } from '../cawg/utils';
import { CoseAlgorithmIdentifier } from '../cose/Algorithms';
import { Crypto, ECDSASigningAlgorithm, Ed25519SigningAlgorithm, RSASigningAlgorithm } from '../crypto';
import { IdentitySigner } from './identity-signer';

/**
 * Configuration options for LocalIdentitySigner
 */
export interface LocalIdentitySignerOptions {
    /** The verified identity or identities for this signer */
    readonly verifiedIdentity: VerifiedIdentity | VerifiedIdentity[];
    /** Named actor roles describing relationship to assets */
    readonly roles: NamedActorRole[];
    /** Signature type (defaults to IdentityClaimsAggregation) */
    readonly sigType?: SignatureType;
    /** Optional explicit issuer DID (auto-generated if not provided) */
    readonly issuerDid?: string;
}

/**
 * Local implementation of IdentitySigner for creating CAWG identity assertions
 *
 * Creates and signs identity assertions using locally-held private keys.
 * The signer derives a did:jwk from the public key if no explicit DID is provided.
 */
export class LocalIdentitySigner implements IdentitySigner {
    /**
     * Get the Web Crypto signing algorithm for the configured COSE algorithm
     *
     * Maps COSE algorithm identifiers to Web Crypto Algorithm specifications.
     */
    public readonly algorithm: CoseAlgorithmIdentifier;

    get signingAlgorithm(): ECDSASigningAlgorithm | RSASigningAlgorithm | Ed25519SigningAlgorithm {
        switch (this.algorithm) {
            case CoseAlgorithmIdentifier.ES256:
                return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
            case CoseAlgorithmIdentifier.ES384:
                return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' };
            case CoseAlgorithmIdentifier.ES512:
                return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' };
            case CoseAlgorithmIdentifier.PS256:
                return { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 };
            case CoseAlgorithmIdentifier.PS384:
                return { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 };
            case CoseAlgorithmIdentifier.PS512:
                return { name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 };
            case CoseAlgorithmIdentifier.Ed25519:
            default:
                return { name: 'Ed25519' };
        }
    }

    /**
     * Get the issuer DID
     *
     * Returns an explicitly-configured issuer DID, or generates a did:jwk from the public key.
     */
    get issuerDid(): Promise<string> {
        if (this.options.issuerDid) {
            return Promise.resolve(this.options.issuerDid);
        } else {
            return this.getDefaultDid();
        }
    }

    /**
     * Get the verified identity
     */
    get verifiedIdentity(): VerifiedIdentity | VerifiedIdentity[] {
        return this.options.verifiedIdentity;
    }

    /**
     * Get the named actor roles
     */
    get roles(): NamedActorRole[] {
        return this.options.roles;
    }

    /**
     * Get the signature type
     */
    get signatureType(): SignatureType {
        return this.options.sigType ?? SignatureType.IdentityClaimsAggregation;
    }

    /**
     * Creates a signer instance using a private key
     *
     * @param privateKey - Private key in PKCS#8 format
     * @param options – signer options
     */
    constructor(
        private readonly privateKey: Uint8Array,
        private readonly options: LocalIdentitySignerOptions,
    ) {
        const coseIdentifier = Crypto.getAlgorithmFromPkcs8(privateKey);
        if (coseIdentifier === undefined) {
            throw new Error('Unable to determine signing algorithm from PKCS#8 private key');
        }

        this.algorithm = coseIdentifier;
    }

    /**
     * Sign a payload using the local private key
     *
     * @param payload - The bytes to sign
     * @returns Promise resolving to the signature bytes
     */
    public sign(payload: Uint8Array): Promise<Uint8Array> {
        return Crypto.sign(payload, this.privateKey, this.signingAlgorithm);
    }

    /**
     * Generate a did:jwk from the local public key
     *
     * Exports the public key as JWK, canonicalizes it, and encodes it as a did:jwk DID.
     *
     * @returns Promise resolving to the generated did:jwk DID
     */
    public async getDefaultDid(): Promise<string> {
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            new Uint8Array(this.privateKey),
            this.signingAlgorithm,
            true,
            ['sign'],
        );
        const privateJwk = await crypto.subtle.exportKey('jwk', privateKey);
        const publicJwk = privateJwkToPublicJwk(privateJwk);
        const canonicalJwk = Object.fromEntries(Object.entries(publicJwk).sort(([a], [b]) => a.localeCompare(b)));
        const base64 = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(canonicalJwk)));
        return `did:jwk:${base64}`;
    }
}
