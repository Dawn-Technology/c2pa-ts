import { fromBER, ObjectIdentifier, Sequence } from 'asn1js';
import type { CoseAlgorithmIdentifier } from '../cose/Algorithms';
import { CryptoProvider } from './CryptoProvider';
import {
    hashAlgorithmFromOID,
    hashAlgorithmToOID,
    namedCurveFromOID,
    namedCurveToOID,
    OID_ECDSAwithSHA256,
    OID_ECDSAwithSHA384,
    OID_ECDSAwithSHA512,
    OID_ECPublicKey,
    OID_Ed25519,
    OID_RSAEncryption,
    OID_SHA256withRSA,
    OID_SHA384withRSA,
    OID_SHA512withRSA,
} from './OIDMap';
import { ECDSANamedCurve, HashAlgorithm, SigningAlgorithm, StreamingDigest } from './types';
import { WebCryptoProvider } from './WebCryptoProvider';

export class Crypto {
    public static provider: CryptoProvider = new WebCryptoProvider();

    /**
     * Computes the digest of given data
     * @param data
     * @param algorithm
     */
    public static digest(data: Uint8Array, algorithm: HashAlgorithm): Promise<Uint8Array> {
        return this.provider.digest(data, algorithm);
    }

    /**
     * Returns a streaming digest instance
     * @param algorithm
     */
    public static streamingDigest(algorithm: HashAlgorithm): StreamingDigest {
        return this.provider.streamingDigest(algorithm);
    }

    /**
     * Verifies a cryptographic signature
     * @param payload
     * @param signature
     * @param publicKey DER encoded public key
     * @param algorithm
     */
    public static verifySignature(
        payload: Uint8Array,
        signature: Uint8Array,
        publicKey: Uint8Array,
        algorithm: SigningAlgorithm,
    ): Promise<boolean> {
        return this.provider.verifySignature(payload, signature, publicKey, algorithm);
    }

    /**
     * Generates a cryptographic signature
     * @param payload
     * @param privateKey DER encoded private key
     * @param algorithm
     */
    public static sign(payload: Uint8Array, privateKey: Uint8Array, algorithm: SigningAlgorithm): Promise<Uint8Array> {
        return this.provider.sign(payload, privateKey, algorithm);
    }

    /**
     * Returns the digest length for the given algorithm
     * @param algorithm
     */
    public static getDigestLength(algorithm: HashAlgorithm): number {
        switch (algorithm) {
            case 'SHA-256':
                return 32;
            case 'SHA-384':
                return 48;
            case 'SHA-512':
                return 64;
        }
    }

    /**
     * Generates random bytes
     * @param length
     */
    public static getRandomValues(length: number): Uint8Array {
        return this.provider.getRandomValues(length);
    }

    /**
     * Returns a supported hash algorithm from an OID
     */
    public static getHashAlgorithmByOID(oid: string): HashAlgorithm | undefined {
        return hashAlgorithmFromOID(oid);
    }

    /**
     * Returns the OID for a hash algorithm
     */
    public static getHashAlgorithmOID(algorithm: HashAlgorithm): string {
        return hashAlgorithmToOID(algorithm);
    }

    /**
     * Returns a supported signature algorithm from an OID
     * @param oid Algorithm OID
     * @param hashAlgorithm The hash algorithm used (required if not included in OID)
     * @param curveOID Named curve OID (required for ECDSA)
     */
    public static getSigningAlgorithmByOID(
        oid: string,
        hashAlgorithm?: HashAlgorithm,
        curveOID?: string,
    ): SigningAlgorithm | undefined {
        const namedCurve = curveOID ? this.getNamedCurveByOID(curveOID) : undefined;

        switch (oid) {
            case OID_RSAEncryption:
                if (!hashAlgorithm) throw new Error('Hash algorithm required for RSA');
                return {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: hashAlgorithm,
                };
            case OID_SHA256withRSA:
                return {
                    name: 'RSA-PSS',
                    hash: 'SHA-256',
                    saltLength: 32,
                };
            case OID_SHA384withRSA:
                return {
                    name: 'RSA-PSS',
                    hash: 'SHA-384',
                    saltLength: 48,
                };
            case OID_SHA512withRSA:
                return {
                    name: 'RSA-PSS',
                    hash: 'SHA-512',
                    saltLength: 64,
                };
            case OID_ECPublicKey:
                if (!hashAlgorithm) throw new Error('Hash algorithm required for EC');
                if (!namedCurve) throw new Error('Named curve required for EC');
                return {
                    name: 'ECDSA',
                    namedCurve,
                    hash: hashAlgorithm,
                };
            case OID_ECDSAwithSHA256:
                if (!namedCurve) throw new Error('Named curve required for EC');
                return {
                    name: 'ECDSA',
                    namedCurve,
                    hash: 'SHA-256',
                };
            case OID_ECDSAwithSHA384:
                if (!namedCurve) throw new Error('Named curve required for EC');
                return {
                    name: 'ECDSA',
                    namedCurve,
                    hash: 'SHA-384',
                };
            case OID_ECDSAwithSHA512:
                if (!namedCurve) throw new Error('Named curve required for EC');
                return {
                    name: 'ECDSA',
                    namedCurve,
                    hash: 'SHA-512',
                };
            case OID_Ed25519:
                return {
                    name: 'Ed25519',
                };
        }
    }

    /**
     * Returns the OID for a signing algorithm
     */
    public static getSigningAlgorithmOID(algorithm: SigningAlgorithm): string {
        switch (algorithm.name) {
            case 'RSASSA-PKCS1-v1_5':
                return OID_RSAEncryption;
            case 'RSA-PSS':
                switch (algorithm.hash) {
                    case 'SHA-256':
                        return OID_SHA256withRSA;
                    case 'SHA-384':
                        return OID_SHA384withRSA;
                    case 'SHA-512':
                        return OID_SHA512withRSA;
                }
            // eslint-disable-next-line no-fallthrough
            case 'ECDSA':
                switch (algorithm.hash) {
                    case 'SHA-256':
                        return OID_ECDSAwithSHA256;
                    case 'SHA-384':
                        return OID_ECDSAwithSHA384;
                    case 'SHA-512':
                        return OID_ECDSAwithSHA512;
                }
            // eslint-disable-next-line no-fallthrough
            case 'Ed25519':
                return OID_Ed25519;
        }
    }

    /**
     * Returns an ECDSA named curve from an OID
     */
    public static getNamedCurveByOID(oid: string): ECDSANamedCurve | undefined {
        return namedCurveFromOID(oid);
    }

    /**
     * Returns the OID for an ECDSA named curve
     */
    public static getNamedCurveOID(namedCurve: ECDSANamedCurve): string {
        return namedCurveToOID(namedCurve);
    }

    /**
     * Derives the COSE algorithm identifier from a DER-encoded PKCS#8 private key.
     * For EC keys the identifier is inferred by convention (P-256→ES256, P-384→ES384, P-521→ES512).
     * For RSA keys the identifier defaults to PS256.
     * Returns `undefined` when the key type cannot be recognised.
     */
    public static getAlgorithmFromPkcs8(der: Uint8Array): CoseAlgorithmIdentifier | undefined {
        try {
            const parsed = fromBER(der);
            if (parsed.offset === -1) return undefined;

            const root = parsed.result;
            if (!(root instanceof Sequence)) return undefined;

            const elements = root.valueBlock.value;
            if (elements.length < 2) return undefined;

            const algorithmIdentifier = elements[1];
            if (!(algorithmIdentifier instanceof Sequence)) return undefined;

            const oidNode = algorithmIdentifier.valueBlock.value[0];
            if (!(oidNode instanceof ObjectIdentifier)) return undefined;

            const oid = oidNode.valueBlock.toString();

            switch (oid) {
                case OID_Ed25519:
                    return -8;

                case OID_ECPublicKey: {
                    const paramsNode = algorithmIdentifier.valueBlock.value[1];
                    if (!(paramsNode instanceof ObjectIdentifier)) return undefined;
                    const namedCurve = namedCurveFromOID(paramsNode.valueBlock.toString());
                    if (!namedCurve) return undefined;
                    return (
                        namedCurve === 'P-256' ? -7
                        : namedCurve === 'P-384' ? -35
                        : -36
                    );
                }

                case OID_RSAEncryption:
                    return -37;

                default:
                    return undefined;
            }
        } catch {
            return undefined;
        }
    }
}
