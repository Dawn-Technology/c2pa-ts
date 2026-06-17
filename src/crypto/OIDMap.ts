import { ECDSANamedCurve, HashAlgorithm } from './types';

/** Hash algorithm OIDs */
export const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
export const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
export const OID_SHA512 = '2.16.840.1.101.3.4.2.3';

/** RSA signing OIDs */
export const OID_RSAEncryption = '1.2.840.113549.1.1.1';
export const OID_SHA256withRSA = '1.2.840.113549.1.1.11';
export const OID_SHA384withRSA = '1.2.840.113549.1.1.12';
export const OID_SHA512withRSA = '1.2.840.113549.1.1.13';

/** EC OIDs */
export const OID_ECPublicKey = '1.2.840.10045.2.1';
export const OID_ECDSAwithSHA256 = '1.2.840.10045.4.3.2';
export const OID_ECDSAwithSHA384 = '1.2.840.10045.4.3.3';
export const OID_ECDSAwithSHA512 = '1.2.840.10045.4.3.4';
export const OID_SECP256r1 = '1.2.840.10045.3.1.7';
export const OID_SECP384r1 = '1.3.132.0.34';
export const OID_SECP521r1 = '1.3.132.0.35';

/** Edwards-curve OIDs */
export const OID_Ed25519 = '1.3.101.112';
export const OID_Ed448 = '1.3.101.113';

/** Maps a hash-algorithm OID to its `HashAlgorithm` string, or `undefined`. */
export function hashAlgorithmFromOID(oid: string): HashAlgorithm | undefined {
    switch (oid) {
        case OID_SHA256:
            return 'SHA-256';
        case OID_SHA384:
            return 'SHA-384';
        case OID_SHA512:
            return 'SHA-512';
        default:
            return undefined;
    }
}

/** Maps a `HashAlgorithm` string to its OID. */
export function hashAlgorithmToOID(algorithm: HashAlgorithm): string {
    switch (algorithm) {
        case 'SHA-256':
            return OID_SHA256;
        case 'SHA-384':
            return OID_SHA384;
        case 'SHA-512':
            return OID_SHA512;
    }
}

/** Maps a named-curve OID to its `ECDSANamedCurve` string, or `undefined`. */
export function namedCurveFromOID(oid: string): ECDSANamedCurve | undefined {
    switch (oid) {
        case OID_SECP256r1:
            return 'P-256';
        case OID_SECP384r1:
            return 'P-384';
        case OID_SECP521r1:
            return 'P-521';
        default:
            return undefined;
    }
}

/** Maps an `ECDSANamedCurve` string to its OID. */
export function namedCurveToOID(namedCurve: ECDSANamedCurve): string {
    switch (namedCurve) {
        case 'P-256':
            return OID_SECP256r1;
        case 'P-384':
            return OID_SECP384r1;
        case 'P-521':
            return OID_SECP521r1;
    }
}
