import { bytesToBase64Url, privateJwkToPublicJwk } from '../cawg';
import { Crypto, ECDSASigningAlgorithm, Ed25519SigningAlgorithm, RSASigningAlgorithm } from '../crypto';
import { Signer } from './Signer';

export class LocalIdentitySigner implements Omit<Signer, 'certificate' | 'chainCertificates'> {
    get signingAlgorithm(): ECDSASigningAlgorithm | RSASigningAlgorithm | Ed25519SigningAlgorithm {
        switch (this.algorithm) {
            case -7:
                return { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' };
            case -35:
                return { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' };
            case -36:
                return { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' };
            case -37:
                return { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 };
            case -38:
                return { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 48 };
            case -39:
                return { name: 'RSA-PSS', hash: 'SHA-512', saltLength: 64 };
            case -8:
            default:
                return { name: 'Ed25519' };
        }
    }

    /**
     * Creates a signer instance using a private key.
     * @param privateKey - Private key in PKCS#8 format
     * @param signingAlgorithm – algorithm identifier
     */
    public constructor(
        private readonly privateKey: Uint8Array,
        public algorithm: COSEAlgorithmIdentifier,
    ) {}

    public sign(payload: Uint8Array): Promise<Uint8Array> {
        return Crypto.sign(payload, this.privateKey, this.signingAlgorithm);
    }

    public async getJwk(): Promise<string> {
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
        return bytesToBase64Url(new TextEncoder().encode(JSON.stringify(canonicalJwk)));
    }
}
