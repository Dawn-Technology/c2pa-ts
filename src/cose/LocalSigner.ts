import { type X509Certificate } from '@peculiar/x509';
import { Crypto } from '../crypto';
import { Algorithms, CoseAlgorithmIdentifier } from './Algorithms';
import { Signer } from './Signer';

export class LocalSigner implements Signer {
    public readonly algorithm: CoseAlgorithmIdentifier;

    /**
     * Creates a signer instance using a certificate and PKCS#8 private key.
     * The COSE algorithm identifier is derived automatically from the private key.
     * @param privateKey - Private key in PKCS#8 format
     * @param certificate – The X.509 certificate to use for signing
     * @param chainCertificates – Additional certificates to include in the certificate chain
     */
    public constructor(
        private readonly privateKey: Uint8Array,
        public certificate: X509Certificate,
        public chainCertificates: X509Certificate[] = [],
    ) {
        const coseIdentifier = Crypto.getAlgorithmFromPkcs8(privateKey);
        if (coseIdentifier === undefined) {
            throw new Error('Unable to determine signing algorithm from PKCS#8 private key');
        }

        this.algorithm = coseIdentifier;
    }

    public sign(payload: Uint8Array): Promise<Uint8Array> {
        return Crypto.sign(
            payload,
            this.privateKey,
            Algorithms.getCryptoAlgorithm(Algorithms.getAlgorithm(this.algorithm), this.certificate)!,
        );
    }
}
