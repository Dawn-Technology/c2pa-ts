import * as fs from 'node:fs/promises';
import { X509Certificate } from '@peculiar/x509';
import { TrustList } from '../../src/cose';

export const DEFAULT_TRUST_LIST_PATH = 'tests/fixtures/trust-list.pem';

export async function setTrustList(trustListFile: string = DEFAULT_TRUST_LIST_PATH): Promise<void> {
    const trustListData = (await fs.readFile(trustListFile)).toString();
    TrustList.setTrustAnchors([trustListData]);
}

export async function getTrustAnchors(trustListFile: string = DEFAULT_TRUST_LIST_PATH): Promise<X509Certificate[]> {
    const trustListData = (await fs.readFile(trustListFile)).toString();
    return TrustList.parseTrustAnchors([trustListData]);
}
