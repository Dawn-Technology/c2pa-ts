import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk';
import { Resolver } from 'did-resolver';
import { getResolver as keyResolver } from 'key-did-resolver';
import { getResolver as webResolver } from 'web-did-resolver';

export const didResolver = new Resolver({
    ...webResolver(),
    ...getDidJwkResolver(),
    ...keyResolver(),
});
