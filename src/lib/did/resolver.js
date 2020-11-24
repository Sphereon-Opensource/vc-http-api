import fetch from 'node-fetch';
import CachedDidDocuments from '../../resources/cache/CachedDidDocuments.json';
import {didResolvers} from '../../resources/config/resolverConfig.json';
import InvalidRequestError from '../error/InvalidRequestError';

const getDidDocument = async did => {
    if (CachedDidDocuments[did]) {
        return CachedDidDocuments[did];
    }
    for (const resolverConfig of didResolvers) {
        const body = await fetch(`${resolverConfig.url}/${did}`)
            .then(res => res.json())
            .catch(() => ({didDocument: false}));
        if (body.didDocument) {
            return body.didDocument;
        }
    }
    throw new Error(`No did document could be found for ${did}`);
};

const extractDidFromVerificationMethod = verificationMethod => {
    if (!verificationMethod.includes('#')) {
        const message = `Invalid verification method. Received: ${verificationMethod} but
        expected something of the form {identifier}#{key-id}`;
        throw new InvalidRequestError(message);
    }
    return verificationMethod.split('#')[0];
};

const validateAssertionMethod = (assertionMethod, did) => {
    if (!assertionMethod) {
        return new Promise((resolve => resolve({})));
    }
    let didUri = did;
    if (!did) {
        didUri = extractDidFromVerificationMethod(assertionMethod);
    }
    return getDidDocument(didUri)
        .then(didDocument => {
            if (!didDocument.assertionMethod) {
                const message = `DID has no authorized assertionMethod. Supplied DID: ${didUri}`;
                throw new InvalidRequestError(message);
            }
            if (!isAssertionMethodAuthorized(didDocument, assertionMethod)) {
                throw new InvalidRequestError(`DID has not authorized assertionMethod. Supplied DID: ${didUri}`);
            }
            return didUri;
        });
};

const isAssertionMethodAuthorized = (didDocument, assertionMethod) => {
    const {assertionMethod: authorizedAssertionMethods} = didDocument;
    return authorizedAssertionMethods.some(method => {
        if (typeof method === 'string') {
            return method === assertionMethod;
        }
        return method.id === assertionMethod;
    });
};

export default {getDidDocument, extractDidFromVerificationMethod, validateAssertionMethod};
