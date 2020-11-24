import {resolver} from '../did';
import fetch from 'node-fetch';
import {extendContextLoader} from 'jsonld-signatures';
import {defaultDocumentLoader} from 'vc-js';
import customContexts from '../../resources/cache/customContexts.json';

const documentLoaderExtension = (url) => {
    if (customContexts[url]) {
        return new Promise(resolve => resolve({
            contextUrl: null,
            documentUrl: url,
            document: customContexts[url],
        }));
    }
    if (url.includes('did:')) {
        return resolver.getDidDocument(url).then(didDocument => (
            {
                contextUrl: null,
                documentUrl: url,
                document: didDocument
            }
        ));
    }
    return fetch(url).then(res => res.json())
        .then(jsonContext => (
            {
                contextUrl: null,
                documentUrl: url,
                document: jsonContext
            }
        )).catch(() => defaultDocumentLoader(url));
}

const documentLoader = extendContextLoader(documentLoaderExtension);

export default documentLoader;
