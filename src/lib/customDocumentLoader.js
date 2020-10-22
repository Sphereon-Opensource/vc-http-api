import {getDidDocument} from './didDocumentService';

const {extendContextLoader} = require('jsonld-signatures');
const customContexts = require('../resources/cache/customContexts.json');
const {defaultDocumentLoader} = require('vc-js');
const Promise = require('promise');
const fetch = require('node-fetch');

function customDocumentLoader(url) {
    if (customContexts[url]) {
        return new Promise(resolve => resolve({
            contextUrl: null,
            documentUrl: url,
            document: customContexts[url],
        }));
    }
    if (url.includes('did:')) {
        return getDidDocument(url).then(didDocument => (
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
        )).catch(err => defaultDocumentLoader(url));
}

const documentLoader = extendContextLoader(customDocumentLoader);

module.exports = {documentLoader};
