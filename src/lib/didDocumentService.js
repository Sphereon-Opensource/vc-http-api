const fetch = require('node-fetch');
const Promise = require('promise');
const CachedDidDocuments = require('../resources/cache/CachedDidDocuments.json');

const SPHEREON_UNIRESOLVER_URL = "https://uniresolver.sphereon.io//1.0/identifiers";
const PUBLIC_UNIRESOLVER_URL = "https://uniresolver.io/1.0/identifiers";

function getDidDocument(did){
    if(CachedDidDocuments[did]){
        return new Promise(resolve => resolve(CachedDidDocuments[did]));
    }
    return fetch(`${SPHEREON_UNIRESOLVER_URL}/${did}`)
        .then(res => res.json())
        .then(body => {
            if(!body.didDocument){
                throw new Error("Could not find did document with sphereon resolver.");
            }
            return body.didDocument;
        })
        .catch(() => fetch(`${PUBLIC_UNIRESOLVER_URL}/${did}`)
            .then(res => res.json())
            .then(body => body.didDocument)
            .catch(() => {
                throw {code: 400, message: "DID document not found"};
            }));
}

function extractDidFromVerificationMethod(verificationMethod){
    if(!verificationMethod.includes('#')){
        throw {code: 400, message: 'Invalid verification method.'};
    }
    return verificationMethod.split('#')[0];
}

function validateAssertionMethod(assertionMethod, did){
    if(!assertionMethod){
        return new Promise((resolve => resolve({})));
    }
    let didUri = did;
    if(!did){
        didUri = extractDidFromVerificationMethod(assertionMethod);
    }
    return getDidDocument(didUri)
        .then(didDocument => {
            if(!didDocument.assertionMethod){
                throw {code: 400, message: 'DID has not authorized assertionMethod.'};
            }
            if(!isAssertionMethodAuthorized(didDocument, assertionMethod)){
                throw {code: 400, message: 'DID has not authorized assertionMethod.'};
            }
            return didUri;
        })
}

function isAssertionMethodAuthorized(didDocument, assertionMethod){
    const {assertionMethod: authorizedAssertionMethods} = didDocument;
    return authorizedAssertionMethods.some(method =>{
        if(typeof method === 'string'){
            return method === assertionMethod;
        }
        return method.id === assertionMethod;
    });
}

module.exports = {getDidDocument, extractDidFromVerificationMethod, validateAssertionMethod};
