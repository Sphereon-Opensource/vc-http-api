const {Ed25519KeyPair, suites: { Ed25519Signature2018 }} = require('jsonld-signatures');
const veresOneDid = require('../resources/veresOneDid');
const vc = require('vc-js');
const {documentLoader} = require('./customDocumentLoader');

function getVeresSuite() {
    const kid = 'did:v1:test:nym:z6MkvSbsrm44VnhngbyW2rZk2u9bvSPUSmJwqYjMd4RSJT7A#z6MkjFhRvbXfjmQ8iFHeYh42cNS7v4CtguLzvwZSXcHe8zqy';
    const key = veresOneDid.keys[kid];
    const importKey = new Ed25519KeyPair({...key});
    return new Ed25519Signature2018({
        verificationMethod: key.id,
        key: importKey,
    });
}

function issueVeresCredential(credential){
    if(!credential.issuer || credential.issuer !== veresOneDid.did){
        credential.issuer = veresOneDid.did;
    }
    return vc.issue({credential: credential, suite: getVeresSuite(), documentLoader})
}

module.exports = {issueVeresCredential};
