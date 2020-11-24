import {Ed25519KeyPair} from 'crypto-ld';
import {suites} from 'jsonld-signatures';
import vcjs from 'vc-js';
import {documentLoader} from '../../credential';
import veresOneDid from '../../../resources/did/veresOneDid.json';
import {parseVcJsIssuanceError} from '../../util';

function getVeresSuite() {
    const kid = 'did:v1:test:nym:z6MkvSbsrm44VnhngbyW2rZk2u9bvSPUSmJwqYjMd4RSJT7A#z6MkjFhRvbXfjmQ8iFHeYh42cNS7v4CtguLzvwZSXcHe8zqy';
    const key = veresOneDid.keys[kid];
    const importKey = new Ed25519KeyPair({...key});
    return new suites.Ed25519Signature2018({
        verificationMethod: key.id,
        key: importKey,
    });
}

function issueVeresCredential(credential){
    if(!credential.issuer || credential.issuer !== veresOneDid.did){
        credential.issuer = veresOneDid.did;
    }
    return vcjs.issue({credential: credential, suite: getVeresSuite(), documentLoader})
        .catch(parseVcJsIssuanceError);
}

module.exports = {issueVeresCredential};
