import {assertRevocationList2020Context, checkStatus, createList, decodeList} from 'vc-revocation-list';
import Promise from 'promise';
import publishing from "./publishing";
import {documentLoader} from '../customDocumentLoader';
import RevocationPublishError from "../error/RevocationPublishError";
import InvalidRequestError from "../error/InvalidRequestError";
import {getSuite} from "../verificationService";

const PublishMethod = Object.freeze({
    HOSTED: 'hosted',
    GITHUB: 'github',
});

const validateRevocationConfig = async revocationConfig => {
    const {publishMethod, gitHubOptions, hostedOptions} = revocationConfig;
    switch (publishMethod) {
        case PublishMethod.GITHUB:
            await publishing.github.validateGitHubOptions(gitHubOptions);
            break;
        case PublishMethod.HOSTED:
            await publishing.hosted.validateHostedOptions(hostedOptions);
            break;
        default:
            const message = `Invalid publishMethod. Expected one of ${Object.values(PublishMethod)} 
                        but got: ${publishMethod}`;
            throw new InvalidRequestError(message);
    }
};

const createRevocationCredential = async (listSize, issuer) => {
    const list = await createList({length: listSize});
    return _createRevocationListCredential({issuer, issuanceDate: (new Date()).toISOString()}, list);
};

const publishRevocationCredential = (rc, revocationConfig) => {
    switch (revocationConfig.publishMethod) {
        case PublishMethod.GITHUB:
            return publishing.github.publish({...revocationConfig.gitHubOptions, content: rc});
        case PublishMethod.HOSTED:
            return publishing.hosted.publish({...revocationConfig.hostedOptions, content: rc});
        default:
            return new Promise((_, reject) => reject(
                new RevocationPublishError(`Invalid publishMethod saved in config.
                 Expected one of ${Object.values(PublishMethod)} but received ${revocationConfig.publishMethod}`)
            ));
    }
};

const getRevocationCredential = revocationConfig => {
    switch (revocationConfig.publishMethod) {
        case PublishMethod.HOSTED:
            return publishing.hosted.getRevocationCredential({...revocationConfig.hostedOptions});
        case PublishMethod.GITHUB:
            return publishing.github.getRevocationCredential({...revocationConfig.gitHubOptions});
        default:
            return new Promise((_, reject) => reject(
                new RevocationPublishError(`Invalid publishMethod saved in config.
                 Expected one of ${Object.values(PublishMethod)} but received ${revocationConfig.publishMethod}`)
            ));
    }
}

const updateRevocationCredential = async (rvc, revocationIndex, revoked) => {
    assertRevocationList2020Context({credential: rvc});
    const list = await decodeList({encodedList: rvc.credentialSubject.encodedList});
    list.setRevoked(revocationIndex, revoked);
    return _createRevocationListCredential(rvc, list);
};

const verifyCredentialWithRevocation = async vc => {
    const vcSuite = getSuite(vc.proof);
    const rvc = await _loadRevocationListCredential(vc);
    const rvcSuite = getSuite(rvc.proof);
    return checkStatus({credential: vc, documentLoader, suite: [vcSuite, rvcSuite], verifyRevocationListCredential: false})
        .then(res => {
            if(res.verified){
                return {...res, revocation: true};
            }
            return res;
        });
};

const _createRevocationListCredential = async ({issuer, issuanceDate}, list) => {
    const encodedList = await list.encode();
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/vc-revocation-list-2020/v1"],
        issuer,
        issuanceDate,
        type: ["VerifiableCredential", "RevocationList2020Credential"],
        credentialSubject: {
            id: `${issuer}#list`,
            type: "RevocationList2020",
            encodedList,
        },
    };
};

const _loadRevocationListCredential = vc => {
    if(!vc || !vc.credentialStatus || !vc.credentialStatus.revocationListCredential){
        throw new Error('Supplied VC is not a RevocationList2020 credential.');
    }
    return documentLoader(vc.credentialStatus.revocationListCredential)
        .then(res => res.document);
};

export {
    validateRevocationConfig,
    createRevocationCredential,
    publishRevocationCredential,
    getRevocationCredential,
    updateRevocationCredential,
    verifyCredentialWithRevocation
};
