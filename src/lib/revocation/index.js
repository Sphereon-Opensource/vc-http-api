import {assertRevocationList2020Context, checkStatus, createList, decodeList} from 'vc-revocation-list';
import vcjs from 'vc-js';
import Promise from 'promise';
import publishing from './publishing';
import {documentLoader} from '../customDocumentLoader';
import RevocationPublishError from '../error/RevocationPublishError';
import InvalidRequestError from '../error/InvalidRequestError';
import {getSuite} from "../verificationService";
import ResourceNotFoundError from '../error/ResourceNotFoundError';
import CredentialLoadError from '../error/CredentialLoadError';
import InvalidRevocationOptions from "../error/InvalidRevocationOptions";

const PublishMethod = Object.freeze({
    HOSTED: 'hosted',
    GITHUB: 'github',
});

const validateRevocationConfig = async revocationConfig => {
    const {publishMethod, gitHubOptions, hostedOptions, listSize, id} = revocationConfig;
    if (!listSize || typeof listSize !== "number") {
        const message = `Unexpected listSize value. ${listSize} is not of type number.`;
        throw new InvalidRevocationOptions(message);
    }
    if (!id) {
        throw new InvalidRevocationOptions("Revocation id must not be empty.");
    }
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
    const vcSuite = await getSuite(vc.proof);
    const rvc = await _loadRevocationListCredential(vc);
    const rvcSuite = await getSuite(rvc.proof);
    return Promise.all([
        checkStatus({credential: vc, documentLoader, suite: vcSuite, verifyRevocationListCredential: false}),
        vcjs.verifyCredential({credential: rvc, documentLoader, suite: rvcSuite})
    ]).then(([vcRes, rvcRes]) => {
        if (vcRes.verified && rvcRes.verified) {
            return {...rvcRes, revocation: true};
        }
        return {...vcRes};
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

const checkRevocationStatus = async (rvc, index) => {
    const {credentialSubject: rl} = rvc;
    const {encodedList} = rl;
    let list;
    try {
        list = await decodeList({encodedList});
    } catch (e) {
        throw new Error(`Could not decode encoded revocation list; reason: ${e.message}`);
    }
    return list.isRevoked(index);
}

const _loadRevocationListCredential = vc => {
    if (!vc || !vc.credentialStatus || !vc.credentialStatus.revocationListCredential) {
        throw new Error('Supplied VC is not a RevocationList2020 credential.');
    }
    const rvcUrl = vc.credentialStatus.revocationListCredential;
    return documentLoader(rvcUrl)
        .then(res => {
            const rvc = res.document;
            if (!rvc.proof) {
                const message = `Revocation credential has no proof object at URL: ${rvcUrl}`;
                throw new CredentialLoadError(message);
            }
            return rvc;
        })
        .catch(err => {
            const message = `Could not resolve url for revocation credential. 
            Provided: ${vc.credentialStatus.revocationListCredential}. Originating error: ${err.message}`;
            throw new ResourceNotFoundError(message);
        });
};

export {
    validateRevocationConfig,
    createRevocationCredential,
    publishRevocationCredential,
    getRevocationCredential,
    updateRevocationCredential,
    verifyCredentialWithRevocation,
    checkRevocationStatus
};
