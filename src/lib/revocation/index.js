import publish from './publish';
import {createList} from 'vc-revocation-list';
import Promise from 'promise';
import github from "./publish/github";
import RevocationPublishError from "../error/RevocationPublishError";

const PublishMethod = Object.freeze({
    HOSTED: 'hosted',
    GITHUB: 'github',
});

const createRevocationCredential = async (listSize, issuer) => {
    const list = await createList({length: listSize});
    const encodedList = await list.encode();
    return {
        "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/vc-revocation-list-2020/v1"],
        issuer,
        issuanceDate: (new Date()).toISOString(),
        type: ["VerifiableCredential", "RevocationList2020Credential"],
        credentialSubject: {
            id: `${issuer}#list`,
            type: "RevocationList2020",
            encodedList,
        },
    };
};

const publishRevocationCredential = (rc, revocationConfig) => {
    switch (revocationConfig.publishMethod) {
        case PublishMethod.GITHUB:
            return github.publish({...revocationConfig.gitHubOptions, content: rc});
        default:
            return new Promise((_, reject) => reject(
                new RevocationPublishError(`Invalid publishMethod saved in config.
                 Expected one of ${Object.values(PublishMethod)} but received ${revocationConfig.publishMethod}`)
            ));
    }
};

export {
    publish,
    PublishMethod,
    createRevocationCredential,
    publishRevocationCredential,
};
