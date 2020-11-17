import InvalidIssuerConfigError from "../error/InvalidIssuerConfigError";
import {RevocationList2020} from "../revocation";

const W3C_VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const W3C_VC_TYPE = 'VerifiableCredential';

const validateIssuerConfig = issuerConfig => {
    if (!issuerConfig) {
        throw new InvalidIssuerConfigError("No issuer config supplied.");
    }
    if (!issuerConfig.id) {
        throw new InvalidIssuerConfigError("Issuer config must contain an id.");
    }
    if (!issuerConfig.type || !Array.isArray(issuerConfig.type)) {
        const message = `Invalid type parameter in issuer config. Expected an array but got: ${issuerConfig.type}`;
        throw new InvalidIssuerConfigError(message);
    }
    if(!issuerConfig.context || !Array.isArray(issuerConfig.context)) {
        const message = `Invalid context parameter in issuer config. Expected an array but got: ${issuerConfig.context}`;
        throw new InvalidIssuerConfigError(message);
    }
};

const fillDefaultValues = issuerConfig => {
    if (!issuerConfig.context.includes(W3C_VC_CONTEXT)) {
        issuerConfig.context = [W3C_VC_CONTEXT, ...issuerConfig.context];
    }
    if (issuerConfig.revocationListCredential && !issuerConfig.context.includes(RevocationList2020.CONTEXT)) {
        issuerConfig.context = [...issuerConfig.context, RevocationList2020.CONTEXT];
    }
    if (!issuerConfig.type.includes(W3C_VC_TYPE)) {
        issuerConfig.type = [W3C_VC_TYPE, ...issuerConfig.type];
    }
    return issuerConfig;
};

const constructCredentialWithConfig = ({credentialSubject, revocationListIndex, did, config}) => {
    if (!config) {
        const message = 'Configuration required to issue.'
        throw new InvalidIssuerConfigError(message);
    }
    let credential = {
        '@context': [...config.context],
        issuer: did,
        issuanceDate: new Date().toISOString(),
        credentialSubject,
        type: [...config.type],
    };
    if (revocationListIndex && config.revocationListCredential) {
        const credentialStatus = {
            id: `${config.revocationListCredential}#${revocationListIndex}`,
            type: RevocationList2020.STATUS_TYPE,
            revocationListIndex,
            revocationListCredential: config.revocationListCredential,
        };
        credential = {...credential, credentialStatus};
    }
    return credential;
};

export {
    validateIssuerConfig,
    fillDefaultValues,
    constructCredentialWithConfig
};
