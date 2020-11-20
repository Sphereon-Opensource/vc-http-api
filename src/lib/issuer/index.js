import InvalidIssuerConfigError from "../error/InvalidIssuerConfigError";
import {RevocationList2020} from "../revocation";

const W3C_VC_CONTEXT_V1 = 'https://www.w3.org/2018/credentials/v1';
const W3C_VC_TYPE = 'VerifiableCredential';

const validateIssuerConfig = issuerConfig => {
    if (!issuerConfig) {
        throw new InvalidIssuerConfigError("No issuer config supplied.");
    } else if (!issuerConfig.id) {
        throw new InvalidIssuerConfigError("Issuer config must contain an id.");
    } else if (!issuerConfig.type || !Array.isArray(issuerConfig.type)) {
        const message = `Invalid type parameter in issuer config. Expected an array but got: ${issuerConfig.type}`;
        throw new InvalidIssuerConfigError(message);
    } else if (!issuerConfig.context || !Array.isArray(issuerConfig.context)) {
        const message = `Invalid context parameter in issuer config. Expected an array but got: ${issuerConfig.context}`;
        throw new InvalidIssuerConfigError(message);
    } else if (issuerConfig.context[0] !== W3C_VC_CONTEXT_V1) {
        const message = `Context must have ${W3C_VC_CONTEXT_V1} as the first value in the array.`;
        throw new InvalidIssuerConfigError(message);
    } else if (issuerConfig.revocationListCredential && !issuerConfig.context.includes(RevocationList2020.CONTEXT)) {
        const message = `When revocationListCredential is specified, context must include ${RevocationList2020.CONTEXT}`;
        throw new InvalidIssuerConfigError(message);
    } else if (issuerConfig.type[0] !== W3C_VC_TYPE) {
        const message = `First value in type array must be ${W3C_VC_TYPE}`;
        throw new InvalidIssuerConfigError(message);
    }
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
    constructCredentialWithConfig
};
