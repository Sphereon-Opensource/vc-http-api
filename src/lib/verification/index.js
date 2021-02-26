import {verifyCredentialWithRevocation} from '../revocation';
import revocation from '../../api/revocation';
import {documentLoader} from '../credential';
import VerificationError from '../error/VerificationError';
import vcjs from 'vc-js';
import {parseVcJsVerificationError} from '../util';
import {getSuite} from './suites';


const verifyCredential = async (verifiableCredential) => {
    const verify = await _getVerificationFunction(verifiableCredential);
    return verify(verifiableCredential)
        .then(result => {
            if (result.verified) {
                let checks = ['proof'];
                if (result.revocation) {
                    checks = [...checks, 'revocation']
                }
                return {
                    checks,
                    warnings: [],
                    errors: [],
                };
            }
            parseVcJsVerificationError(result.error);
        });
};


const verifyPresentation = async (verifiablePresentation, challenge) => {
    const {proof} = verifiablePresentation;
    //attempt to fetch did document for credentials
    const {verifiableCredential} = verifiablePresentation;
    let credentialSuites = [];
    let revocationChecks = [];
    if (verifiableCredential && Array.isArray(verifiableCredential)) {
        credentialSuites = await Promise.all(verifiableCredential
            .filter(vc => !!vc.proof)
            .map(vc => getSuite(vc.proof)));
        revocationChecks = await Promise.all(
            verifiableCredential
                .filter(vc => !!vc.credentialStatus)
                .map(vc => verifyCredentialWithRevocation(vc))
        );
    }

    //attempt to fetch suite for presentation
    const presentationSuite = await getSuite(proof);
    return vcjs.verify({
        presentation: verifiablePresentation,
        suite: [...credentialSuites, presentationSuite],
        documentLoader,
        challenge
    }).then(result => {
        let checks = ['proof'];
        if (revocationChecks.length) {
            if (revocationChecks.every(result => result.revocation)) {
                checks = [...checks, 'revocation'];
            } else {
                throw new VerificationError('One or more credentials in the presentation has been revoked');
            }
        }
        if (result.verified) {
            return {
                checks,
                warnings: [],
                errors: [],
            };
        } else {
            parseVcJsVerificationError(result.error);
        }
    });
};

const _getVerificationFunction = async (vc) => {
    if (vc.credentialStatus) {
        return new Promise(resolve => resolve(verifyCredentialWithRevocation));
    }
    const {proof} = vc;
    const suite = await getSuite(proof);
    return credential => vcjs.verifyCredential({credential, suite, documentLoader})
        .catch(parseVcJsVerificationError);
};

export {verifyCredential, verifyPresentation, getSuite};
