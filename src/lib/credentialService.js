const {validateAssertionMethod} = require('./didDocumentService');
const factomDid = require('../resources/did/factomDid.json');
const veresOneDid = require('../resources/did/veresOneDid.json');
const Promise = require('promise');

const AllowedProofPurposes = Object.freeze(['assertionMethod']);
const AllowedIssuers = Object.freeze([factomDid.identity.did, veresOneDid.did]);

function verifyCredentialStructure(verifiableCredential) {
    if (!verifiableCredential) {
        throw {code: 400, message: 'No verifiableCredential in request.'};
    }
    if (!verifiableCredential.proof) {
        throw {code: 400, message: 'Verifiable credential requires proof.'};
    }
    const {proof} = verifiableCredential;
    if (!proof.verificationMethod) {
        throw {code: 400, message: 'Credential proof verification method not found.'};
    }

    if (!proof.proofPurpose) {
        throw {code: 400, message: 'Credential proof requires proof purpose field.'};
    }

    if (proof.proofPurpose !== 'assertionMethod') {
        throw {code: 400, message: 'Proof purpose must be assertion method.'};
    }

    if (!proof.created) {
        throw {code: 400, message: 'Proof must contain created field.'};
    }
}

function assertValidIssuanceCredential(credential) {
    if (!credential) {
        throw {code: 400, message: 'Request must contain a credential'};
    }
    if (!credential['@context']) {
        throw {code: 400, message: 'Credential must contain a context'};
    }
}

async function getRequestedIssuer(options) {
    // if no issuer specified, issue on factom did
    if (!options) {
        return factomDid.identity.did;
    }

    if (options.proofPurpose && !AllowedProofPurposes.includes(options.proofPurpose)) {
        throw {code: 400, message: 'Proof purpose not supported.'};
    }

    // if issuer specified
    if (options.issuer && AllowedIssuers.includes(options.issuer)) {
        if (options.assertionMethod) {
            return await validateAssertionMethod(options.assertionMethod, options.issuer);
        }
        return options.issuer;
    }

    if (options.assertionMethod) {
        return await validateAssertionMethod(options.assertionMethod);
    }

    throw {code: 400, message: 'Invalid options'};
}

function assertValidEmployeeCredential(employeeCredential){
    const {credentialSubject} = employeeCredential;

    if(!credentialSubject){
        throw {code:400, message: 'Invalid credential format. No credentialSubject found'};
    }

    const { employee, employer } = credentialSubject;

    if(!employee || !employer){
        throw {code: 400, message: 'Invalid credential format. Credential has wrong employer/employee structure'};
    }

    const {name: employerName} = employer;
    const {givenName: employeeGivenName, familyName: employeeFamilyName, email} = employee;
    if(!employerName || !employeeGivenName | !email || !employeeFamilyName){
        throw {code: 400, message: 'Employer name, employee name and employee email are required'};
    }
}

module.exports = {verifyCredentialStructure, assertValidIssuanceCredential, getRequestedIssuer, assertValidEmployeeCredential};
