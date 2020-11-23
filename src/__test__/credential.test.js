import universityDegreeCredentialExample from './resources/universityDegreeCredentialExample.json';
import {assertValidIssuanceCredential, verifyCredentialStructure} from '../lib/credential';
import InvalidCredentialStructureError from '../lib/error/InvalidCredentialStructureError';

describe('Credential lib tests', () => {
    describe('verifyCredentialStructure', () => {
        it('should succeed when credential structure is valid', () => {
            verifyCredentialStructure(universityDegreeCredentialExample);
        });
        it('should fail when no proof is present', done => {
            const invalidCredentialExample = {...universityDegreeCredentialExample, proof: null};
            try {
                verifyCredentialStructure(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    done(new Error(message));
                    return;
                }
                done();
            }
        });
        it('should fail when no proofPurpose is present', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                proof: {...universityDegreeCredentialExample.proof, proofPurpose: null},
            };
            try {
                verifyCredentialStructure(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    done(new Error(message));
                    return;
                }
                done();
            }
        });
        it('should fail when no proof created date is supplied', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                proof: {...universityDegreeCredentialExample.proof, created: null},
            };
            try {
                verifyCredentialStructure(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    done(new Error(message));
                    return;
                }
                done();
            }
        });
    });
    describe('assertValidIssuanceCredential', () => {
        it('should succeed when credential is valid', () => {
            assertValidIssuanceCredential(universityDegreeCredentialExample);
        });
        it('should fail when no context is provided', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                ['@context']: null,
            };
            try {
               assertValidIssuanceCredential(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    done(new Error(message));
                    return;
                }
                done();
            }
        });
        it('should fail when no issuer is provided', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                issuer: null,
            };
            try {
                assertValidIssuanceCredential(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    done(new Error(message));
                    return;
                }
                done();
            }
        });
    });
});
