import universityDegreeCredentialExample from './resources/universityDegreeCredentialExample.json';
import {assertValidIssuanceCredential, verifyCredentialStructure} from '../lib/credential';
import InvalidCredentialStructureError from '../lib/error/InvalidCredentialStructureError';

describe('Credential lib tests', () => {
    describe('verifyCredentialStructure', () => {
        const assertFailVerifyCredentialStructure = (invalidCredentialExample, done) => {
            try {
                verifyCredentialStructure(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    return done(new Error(message));
                }
                return done();
            }
            return done(new Error('verifyCredentialStructure did not throw error when expected.'))
        };

        it('should succeed when credential structure is valid', () => {
            verifyCredentialStructure(universityDegreeCredentialExample);
        });
        it('should fail when no proof is present', done => {
            const invalidCredentialExample = {...universityDegreeCredentialExample, proof: null};
            assertFailVerifyCredentialStructure(invalidCredentialExample, done);
        });
        it('should fail when no proofPurpose is present', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                proof: {...universityDegreeCredentialExample.proof, proofPurpose: null},
            };
            assertFailVerifyCredentialStructure(invalidCredentialExample, done);
        });
        it('should fail when no proof created date is supplied', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                proof: {...universityDegreeCredentialExample.proof, created: null},
            };
            assertFailVerifyCredentialStructure(invalidCredentialExample, done);
        });
    });
    describe('assertValidIssuanceCredential', () => {
        const assertFailAssertValidIssuanceCredential = (invalidCredentialExample, done) => {
            try {
                assertValidIssuanceCredential(invalidCredentialExample);
            } catch (err) {
                if (!(err instanceof InvalidCredentialStructureError)) {
                    const message = `Expected InvalidCredentialStructureError but got ${err.name}`;
                    return done(new Error(message));
                }
                return done();
            }
            return done(new Error('assertValidIssuanceCredential did not throw error when expected'));
        };
        it('should succeed when credential is valid', () => {
            assertValidIssuanceCredential(universityDegreeCredentialExample);
        });
        it('should fail when no context is provided', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                ['@context']: null,
            };
            assertFailAssertValidIssuanceCredential(invalidCredentialExample, done);
        });
        it('should fail when no issuer is provided', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                issuer: null,
            };
            assertFailAssertValidIssuanceCredential(invalidCredentialExample, done);
        });
        it('should fail when first context value isn\'t W3C V1 VC context', done => {
            const invalidCredentialExample = {
                ...universityDegreeCredentialExample,
                ['@context']: [
                    'https://www.w3.org/2018/credentials/examples/v1',
                    ...universityDegreeCredentialExample['@context']
                ],
            };
            assertFailAssertValidIssuanceCredential(invalidCredentialExample, done);
        });
    });
});
