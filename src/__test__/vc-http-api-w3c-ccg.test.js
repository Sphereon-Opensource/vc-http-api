import express from 'express';
import {v4 as uuid} from 'uuid';
import {expect} from 'chai';
import api from '../api';
import config from '../config.json';
import request from 'supertest';
import User from '../models/User';
import sinon from 'sinon';
import passport from '../middleware/passport';
import resources from './resources/w3cTestResources';
import bodyParser from 'body-parser';

const app = express();
app.use(bodyParser.json({
    limit: config.bodyLimit
}));
app.use('/services', api({config}));
const UserStub = sinon.stub(User);

describe('W3C VC HTTP API Tests', () => {
    let help;
    before(() => {
        return new Promise(resolve => {
            UserStub.findOne.callsFake((query, callback) =>
                callback(null, {
                    comparePassword: (password, callback) => {
                        callback(null, true)
                    }
                }));
            request(app)
                .post('/services/auth/login')
                .set('Authorization', 'Basic ' + Buffer.from('test-username:test-password').toString('base64'))
                .end((err, res) => {
                    const token = res.body.token;
                    help = {
                        postJson: (endpoint, body) => new Promise((resolve, reject) => {
                            request(app)
                                .post(endpoint)
                                .type('json')
                                .set('Authorization', 'bearer ' + token)
                                .send(body)
                                .end((err, res) => {
                                    if (err) {
                                        reject(err);
                                        return;
                                    }
                                    resolve(res);
                                });
                        })
                    };
                    resolve();
                });
        });
    });
    describe('Issuer', () => {
        describe('Issue Credential HTTP API', () => {
            let credentials;
            const issuer_vms = [];
            const issuer = resources.issuers[0];
            describe(issuer.name + ' ' + issuer.endpoint, () => {
                beforeEach(() => {
                    const clonedVendorCredentials = cloneObj(resources.credentials);
                    credentials = annotateWithUniqueId(clonedVendorCredentials);
                });

                // eslint-disable-next-line max-len
                describe('1. The Issuer\'s Issue Credential HTTP API MUST return a 201 HTTP response status code after successful credential issuance.', () => {
                    it('positive test', async () => {
                        const body = {
                            credential: credentials[0],
                            options: issuer.options[0]
                        };
                        const res = await help.postJson(issuer.endpoint, body)
                        expect(res.status).to.equal(201);
                        expect(res.body.proof).to.exist;
                    });
                });

                // eslint-disable-next-line max-len
                describe(`2. The Issuer's Issue Credential HTTP API MUST require "credential" in the body of the POST request. The field "credential" MUST be conformant to [Verifiable Credentials Data Model 1.0](https://www.w3.org/TR/vc-data-model/).`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: credentials[0],
                            options: issuer.options[0]
                        };
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(201);
                        expect(res.body.proof).to.exist;
                    });
                });

                describe('3.1 Can issue with all supplied options', () => {
                    it('test each option for ' + issuer.name, async () => {
                        await Promise.all(
                            issuer.options.map(async issuer_options => {
                                const body = {
                                    credential: credentials[0],
                                    options: {...issuer_options},
                                };
                                const res = await help.postJson(issuer.endpoint, body);
                                expect(res.status).to.equal(201);
                                expect(res.body.proof).to.exist;
                                if (
                                    // eslint-disable-next-line max-len
                                    issuer_vms.indexOf(
                                        res.body.proof.verificationMethod
                                    ) === -1
                                ) {
                                    issuer_vms.push(res.body.proof.verificationMethod);
                                }
                            })
                        );
                    });
                });

                // eslint-disable-next-line max-len
                describe(`4. The Issuer's Issue Credential HTTP API MUST return a 400 HTTP response status code when the request is rejected.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: {
                                ...credentials[0],
                                '@context': 'force_error',
                            },
                            options: issuer.options[0]
                        };
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(400);
                    });
                });

                // eslint-disable-next-line max-len
                describe(`5. The Issuer's Issue Credential HTTP API MUST return a Verifiable Credential with the value of its "issuer" or "issuer.id" as a URI in the body of the response.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: credentials[0],
                            options: issuer.options[0]
                        };
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(201);
                        expect(res.body).to.exist;
                        expect(res.body.issuer).to.exist;
                        const issuerId = res.body.issuer || res.body.issuer.id;
                        expect(issuerId).to.exist;
                    });
                });

                // eslint-disable-next-line max-len
                describe(`6. The Issuer's Issue Credential HTTP API MUST reject if the value of "options.proofPurpose" in the body of the POST request is not supported.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: credentials[0],
                            options: {
                                ...issuer.options[0],
                                proofPurpose: 'foo',
                            },
                        };
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(400);
                    });
                });

                // eslint-disable-next-line max-len
                describe(`7. The Issuer's Issue Credential HTTP API MUST reject if the value of "options.assertionMethod" in the body of the POST request does not exist.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: {
                                ...credentials[0],
                            },
                            options: {
                                ...issuer.options[0],
                                assertionMethod: 'foo',
                            },
                        };
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(400);
                    });
                });

                // eslint-disable-next-line max-len
                describe(`8. The Issuer's Issue Credential HTTP API MUST reject if the value of "credential" in the body of the POST request does not contain a context.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: {
                                ...credentials[0],
                            },
                        };
                        delete body.credential['@context'];
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(400);
                    });
                });

                // eslint-disable-next-line max-len
                describe(`9. The Issuer's Issue Credential HTTP API MUST reject if the value of "credential" in the body of the POST request contains a malformed JSON-LD context.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: {
                                ...credentials[0],
                            },
                            options: issuer.options[0]
                        };
                        body.credential['@context'] = [
                            'https://www.w3.org/2018/credentials/v1',
                            'broken',
                        ];
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(400);
                    });
                });

                // eslint-disable-next-line max-len
                describe(`10. The Issuer's Issue Credential HTTP API MUST must support no "options" in the body of the POST request.`, () => {
                    it('positive test', async () => {
                        const body = {
                            credential: credentials[0],
                        };
                        const res = await help.postJson(issuer.endpoint, body);
                        expect(res.status).to.equal(201);
                        expect(res.body.proof).to.exist;
                    });
                });
            });

            // This is here, becuase some vendors may only issue from a single
            // DID per endpoint.
            // eslint-disable-next-line max-len
            describe(`3. The Issuer's Issue Credential HTTP API MUST support the issuance of credentials with at least 2 different DID methods as the "issuer" on a Verifiable Credential.`, () => {
                // eslint-disable-next-line max-len
                it('meets criteria after all issuers have been tested', async () => {
                    expect(issuer_vms.length).to.be.least(2);
                });
            });
        });
    });

    describe('Verifier', () => {
        describe('Verify Credential HTTP API', () => {
            let verifiableCredentials;
            beforeEach(() => {
                verifiableCredentials = cloneObj(resources.verifiable_credentials);
            });
            // eslint-disable-next-line max-len
            describe(`1. The Verifier's Verify Credential HTTP API MUST fail to verify a Verifiable Credential with a mutated signature value (ex. a mutated jws) in the proof.`, () => {
                it('should pass with no mutation', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(200);
                    expect(res.body.checks).to.eql(['proof']);
                });
                it('should fail with with mutation', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    body.verifiableCredential.proof.jws += 'bar';
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe(`2. The Verifier's Verify Credential HTTP API MUST fail to verify a Verifiable Credential with the "created" property removed from the proof.`, () => {
                it('should fail with without created in proof', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    delete body.verifiableCredential.proof.created;
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe(`3. The Verifier's Verify Credential HTTP API MUST fail to verify a Verifiable Credential with a mutated "proofPurpose" in the proof.`, () => {
                it('should fail ', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: {...verifiableCredentials[0]},
                        options: {
                            checks: ['proof'],
                        },
                    };
                    body.verifiableCredential.proof.proofPurpose = 'bar';
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('4. The Verifier\'s Verify Credential HTTP API MUST fail to verify a Verifiable Credential with an added property to the credential.', () => {
                it('should fail', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    body.verifiableCredential.newProp = 'foo';
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('5. The Verifier\'s Verify Credential HTTP API MUST fail to verify a Verifiable Credential with a removed property from the credential.', () => {
                it('should fail', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    delete body.verifiableCredential.issuer;
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('6. The Verifier\'s Verify Credential HTTP API MUST fail to verify a Verifiable Credential with a mutated property to the credential.', () => {
                it('should fail ', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    body.verifiableCredential.issuer = 'bar';
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('7. The Verifier\'s Verify Credential HTTP API MUST fail to verify a Verifiable Credential with an added property to the proof.', () => {
                it('should fail ', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    body.verifiableCredential.proof.newProp = 'bar';
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('8. The Verifier\'s Verify Credential HTTP API MUST fail to verify a Verifiable Credential a removed property to the proof.', () => {
                it('should fail ', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    delete body.verifiableCredential.proof.proofPurpose;
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('9. The Verifier\'s Verify Credential HTTP API MUST fail to verify a Verifiable Credential with a mutated property to the proof.', () => {
                it('should fail ', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    body.verifiableCredential.proof.created += 'bar';
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('10. The Verifier\'s Verify Credential HTTP API MUST verify a Verifiable Credential with at least 2 different DID methods set as the issuer property for a credential.', () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const unique_issuers = [];
                    await Promise.all(
                        resources.verifiable_credentials.map(async vc => {
                            const body = {
                                verifiableCredential: vc,
                                options: {
                                    checks: ['proof'],
                                },
                            };
                            const res = await help.postJson(endpoint, body);

                            expect(res.status).to.equal(200);
                            if (unique_issuers.indexOf(vc.issuer) === -1) {
                                unique_issuers.push(vc.issuer);
                            }
                        })
                    );
                    expect(unique_issuers.length).to.be.least(2);
                });
            });

            // eslint-disable-next-line max-len
            describe('11. The Verifier\'s Verify Credential HTTP API MUST adhere to the proof verification format.', () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: verifiableCredentials[0],
                        options: {
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(200);
                    expect(res.body.checks).to.eql(['proof']);
                });
            });

            // eslint-disable-next-line max-len
            describe('12. The Verifier\'s Verify Credential HTTP API MUST return a 400 HTTP response status code when the request is rejected.', () => {
                it('should have error', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const body = {
                        verifiableCredential: null,
                        options: {
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('13. The Verifier\'s Verify Credential HTTP API MUST support the verification of, JSON-LD Proof, Ed25519Signature2018.', () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_credential_endpoint;
                    const vc = verifiableCredentials[0];
                    const proof = Array.isArray(vc.proof) ? vc.proof : [vc.proof];
                    const type = 'Ed25519Signature2018';
                    const ed25519Signature2018 = proof.find(p => p.type === type);
                    expect(ed25519Signature2018).to.exist;
                    const body = {
                        verifiableCredential: vc,
                        options: {
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(200);
                    expect(res.body.checks).to.eql(['proof']);
                });
            });
        });

        describe('Verify Presentation HTTP API', () => {
            let verifiablePresentations;
            beforeEach(() => {
                verifiablePresentations = cloneObj(resources.verifiable_presentations);
            });
            // eslint-disable-next-line max-len
            describe(`1. The Verifier's Verify Presentation HTTP API MUST verify a Verifiable Presentation where the credential's issuer, presentation's holder and credential's subject are different.`, () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_presentation_endpoint;
                    const solutions = [];
                    // this logic needs to account for object and string variations...
                    const test_vps = verifiablePresentations.filter(vp => {
                        return (
                            vp.holder !== vp.verifiableCredential[0].issuer &&
                            vp.holder !==
                            vp.verifiableCredential[0].credentialSubject.id &&
                            vp.verifiableCredential[0].issuer !==
                            vp.verifiableCredential[0].credentialSubject.id
                        );
                    });
                    await Promise.all(
                        test_vps.map(async vp => {
                            // this logic needs to account for objet and string variations
                            expect(vp.holder).to.not.equal(vp.verifiableCredential[0].issuer);
                            expect(vp.holder).to.not.equal(
                                vp.verifiableCredential[0].credentialSubject.id
                            );
                            const body = {
                                verifiablePresentation: vp,
                                options: {
                                    challenge: vp.proof.challenge,
                                    domain: vp.proof.domain,
                                    checks: ['proof'],
                                },
                            };
                            const res = await help.postJson(endpoint, body);
                            expect(res.status).to.equal(200);
                            solutions.push(vp);
                        })
                    );
                    expect(solutions.length).to.be.least(1);
                });
            });

            // eslint-disable-next-line max-len
            describe(`2. The Verifier's Verify Presentation HTTP API MUST verify a Verifiable Presentation where the credential's issuer, presentation's holder and credential's subject are the same.`, () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_presentation_endpoint;
                    // this logic needs to account for object and string variations...
                    const test_vps = verifiablePresentations.filter(vp => {
                        return (
                            vp.holder === vp.verifiableCredential[0].issuer &&
                            vp.holder === vp.verifiableCredential[0].credentialSubject.id
                        );
                    });
                    const solutions = [];
                    await Promise.all(
                        test_vps.map(async vp => {
                            const body = {
                                verifiablePresentation: vp,
                                options: {
                                    challenge: vp.proof.challenge,
                                    domain: vp.proof.domain,
                                    checks: ['proof'],
                                },
                            };
                            const res = await help.postJson(endpoint, body);
                            expect(res.status).to.equal(200);
                            solutions.push(vp);
                        })
                    );
                    expect(solutions.length).to.be.least(1);
                });
            });

            // eslint-disable-next-line max-len
            describe('3. The Verifier\'s Verify Presentation HTTP API MUST adhere to the proof verification format.', () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_presentation_endpoint;
                    const body = {
                        verifiablePresentation: verifiablePresentations[0],
                        options: {
                            challenge: verifiablePresentations[0].proof.challenge,
                            domain: verifiablePresentations[0].proof.domain,
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(200);
                    expect(res.body.checks).to.eql(['proof']);
                });
            });

            // eslint-disable-next-line max-len
            describe('4. The Verifier\'s Verify Presentation HTTP API MUST return a 400 HTTP response status code when the request is rejected.', () => {
                it('should have error', async () => {
                    const endpoint = resources.verify_presentation_endpoint;
                    const body = {
                        verifiablePresentation: null,
                        options: {
                            challenge: verifiablePresentations[0].proof.challenge,
                            domain: verifiablePresentations[0].proof.domain,
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });

            // eslint-disable-next-line max-len
            describe('5. The Verifier\'s Verify Presentation HTTP API MUST support the verification of, JSON-LD Proof, Ed25519Signature2018.', () => {
                it('should pass', async () => {
                    const endpoint = resources.verify_presentation_endpoint;
                    const vp = verifiablePresentations[0];
                    const proof = Array.isArray(vp.proof) ? vp.proof : [vp.proof];
                    const type = 'Ed25519Signature2018';
                    const ed25519Signature2018 = proof.find(p => p.type === type);
                    expect(ed25519Signature2018).to.exist;
                    const body = {
                        verifiablePresentation: verifiablePresentations[0],
                        options: {
                            challenge: verifiablePresentations[0].proof.challenge,
                            domain: verifiablePresentations[0].proof.domain,
                            checks: ['proof'],
                        },
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(200);
                    expect(res.body.checks).to.eql(['proof']);
                });
            });

            // eslint-disable-next-line max-len
            describe(`6. The Verifier's Verify Presentation HTTP API MUST support "options.challenge" in the body of the POST request.`, () => {
                it('should have error', async () => {
                    const endpoint = resources.verify_presentation_endpoint;
                    const body = {
                        verifiablePresentation: verifiablePresentations[0],
                    };
                    const res = await help.postJson(endpoint, body);
                    expect(res.status).to.equal(400);
                });
            });
        });
    });
})
;


function cloneObj(obj) {
    return JSON.parse(JSON.stringify(obj));
}

function annotateWithUniqueId(credentials) {
    return credentials.map(credential =>
        credential.id ?
            {
                ...credential,
                id: `${credential.id}#${uuid()}`,
            } :
            credential
    );
}
