import {publishRevocationCredential, validateRevocationConfig} from '../lib/revocation';
import sinon from "sinon";
import {assert} from 'chai';
import GitHubApi from 'github-api';
import Credential from '../models/Credential';
import revocationCredentialExample from './resources/revocationCredentialExample.json';
import config from '../config.json';
import InvalidRequestError from "../lib/error/InvalidRequestError";

describe('Revocation tests', () => {
    const GitHubApiStub = sinon.stub(GitHubApi.prototype, 'getRepo');
    const CredentialStub = sinon.stub(Credential);
    const gitHubRevocationConfig = {
        publishMethod: 'github',
        gitHubOptions: {
            token: '<token>',
            owner: '<owner>',
            repo: '<repo>',
            branch: 'master',
            credentialId: 'test-credential-id',
        },
        listSize: 1000,
        id: 'test-revocation-id'
    };
    const hostedRevocationConfig = {
        publishMethod: 'hosted',
        hostedOptions: {
            credentialId: 'test-credential-id',
        },
        listSize: 1000,
        id: 'test-revocation-id'
    };

    describe('validateRevocationConfig', () => {
        it('should fail when publishMethod doesn\'t match options', done => {
            const revocationConfig = {
                ...hostedRevocationConfig,
                publishMethod: 'github',
            };
            validateRevocationConfig(revocationConfig)
                .then(() => done(new Error('validateRevocationConfig succeeded when it should fail')))
                .catch(() => done());
        });
        it('should pass when valid hosted publishMethod and options', done => {
            CredentialStub.findOne.callsFake((query, callback) => callback(null, null));
            validateRevocationConfig(hostedRevocationConfig)
                .then(() => done())
                .catch(done);
        });
        it('should pass when valid github publishMethod and options', done => {
            GitHubApiStub.returns({
                getBranch: branch => new Promise(resolve => resolve())
            });
            validateRevocationConfig(gitHubRevocationConfig)
                .then(() => done())
                .catch(done);
        });
        it('should fail when hosted credential id already exists', done => {
            CredentialStub.findOne.callsFake((query, callback) => callback(null, {}));
            validateRevocationConfig(hostedRevocationConfig)
                .then(() => done(new Error('test succeeded when credential already exists')))
                .catch(err => {
                    assert.instanceOf(err, InvalidRequestError)
                    done();
                });
        });
    });
    describe('publish', () => {
        it('should return correct github pages url for github config', done => {
            GitHubApiStub.returns({
                writeFile: (commitBranch,
                            commitPath,
                            content,
                            commitMessage,
                            callback) => callback(null)
            });
            const revocationConfig = {
                ...gitHubRevocationConfig,
                gitHubOptions:{
                    ...gitHubRevocationConfig.gitHubOptions,
                    path: 'test.jsonld',
                },
            }
            publishRevocationCredential(revocationCredentialExample, revocationConfig)
                .then(url => {
                    assert.typeOf(url, 'string');
                    assert.equal(url, 'https://<owner>.github.io/<repo>/test.jsonld');
                    done()
                }).catch(done);
        });
        it('should return correct hosted url for hosted config', done => {
            CredentialStub.findOne.callsFake((query, callback) =>
                callback(null, {
                    save: () =>
                        new Promise(resolve => resolve())
                })
            );
            config.baseUrl = 'http://example.com';
            publishRevocationCredential(revocationCredentialExample, hostedRevocationConfig)
                .then(url => {
                    assert.typeOf(url, 'string');
                    assert.equal(url, 'http://example.com/services/credentials/test-credential-id');
                    done()
                }).catch(done);
        });
    });
});
