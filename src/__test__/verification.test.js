import {verifyCredential, verifyPresentation} from '../lib/verification';
import {assert} from 'chai';
import RSATestCredential from './resources/RSATestCredential.json';
import RSATestPresentation from './resources/RSATestPresentation.json';

describe('VC verification tests', () => {
    it('should verify a credential with an RSA key type', done => {
        verifyCredential(RSATestCredential)
            .then(res => {
                assert.equal(res.checks[0], 'proof');
                assert.equal(res.errors.length, 0);
                done();
            }).catch(err => done(err));
    });

    it('should verify a presentation signed with an RSA key type', done => {
        verifyPresentation(RSATestPresentation, '1234')
            .then(res => {
                assert.equal(res.checks[0], 'proof');
                assert.equal(res.errors.length, 0);
                done();
            }).catch(err => done(err));
    })
});
