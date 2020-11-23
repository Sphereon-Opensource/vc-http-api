'use strict';

const credentials = require('./credentials');
const verifiable_credentials = require('./verifiable_credentials');
const verifiable_presentations = require('./verifiable_presentations');

module.exports = {
  name: 'VC API',
  // eslint-disable-next-line max-len
  verify_credential_endpoint:
    '/services/verify/credentials',
  // eslint-disable-next-line max-len
  verify_presentation_endpoint:
    '/services/verify/presentations',
  credentials: [...credentials],
  verifiable_credentials: [...verifiable_credentials],
  verifiable_presentations: [...verifiable_presentations],
  issuers: [
    {
      name: 'DID Issuers',
      endpoint: '/services/issue/credentials',
      options: [
        {
          // eslint-disable-next-line
          issuer:
            'did:factom:5d0dd58757119dd437c70d92b44fbf86627ee275f0f2146c3d99e441da342d9f',
          // eslint-disable-next-line max-len
          assertionMethod:
            'did:factom:5d0dd58757119dd437c70d92b44fbf86627ee275f0f2146c3d99e441da342d9f#key-0',
        },
        {
          // eslint-disable-next-line max-len
          issuer:
            'did:v1:test:nym:z6MkvSbsrm44VnhngbyW2rZk2u9bvSPUSmJwqYjMd4RSJT7A',
          // eslint-disable-next-line max-len
          assertionMethod:
            'did:v1:test:nym:z6MkvSbsrm44VnhngbyW2rZk2u9bvSPUSmJwqYjMd4RSJT7A#z6MkjFhRvbXfjmQ8iFHeYh42cNS7v4CtguLzvwZSXcHe8zqy',
        },
      ],
    },
  ],
};
