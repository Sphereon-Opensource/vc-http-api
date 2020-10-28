import publish from './publish';

const PublishMethod = Object.freeze({
    HOSTED: 'hosted',
    GITHUB: 'github',
});

const RevocationCredentialConstants = Object.freeze({
    DEFAULT_PATH: 'revocation-credential.jsonld'
});

export {publish, PublishMethod, RevocationCredentialConstants};
