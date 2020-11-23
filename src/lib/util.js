import InvalidRequestError from './error/InvalidRequestError';
import ResourceNotFoundError from './error/ResourceNotFoundError';
import ResourceConflictError from './error/ResourceConflictError';
import InvalidCredentialStructureError from './error/InvalidCredentialStructureError';
import ApiError from './error/ApiError';
import VerificationError from './error/VerificationError';
import InvalidProofError from './error/InvalidProofError';

const handleVerificationError = (res, err) => {
    if (err.code && err.message) {
        res.status(err.code).send({message: err.message});
        return;
    }
    if (Array.isArray(err)) {
        err = err[0];
    }
    if (err.name === 'VerificationError' || err.errors) {
        if (err.errors.length) {
            if (err.errors[0].message === 'Invalid signature.') {
                res.status(400).send({message: 'Invalid signature.'});
                return;
            }
            if (err.errors[0].message === 'Could not verify any proofs; no proofs matched the required suite and purpose.') {
                res.status(400).send({message: 'Malformed proof.'});
                return;
            }
            if (err.errors[0].message.includes('in the input was not defined in the context.')) {
                res.status(400).send({message: 'Malformed proof.'});
                return;
            }
        }
    }
    if (!err.message) {
        res.status(500).send({message: 'Could not verify credential.'});
        return;
    }
    if (err.message.includes('property is required.')) {
        res.status(400).send({message: 'Missing property.'});
        return;
    }
    if (err.message.includes('id must be a URL')) {
        res.status(400).send({message: 'Property must be a url'});
        return;
    }
    res.status(500).send({message: 'Could not verify credential.'});
    return;
}

const handleErrorResponse = (res, err) => {
    if (err instanceof InvalidRequestError) {
        return res.status(400).send({message: err.message});
    }
    if (err instanceof ResourceNotFoundError) {
        return res.status(404).send({message: err.message});
    }
    if (err instanceof ResourceConflictError) {
        return res.status(403).send({message: err.message});
    }
    res.status(500).send({message: err.message});
}

const parseVcJsIssuanceError = err => {
    // Not a pretty way to get HTTP response codes from VC-JS, but these are
    // necessary to pass the W3C-CCG test suite.
    if (err.message === 'https://www.w3.org/2018/credentials/v1 needs to be first in the list of contexts.') {
        throw new InvalidCredentialStructureError(err.message);
    } else if (err.name === 'jsonld.InvalidUrl') {
        throw new InvalidCredentialStructureError('Invalid URL in JSONLD context.');
    } else if (err.details && err.details.code === 'loading remote context failed') {
        throw new InvalidCredentialStructureError('Invalid context.');
    }
    throw new ApiError('Could not issue credential');
};

const parseVcJsVerificationError = err => {
    if (!err) {
        // error is unknown, throw generic error.
        throw new VerificationError('Could not verify credential.');
    }
    if (err.name === 'VerificationError' || err.errors) {
        if (err.errors.length) {
            if (err.errors[0].message === 'Invalid signature.') {
                throw new InvalidProofError('Invalid signature.');
            } else if (err.errors[0].message === 'Could not verify any proofs; no proofs matched the required suite and purpose.') {
                throw new InvalidProofError('Malformed proof.');
            } else if (err.errors[0].message.includes('in the input was not defined in the context.')) {
                const message = `Malformed proof. Originating error: ${err.errors[0].message}`;
                throw new InvalidProofError(message)
            }
        }
    }
    if (!err.message) {
        throw new VerificationError('Could not verify credential.');
    }
    if (err.message.includes('property is required.')) {
        const message = `Missing property. Originating error: ${err.message}`;
        throw new InvalidProofError(message);
    }
    if (err.message.includes('id must be a URL')) {
        const message = `Property must be a URL. Originating error: ${err.message}`;
        throw new InvalidProofError(message);
    }
    throw new VerificationError('Could not verify credential.');
};

export {
    handleVerificationError,
    parseVcJsIssuanceError,
    parseVcJsVerificationError,
    handleErrorResponse
}
