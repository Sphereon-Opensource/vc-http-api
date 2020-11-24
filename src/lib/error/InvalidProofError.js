import InvalidRequestError from './InvalidRequestError';

export default class InvalidProofError extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
