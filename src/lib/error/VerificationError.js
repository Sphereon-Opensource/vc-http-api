import ApiError from './ApiError';

export default class VerificationError extends ApiError {
    constructor(message) {
        super(message);
    }
}
