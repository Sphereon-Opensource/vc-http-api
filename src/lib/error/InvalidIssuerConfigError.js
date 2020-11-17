import InvalidRequestError from "./InvalidRequestError";

export default class InvalidIssuerConfigError extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
