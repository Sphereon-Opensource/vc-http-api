import InvalidRequestError from "./InvalidRequestError";

export default class InvalidIssuanceOptionsError extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
