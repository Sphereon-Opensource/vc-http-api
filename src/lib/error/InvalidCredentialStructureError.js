import InvalidRequestError from "./InvalidRequestError";

export default class InvalidCredentialStructureError extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
