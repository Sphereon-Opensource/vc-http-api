import InvalidRequestError from "./InvalidRequestError";

export default class ResourceConflictError extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
