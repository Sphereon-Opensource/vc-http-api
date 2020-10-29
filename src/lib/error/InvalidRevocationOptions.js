import InvalidRequestError from "./InvalidRequestError";

export default class InvalidRevocationOptions extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
