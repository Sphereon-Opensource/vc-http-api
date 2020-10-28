import InvalidRequestError from "./InvalidRequestError";

export default class InvalidGitHubOptions extends InvalidRequestError {
    constructor(message) {
        super(message);
    }
}
