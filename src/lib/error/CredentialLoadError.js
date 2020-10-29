import ApiError from "./ApiError";

export default class CredentialLoadError extends ApiError {
    constructor(message) {
        super(message);
    }
}
