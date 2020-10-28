import ApiError from "./ApiError";

export default class RevocationPublishError extends ApiError {
    constructor(message) {
        super(message);
    }
}
