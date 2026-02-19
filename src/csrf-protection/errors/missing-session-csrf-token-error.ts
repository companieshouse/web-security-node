import { CsrfError } from "./csrf-error";

/**
 * An error thrown when CSRF token is not held within the Session when
 * validating a request.
 */
export class MissingCsrfSessionToken extends CsrfError { }
