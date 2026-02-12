import {
    CsrfError
} from "./csrf-error";

/**
 * An Error thrown when CSRF token does not match the expected token held
 * within session
 */
export class CsrfTokensMismatchError extends CsrfError { }
