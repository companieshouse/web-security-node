import { CsrfError } from "./csrf-error";

/**
 * A CSRF Error thrown when the session is unset
 */
export class SessionUnsetError extends CsrfError { }
