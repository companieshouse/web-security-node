"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CsrfTokensMismatchError = void 0;
const csrf_error_1 = require("./csrf-error");
class CsrfTokensMismatchError extends csrf_error_1.CsrfError {
}
exports.CsrfTokensMismatchError = CsrfTokensMismatchError;
