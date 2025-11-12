"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionUnsetError = void 0;
const csrf_error_1 = require("./csrf-error");
class SessionUnsetError extends csrf_error_1.CsrfError {
}
exports.SessionUnsetError = SessionUnsetError;
