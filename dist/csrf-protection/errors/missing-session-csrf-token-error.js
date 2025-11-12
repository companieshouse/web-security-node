"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MissingCsrfSessionToken = void 0;
const csrf_error_1 = require("./csrf-error");
class MissingCsrfSessionToken extends csrf_error_1.CsrfError {
}
exports.MissingCsrfSessionToken = MissingCsrfSessionToken;
