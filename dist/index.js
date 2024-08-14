"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddleware = void 0;
require("@companieshouse/node-session-handler");
const authMiddlewarePrivate_1 = require("./auth/authMiddlewarePrivate");
__exportStar(require("./csrf-protection"), exports);
__exportStar(require("./scopes-permissions"), exports);
__exportStar(require("./utils"), exports);
const authMiddleware = (options) => (req, res, next) => {
    return (0, authMiddlewarePrivate_1.authMiddlewarePrivate)(options)(req, res, next);
};
exports.authMiddleware = authMiddleware;
