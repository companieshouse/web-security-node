"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CsrfProtectionMiddleware = exports.defaultCsrfTokenFactory = void 0;
const node_session_handler_1 = require("@companieshouse/node-session-handler");
const SessionKey_1 = require("@companieshouse/node-session-handler/lib/session/keys/SessionKey");
const Cookie_1 = require("@companieshouse/node-session-handler/lib/session/model/Cookie");
const structured_logging_node_1 = require("@companieshouse/structured-logging-node");
const express_async_handler_1 = __importDefault(require("express-async-handler"));
const uuid_1 = require("uuid");
const errors_1 = require("./errors");
const APP_NAME = 'web-security-node';
const logger = (0, structured_logging_node_1.createLogger)(APP_NAME);
const DEFAULT_CSRF_TOKEN_HEADER = 'x-csrf-token';
const DEFAULT_CSRF_TOKEN_PARAMETER_NAME = '_csrf';
const MUTABLE_METHODS = ['POST', 'DELETE', 'PUT', 'PATCH'];
const DEFAULT_CHS_SESSION_COOKIE_NAME = '_SID';
const defaultCsrfTokenFactory = () => (0, uuid_1.v4)();
exports.defaultCsrfTokenFactory = defaultCsrfTokenFactory;
const CsrfProtectionMiddleware = (csrfOptions) => {
    return (0, express_async_handler_1.default)(csrfFilter(csrfOptions));
};
exports.CsrfProtectionMiddleware = CsrfProtectionMiddleware;
const csrfFilter = (options) => {
    return (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
        const appName = 'CH Web Security Node';
        if (!options.enabled) {
            console.debug('CSRF protections disabled');
            return next();
        }
        try {
            if (!req.session) {
                logger.error(`${appName} - handler: Session object is missing!`);
                if (MUTABLE_METHODS.includes(req.method)) {
                    throw new errors_1.SessionUnsetError('Session not set.');
                }
                else {
                    return next();
                }
            }
            const headerName = options.headerName || DEFAULT_CSRF_TOKEN_HEADER;
            const parameterName = options.parameterName || DEFAULT_CSRF_TOKEN_PARAMETER_NAME;
            const csrfTokenFactory = options.csrfTokenFactory || exports.defaultCsrfTokenFactory;
            const cookieName = options.sessionCookieName || DEFAULT_CHS_SESSION_COOKIE_NAME;
            const errorWhenNoSessionCookie = options.errorWhenNoSessionCookie || false;
            const hasSessionCookie = typeof req.cookies[cookieName] !== 'undefined';
            const sessionCsrfToken = req.session.get(SessionKey_1.SessionKey.CsrfToken);
            const applyCsrfTokenToLocals = (csrfTokenToUse) => res.locals.csrfToken = csrfTokenToUse;
            if (MUTABLE_METHODS.includes(req.method)) {
                if (!hasSessionCookie && errorWhenNoSessionCookie) {
                    logger.error('Request does not have cookie present.');
                    return next(new errors_1.SessionUnsetError('Performing mutable request and no Session Cookie present'));
                }
                else if (!hasSessionCookie) {
                    logger.info('WARNING: Request does not have cookie present and ' +
                        'performing a mutable request. Not performing further validation.');
                    return next();
                }
                if (!sessionCsrfToken) {
                    throw new errors_1.MissingCsrfSessionToken('Session does not include CSRF token.');
                }
                const csrfTokenInRequest = req.body[parameterName] || req.headers[headerName];
                if (csrfTokenInRequest !== sessionCsrfToken) {
                    logger.error('Possible csrf attack mitigated');
                    throw new errors_1.CsrfTokensMismatchError('Invalid CSRF token.');
                }
                applyCsrfTokenToLocals(sessionCsrfToken);
            }
            else if (!sessionCsrfToken && hasSessionCookie) {
                if (options.createWhenCsrfTokenAbsent !== false) {
                    const csrfToken = csrfTokenFactory();
                    const newSessionData = Object.assign(Object.assign({}, (req.session.data)), { [SessionKey_1.SessionKey.CsrfToken]: csrfToken });
                    req.session = new node_session_handler_1.Session(newSessionData);
                    yield options.sessionStore.store(Cookie_1.Cookie.createFrom(req.cookies[cookieName]), newSessionData);
                    applyCsrfTokenToLocals(csrfToken);
                }
                else {
                    throw new errors_1.MissingCsrfSessionToken('CSRF token not found in session.');
                }
            }
            else if (sessionCsrfToken) {
                applyCsrfTokenToLocals(sessionCsrfToken);
            }
            return next();
        }
        catch (err) {
            logger.errorRequest(req, `Could not handle CSRF validation: ${err}`);
            return next(err);
        }
    });
};
