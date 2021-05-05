"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddleware = void 0;
require("@companieshouse/node-session-handler");
const SessionKey_1 = require("@companieshouse/node-session-handler/lib/session/keys/SessionKey");
const SignInInfoKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys");
const structured_logging_node_1 = require("@companieshouse/structured-logging-node");
const APP_NAME = 'web-security-node';
const logger = structured_logging_node_1.createLogger(APP_NAME);
exports.authMiddleware = (options) => (req, res, next) => {
    const appName = 'CH Web Security Node';
    const redirectURI = `${options.accountWebUrl}/signin?return_to=${options.returnUrl}`;
    logger.debug(`${JSON.stringify(options)} - Log options variables!`);
    if (!req.session) {
        logger.debug(`${appName} - handler: Session object is missing!`);
        return res.redirect(redirectURI);
    }
    const signInInfo = req.session.get(SessionKey_1.SessionKey.SignInInfo) || {};
    const signedIn = signInInfo[SignInInfoKeys_1.SignInInfoKeys.SignedIn] === 1;
    const userProfile = signInInfo[SignInInfoKeys_1.SignInInfoKeys.UserProfile] || {};
    const userId = userProfile === null || userProfile === void 0 ? void 0 : userProfile.id;
    logger.debug(`${JSON.stringify(signInInfo)} - Log signInInfo variables!`);
    if (!signedIn) {
        logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`);
    next();
};