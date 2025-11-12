"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddlewareHelper = void 0;
require("@companieshouse/node-session-handler");
const SessionKey_1 = require("@companieshouse/node-session-handler/lib/session/keys/SessionKey");
const SignInInfoKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys");
const UserProfileKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys");
const crypto_1 = __importDefault(require("crypto"));
const additionalScopeIsRequired_1 = require("./additionalScopeIsRequired");
const createLogger_1 = require("./createLogger");
const authMiddlewareHelper = (options, requestScopeAndPermissions) => (req, res, next) => {
    var _a, _b, _c, _d, _e;
    const appName = createLogger_1.LOG_MESSAGE_APP_NAME;
    createLogger_1.logger.debug(`${appName} - handler: in auth helper function`);
    if (!options.chsWebUrl) {
        createLogger_1.logger.error(`${appName} - handler: Required Field CHS Web URL not set`);
        throw new Error('Required Field CHS Web URL not set');
    }
    let redirectURI = buildRedirectUri(options);
    if (!req.session) {
        if (requestScopeAndPermissions) {
            redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`);
        }
        createLogger_1.logger.debug(`${appName} - handler: Session object is missing!`);
        return res.redirect(redirectURI);
    }
    const signInInfo = req.session.get(SessionKey_1.SessionKey.SignInInfo) || {};
    const signedIn = signInInfo[SignInInfoKeys_1.SignInInfoKeys.SignedIn] === 1;
    const userProfile = signInInfo[SignInInfoKeys_1.SignInInfoKeys.UserProfile] || {};
    const userId = userProfile === null || userProfile === void 0 ? void 0 : userProfile.id;
    const hijackFilter = (_b = (_a = req.session) === null || _a === void 0 ? void 0 : _a.data[SessionKey_1.SessionKey.Hijacked]) !== null && _b !== void 0 ? _b : '0';
    const clientSignature = (_d = (_c = req.session) === null || _c === void 0 ? void 0 : _c.data[SessionKey_1.SessionKey.ClientSig]) !== null && _d !== void 0 ? _d : '';
    const computedSignature = computeSignatureFromRequest(req);
    if (parseInt(hijackFilter, 10) === 1) {
        return res.redirect(redirectURI);
    }
    if (signedIn) {
        if (computedSignature !== clientSignature) {
            if (!clientSignature.length) {
                req.session.data[`${SessionKey_1.SessionKey.ClientSig}`] = computedSignature;
            }
            else {
                createLogger_1.logger.info(`${appName} - possible hijack detected, forcing redirect to sign in page`);
                createLogger_1.logger.info(`${appName} - clientSignature: ${clientSignature}`);
                createLogger_1.logger.info(`${appName} - computedSignature: ${computedSignature}`);
                createLogger_1.logger.info(`${appName} - session_cookie_id": ${(_e = req.session) === null || _e === void 0 ? void 0 : _e.data[SessionKey_1.SessionKey.Id]}`);
                req.session.data = {};
                return res.redirect(redirectURI);
            }
        }
    }
    if (requestScopeAndPermissions && (0, additionalScopeIsRequired_1.additionalScopeIsRequired)(requestScopeAndPermissions, userProfile, userId)) {
        redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`);
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Updating URL to: ${redirectURI}`);
    }
    if (!signedIn) {
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    if (requestScopeAndPermissions && (0, additionalScopeIsRequired_1.additionalScopeIsRequired)(requestScopeAndPermissions, userProfile, userId)) {
        createLogger_1.logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }
    createLogger_1.logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`);
    if (userProfile.hasOwnProperty(UserProfileKeys_1.UserProfileKeys.TokenPermissions)) {
        const userProfileTokenPermissions = userProfile[UserProfileKeys_1.UserProfileKeys.TokenPermissions];
        createLogger_1.logger.debug(`${appName} : userId=${userId}, userProfileTokenPermissions : ${JSON.stringify(userProfileTokenPermissions, null, 2)}}`);
    }
    else {
        createLogger_1.logger.debug(`${appName} : userId=${userId}, No userProfileTokenPermissions present`);
    }
    return next();
};
exports.authMiddlewareHelper = authMiddlewareHelper;
function isAuthorisedForCompany(companyNumber, signInInfo) {
    const authorisedCompany = signInInfo[SignInInfoKeys_1.SignInInfoKeys.CompanyNumber];
    if (!authorisedCompany) {
        return false;
    }
    return authorisedCompany.localeCompare(companyNumber) === 0;
}
const computeSignatureFromRequest = (req) => {
    var _a;
    const clientIp = getClientIp(req);
    const hashTarget = `${req.headers['user-agent']}${clientIp}${(_a = process.env) === null || _a === void 0 ? void 0 : _a.COOKIE_SECRET}`;
    return crypto_1.default
        .createHash('sha1')
        .update(hashTarget, 'utf8')
        .digest('hex');
};
const getClientIp = (req) => {
    var _a;
    let ipStr = '';
    if (!req.headers['x-forwarded-for']) {
        return (_a = req.socket) === null || _a === void 0 ? void 0 : _a.remoteAddress;
    }
    else {
        ipStr = Array.isArray(req.headers['x-forwarded-for']) ? req.headers['x-forwarded-for'].toString() : req.headers['x-forwarded-for'];
        return ipStr.split(',').shift();
    }
};
function buildRedirectUri(options) {
    let uri = `${options.chsWebUrl}/signin?return_to=${options.returnUrl}`;
    if (options.companyNumber) {
        uri += `&company_number=${options.companyNumber}`;
        if (options.disableSaveCompanyCheckbox === true) {
            uri += `&company_disable_add_checkbox=true`;
        }
    }
    return uri;
}
