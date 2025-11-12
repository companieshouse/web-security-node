"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.additionalScopeIsRequired = void 0;
const UserProfileKeys_1 = require("@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys");
const createLogger_1 = require("./createLogger");
function additionalScopeIsRequired(requestScopeAndPermissions, userProfile, userId = 'UNKNOWN') {
    if (!requestScopeAndPermissions) {
        createLogger_1.logger.info(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId}, user has not specified any scopes`);
        return false;
    }
    if (!userProfile.hasOwnProperty(UserProfileKeys_1.UserProfileKeys.TokenPermissions)) {
        createLogger_1.logger.info(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId}, UserProfile missing Token Permissions property`);
        return true;
    }
    const userProfileTokenPermissions = userProfile[UserProfileKeys_1.UserProfileKeys.TokenPermissions];
    if (userProfileTokenPermissions == null) {
        createLogger_1.logger.info(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId}, UserProfile Token Permissions property has null value`);
        return true;
    }
    for (const key in requestScopeAndPermissions.tokenPermissions) {
        createLogger_1.logger.debug(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId} key=${key}, checking UserProfile for token permission key`);
        if (!userProfileTokenPermissions.hasOwnProperty(key)) {
            createLogger_1.logger.debug(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId} key=${key}, token permission key is missing in userProfile, so since we request this permission we will need to add it`);
            return true;
        }
        const requestValue = requestScopeAndPermissions.tokenPermissions[key];
        const userProfileValue = userProfileTokenPermissions[key];
        const normaliseCommaSeparatedString = (value) => {
            return value
                .split(',')
                .map(item => item.trim())
                .filter(item => item !== '')
                .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }))
                .join(',');
        };
        const requestArray = normaliseCommaSeparatedString(requestValue);
        const userProfileArray = normaliseCommaSeparatedString(userProfileValue);
        if (!userProfileArray.includes(requestArray)) {
            createLogger_1.logger.debug(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId} key=${key}, user profile does not have all the permissions for the requested token permission key`);
            return true;
        }
    }
    createLogger_1.logger.debug(`${createLogger_1.LOG_MESSAGE_APP_NAME} userId=${userId}, user profile HAS all the permissions for the requested token permission keys`);
    return false;
}
exports.additionalScopeIsRequired = additionalScopeIsRequired;
