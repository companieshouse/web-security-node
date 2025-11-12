"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.acspManageUsersAuthMiddleware = void 0;
const authMiddlewareHelper_1 = require("../private-helpers/authMiddlewareHelper");
const createLogger_1 = require("../private-helpers/createLogger");
const errors_1 = require("./errors");
const acspManageUsersAuthMiddleware = (options) => (req, res, next) => {
    const { acspNumber } = options;
    const authMiddlewareConfig = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
        acspNumber
    };
    if (typeof acspNumber !== 'string' || !(acspNumber === null || acspNumber === void 0 ? void 0 : acspNumber.length) || acspNumber === 'undefined') {
        createLogger_1.logger.error(`${createLogger_1.LOG_MESSAGE_APP_NAME} - acspManageUsersAuthMiddleware: Acsp Number invalid`);
        throw new errors_1.InvalidAcspNumberError(`invalid ACSP number - ${acspNumber}`);
    }
    const acspManageUsersRequestScopeAndPermissions = {
        scope: `https://api.company-information.service.gov.uk/authorized-corporate-service-provider/${acspNumber}`,
        tokenPermissions: {
            'acsp_members': 'read',
            acsp_number: acspNumber
        }
    };
    createLogger_1.logger.debug(`${createLogger_1.LOG_MESSAGE_APP_NAME} - Auth acspManageUsers`);
    return (0, authMiddlewareHelper_1.authMiddlewareHelper)(authMiddlewareConfig, acspManageUsersRequestScopeAndPermissions)(req, res, next);
};
exports.acspManageUsersAuthMiddleware = acspManageUsersAuthMiddleware;
