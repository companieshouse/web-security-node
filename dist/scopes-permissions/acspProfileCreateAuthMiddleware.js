"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.acspProfileCreateAuthMiddleware = void 0;
const authMiddlewareHelper_1 = require("../private-helpers/authMiddlewareHelper");
const createLogger_1 = require("../private-helpers/createLogger");
const acspProfileCreateAuthMiddleware = (options) => (req, res, next) => {
    const authMiddlewareConfig = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
    };
    const acspProfileCreateRequestScopeAndPermissions = {
        scope: 'https://identity.company-information.service.gov.uk/acsp-profile.create',
        tokenPermissions: {
            'acsp_profile': 'create'
        }
    };
    createLogger_1.logger.debug(`${createLogger_1.LOG_MESSAGE_APP_NAME} - Auth acspProfileCreate`);
    return (0, authMiddlewareHelper_1.authMiddlewareHelper)(authMiddlewareConfig, acspProfileCreateRequestScopeAndPermissions)(req, res, next);
};
exports.acspProfileCreateAuthMiddleware = acspProfileCreateAuthMiddleware;
