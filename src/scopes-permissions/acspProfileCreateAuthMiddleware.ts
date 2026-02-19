import {NextFunction, Request, RequestHandler, Response} from "express";
import {AuthOptions} from "../";
import {RequestScopeAndPermissions} from "../private-helpers/RequestScopeAndPermissions";
import {authMiddlewareHelper} from "../private-helpers/authMiddlewareHelper";
import {logger, LOG_MESSAGE_APP_NAME} from "../private-helpers/createLogger";


export const acspProfileCreateAuthMiddleware = (options: AuthOptions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
) => {

    const authMiddlewareConfig: AuthOptions = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
    };

    const acspProfileCreateRequestScopeAndPermissions: RequestScopeAndPermissions = {
        scope: "https://identity.company-information.service.gov.uk/acsp-profile.create",
        tokenPermissions: {
            "acsp_profile": "create"
        }
    };

    logger.debug(`${LOG_MESSAGE_APP_NAME} - Auth acspProfileCreate`);

    return authMiddlewareHelper(authMiddlewareConfig, acspProfileCreateRequestScopeAndPermissions)(req, res, next);

};
