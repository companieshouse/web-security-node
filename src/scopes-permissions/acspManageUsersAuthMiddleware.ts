import { NextFunction, Request, RequestHandler, Response } from "express";
import { AuthOptions } from "..";
import { RequestScopeAndPermissions } from "../private-helpers/RequestScopeAndPermissions";
import { authMiddlewareHelper } from "../private-helpers/authMiddlewareHelper";
import { logger, LOG_MESSAGE_APP_NAME } from "../private-helpers/createLogger";
import { InvalidAcspNumberError } from "./errors";

export const acspManageUsersAuthMiddleware = (options: AuthOptions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const { acspNumber } = options;
    const authMiddlewareConfig: AuthOptions = {
        chsWebUrl: options.chsWebUrl,
        returnUrl: options.returnUrl,
        acspNumber
    };

    if (typeof acspNumber !== "string" || !acspNumber?.length || acspNumber === "undefined") {
        logger.error(`${LOG_MESSAGE_APP_NAME} - acspManageUsersAuthMiddleware: Acsp Number invalid`);
        throw new InvalidAcspNumberError(`invalid ACSP number - ${acspNumber}`);
    }

    const acspManageUsersRequestScopeAndPermissions: RequestScopeAndPermissions = {
        scope: `https://api.company-information.service.gov.uk/authorized-corporate-service-provider/${acspNumber}`,
        tokenPermissions: {
            "acsp_members": "read",
            acsp_number: acspNumber
        }
    };

    logger.debug(`${LOG_MESSAGE_APP_NAME} - Auth acspManageUsers`);

    return authMiddlewareHelper(authMiddlewareConfig, acspManageUsersRequestScopeAndPermissions)(req, res, next);

};
