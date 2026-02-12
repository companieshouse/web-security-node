import "@companieshouse/node-session-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { SignInInfoKeys} from "@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys";
import { UserProfileKeys } from "@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys";
import { ISignInInfo, IUserProfile } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import crypto from "crypto";
import { NextFunction, Request, RequestHandler, Response } from "express";
import { AuthOptions } from "..";
import { RequestScopeAndPermissions } from "./RequestScopeAndPermissions";
import { additionalScopeIsRequired }  from "./additionalScopeIsRequired";
import { logger, LOG_MESSAGE_APP_NAME } from "./createLogger";

/* tslint:disable-next-line */
export const authMiddlewareHelper = (options: AuthOptions, requestScopeAndPermissions?: RequestScopeAndPermissions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
) => {

    const appName = LOG_MESSAGE_APP_NAME;

    logger.debug(`${appName} - handler: in auth helper function`);

    if (!options.chsWebUrl) {
        logger.error(`${appName} - handler: Required Field CHS Web URL not set`);
        throw new Error("Required Field CHS Web URL not set");
    }

    let redirectURI = buildRedirectUri(options);


    if (!req.session)  {
        if(requestScopeAndPermissions) {
            redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`);
        }
        logger.debug(`${appName} - handler: Session object is missing!`);
        return res.redirect(redirectURI);
    }

    const signInInfo: ISignInInfo = req.session.get<ISignInInfo>(SessionKey.SignInInfo) || {};
    const signedIn: boolean = signInInfo![SignInInfoKeys.SignedIn] === 1;
    const userProfile: IUserProfile = signInInfo![SignInInfoKeys.UserProfile] || {};
    const userId: string | undefined = userProfile?.id;
    const hijackFilter: string = req.session?.data[SessionKey.Hijacked] ?? "0";
    const clientSignature: string = req.session?.data[SessionKey.ClientSig] ?? "";
    const computedSignature: string = computeSignatureFromRequest(req);

    if (parseInt(hijackFilter, 10) === 1) {
        return res.redirect(redirectURI);
    }

    if (signedIn) {
        if (computedSignature !== clientSignature) {
            if (!clientSignature.length) {
                // @ts-ignore
                req.session.data[`${SessionKey.ClientSig}`] = computedSignature;
            } else {
                // possible hijack detected
                logger.info(`${appName} - possible hijack detected, forcing redirect to sign in page`);
                logger.info(`${appName} - clientSignature: ${clientSignature}`);
                logger.info(`${appName} - computedSignature: ${computedSignature}`);
                logger.info(`${appName} - session_cookie_id": ${req.session?.data[SessionKey.Id]}`);
                req.session.data = {};
                return res.redirect(redirectURI);
            }
        }
    }

    if (requestScopeAndPermissions && additionalScopeIsRequired(requestScopeAndPermissions, userProfile, userId)) {
        redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`);
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Updating URL to: ${redirectURI}`);
    }

    if (!signedIn) {
        logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }

    if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }

    if (requestScopeAndPermissions && additionalScopeIsRequired(requestScopeAndPermissions, userProfile, userId)) {
        logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Redirecting to: ${redirectURI}`);
        return res.redirect(redirectURI);
    }

    logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`);

    if (userProfile.hasOwnProperty(UserProfileKeys.TokenPermissions)) {
        const userProfileTokenPermissions = userProfile[UserProfileKeys.TokenPermissions];
        logger.debug(`${appName} : userId=${userId}, userProfileTokenPermissions : ${JSON.stringify(userProfileTokenPermissions, null, 2)}}`);
    } else {
        logger.debug(`${appName} : userId=${userId}, No userProfileTokenPermissions present`);
    }

    return next();
};

function isAuthorisedForCompany(companyNumber: string, signInInfo: ISignInInfo): boolean {
    const authorisedCompany = signInInfo[SignInInfoKeys.CompanyNumber];
    if (!authorisedCompany) {
        return false;
    }

    return authorisedCompany.localeCompare(companyNumber) === 0;
}

const computeSignatureFromRequest = (req: Request): string => {
    const clientIp = getClientIp(req);
    const hashTarget = `${req.headers["user-agent"]}${clientIp}${process.env?.COOKIE_SECRET}`;
    return crypto
        .createHash("sha1")
        .update(hashTarget, "utf8")
        .digest("hex");
};

const getClientIp = (req: Request) => {
    let ipStr = "";
    if (!req.headers["x-forwarded-for"]) {
        return req.socket?.remoteAddress;
    } else {
        ipStr = Array.isArray(req.headers["x-forwarded-for"]) ? req.headers["x-forwarded-for"].toString() : req.headers["x-forwarded-for"];
        return ipStr.split(",").shift();
    }

};

function buildRedirectUri(options: AuthOptions): string {
    let uri = `${options.chsWebUrl}/signin?return_to=${options.returnUrl}`;
    if (options.companyNumber) {
        uri += `&company_number=${options.companyNumber}`;
        if (options.disableSaveCompanyCheckbox === true) {
            uri += `&company_disable_add_checkbox=true`;
        }
    }
    return uri;
}