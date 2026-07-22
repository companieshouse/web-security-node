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
    const clientSignatureV2: string = req.session?.data[SessionKey.ClientSigV2] ?? "";
    const computedSignature: string = computeSignatureFromRequest(req);
    const computedSignatureV2: string = computeV2SignatureFromRequest(req);

    if (parseInt(hijackFilter, 10) === 1) {
        return res.redirect(redirectURI);
    }

    if (validateClientSignatures(req, signedIn, clientSignature, clientSignatureV2, computedSignature, computedSignatureV2)) {
        // possible hijack
        return res.redirect(redirectURI);
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
    // Absent User-Agent coerces to "" to match web-security-java HijackFilter.getUserAgent()
    const userAgent = req.headers["user-agent"] ?? "";
    const hashTarget = `${userAgent}${clientIp}${process.env?.COOKIE_SECRET}`;
    return crypto
        .createHash("sha1")
        .update(hashTarget, "utf8")
        .digest("hex");
};

// V2 leaves out the client IP, which isn't stable across services and was
// triggering false hijack detections.
const computeV2SignatureFromRequest = (req: Request): string => {
    const userAgent = req.headers["user-agent"] ?? "";
    const hashTarget = `${userAgent}${process.env?.COOKIE_SECRET}`;
    return crypto
        .createHash("sha1")
        .update(hashTarget, "utf8")
        .digest("hex");
};

// Returns true when a possible hijack is detected
// (caller should redirect). Prefers V2, falls back to legacy V1 and backfills V2,
// or writes both on first sign-in.
const validateClientSignatures = (
    req: Request,
    signedIn: boolean,
    clientSignature: string,
    clientSignatureV2: string,
    computedSignature: string,
    computedSignatureV2: string
): boolean => {
    if (!signedIn) {
        return false;
    }

    const appName = LOG_MESSAGE_APP_NAME;

    if (clientSignatureV2.length) {
        // V2 exists, so only check that
        if (computedSignatureV2 !== clientSignatureV2) {
            logger.info(`${appName} - possible hijack detected, forcing redirect to sign in page`);
            logger.info(`${appName} - signature_version: v2`);
            logger.info(`${appName} - validation_result: mismatch`);
            logger.info(`${appName} - clientSignatureV2: ${clientSignatureV2}`);
            logger.info(`${appName} - computedSignatureV2: ${computedSignatureV2}`);
            logger.info(`${appName} - session_cookie_id: ${req.session?.data[SessionKey.Id]}`);
            clearClientSignatures(req);
            return true;
        }
        logger.debug(`${appName} - signature_version: v2, validation_result: matched`);
        return false;
    }

    if (clientSignature.length) {
        // no V2 yet, fall back to the old IP-based signature
        if (computedSignature !== clientSignature) {
            logger.info(`${appName} - possible hijack detected, forcing redirect to sign in page`);
            logger.info(`${appName} - signature_version: v1`);
            logger.info(`${appName} - validation_result: mismatch`);
            logger.info(`${appName} - clientSignature: ${clientSignature}`);
            logger.info(`${appName} - computedSignature: ${computedSignature}`);
            logger.info(`${appName} - session_cookie_id: ${req.session?.data[SessionKey.Id]}`);
            clearClientSignatures(req);
            return true;
        }
        // old signature is fine, backfill V2 for next time
        logger.debug(`${appName} - signature_version: v1, validation_result: matched, fallback_used: true`);
        // @ts-ignore
        req.session.data[`${SessionKey.ClientSigV2}`] = computedSignatureV2;
        return false;
    }

    // first sign-in, store both
    logger.debug(`${appName} - no client signatures present, writing v1 and v2`);
    // @ts-ignore
    req.session.data[`${SessionKey.ClientSig}`] = computedSignature;
    // @ts-ignore
    req.session.data[`${SessionKey.ClientSigV2}`] = computedSignatureV2;
    return false;
};

// Wipe both signatures on a possible hijack so the next request writes fresh ones.
const clearClientSignatures = (req: Request): void => {
    req.session!.data = {};
};

// Equivalent to Java's InetAddress.isSiteLocalAddress() + the explicit startsWith("127.") check
// in web-security-java HijackFilter.parseIpFromXForwardedFor.
//
// Java uses InetAddress.isSiteLocalAddress() which covers:
//   - RFC 1918 IPv4:        10/8, 172.16/12, 192.168/16  → entries [0–2] below
//   - IPv6 unique local:    fc00::/7                      → entry [7] below
// Java adds an explicit startsWith("127.") check for IPv4 loopback → entry [3] below.
//
// The following entries go further than Java (Java treats these as public):
//   - ::1 (IPv6 loopback)                  → entry [4]
//   - ::ffff: IPv4-mapped private addresses → entry [5]
//   - fe80::/10 IPv6 link-local            → entry [6]
// These cannot appear in real X-Forwarded-For headers in CHS infrastructure, so the
// difference has no practical effect on signature compatibility.
//
// CGNAT (100.64.0.0/10) is intentionally excluded — it is not covered by Java's
// isSiteLocalAddress() and does not appear in X-Forwarded-For in the CHS topology.
const privateRanges = [
    // RFC 1918 IPv4 — equivalent to Java isSiteLocalAddress() for IPv4
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    // IPv4 loopback — equivalent to Java's explicit startsWith("127.") check
    /^127\./,
    // IPv6 loopback — beyond Java; ::1 is treated as public by isSiteLocalAddress()
    /^::1$/,
    // IPv4-mapped IPv6 — beyond Java; checks the embedded IPv4 address
    /^::ffff:(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/i,
    // IPv6 link-local (fe80::/10) — beyond Java; not covered by isSiteLocalAddress()
    /^fe[89ab][0-9a-f]:/i,
    // IPv6 unique local (fc00::/7) — equivalent to Java isSiteLocalAddress() for IPv6
    /^f[cd][0-9a-f]{2}:/i,
];
const isPrivateIp = (ip: string): boolean => privateRanges.some(r => r.test(ip));

// Mirrors the logic in web-security-java HijackFilter.getClientIp / parseIpFromXForwardedFor.
// Returns the rightmost public (non-private) IP from X-Forwarded-For, which is
// set by trusted infrastructure (CDN/WAF/ALB) and cannot be spoofed by the client.
// Falls back to X-REAL-IP, then socket.remoteAddress when X-Forwarded-For is absent.
const getClientIp = (req: Request): string => {
    if (req.headers["x-forwarded-for"]) {
        const ipStr = Array.isArray(req.headers["x-forwarded-for"])
            ? req.headers["x-forwarded-for"].toString()
            : req.headers["x-forwarded-for"];
        const ips = ipStr.split(",").map(ip => ip.trim()).filter(ip => ip.length > 0);
        if (ips.length === 0) {
            return req.socket?.remoteAddress ?? "";
        }
        if (ips.length === 1) {
            return ips[0];
        }
        for (let i = ips.length - 1; i >= 0; i--) {
            if (!isPrivateIp(ips[i])) {
                return ips[i];
            }
        }
        return ips[0];
    }
    // Match web-security-java: fall back to X-REAL-IP before remoteAddr
    const xRealIp = req.headers["x-real-ip"];
    if (xRealIp) {
        return Array.isArray(xRealIp) ? xRealIp[0] : xRealIp;
    }
    return req.socket?.remoteAddress ?? "";
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
