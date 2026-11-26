import { logger } from "../private-helpers/createLogger";

const DEFAULT_ALLOWLIST = [".gov.uk", ".chdev.org"];
const INVALID_URI_CHARACTERS = /[\s"<>^`{|}]/;
const INVALID_PERCENT_ESCAPE = /%(?![0-9a-f]{2})/i;

const isControlCharacter = (character: string): boolean => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x1f || (code >= 0x7f && code <= 0x9f);
};

const hasInvalidCharacters = (value: string): boolean =>
    value.includes("\\") ||
    Array.from(value).some(isControlCharacter) ||
    INVALID_URI_CHARACTERS.test(value) ||
    INVALID_PERCENT_ESCAPE.test(value);

const hasMalformedPathOrFragment = (value: string): boolean => {
    const rawPath = value.split(/[?#]/, 1)[0];
    const fragmentIndex = value.indexOf("#");
    return rawPath.includes("[") || rawPath.includes("]") ||
        (fragmentIndex >= 0 && value.includes("#", fragmentIndex + 1));
};

const isAllowlisted = (hostname: string, allowlist: readonly string[]): boolean =>
    allowlist.some((allowedDomain) => {
        const domain = allowedDomain.toLowerCase();
        return domain.startsWith(".")
            ? hostname.length > domain.length && hostname.endsWith(domain)
            : hostname === domain;
    });

const reject = (reason: string, destination?: string): null => {
    const suffix = destination ? `; destination=${destination}` : "";
    logger.error(`Return URL rejected: ${reason}${suffix}`);
    return null;
};

const validateAbsoluteReturnTo = (
    returnTo: string,
    allowlist: readonly string[],
    isTestEnvironment: boolean
): string | null => {
    const authorityMatch = /^https:\/\/([^/?#]+)(?:[/?#]|$)/i.exec(returnTo);
    if (!authorityMatch || !/^[a-z0-9.-]+(?::\d+)?$/i.test(authorityMatch[1])) {
        return reject("not a relative path or HTTPS URL with a valid host");
    }

    let parsedUrl: URL;
    try {
        parsedUrl = new URL(returnTo);
    } catch (error) {
        if (error instanceof TypeError) {
            return reject("URL could not be parsed");
        }
        throw error;
    }

    if (parsedUrl.protocol !== "https:" || parsedUrl.username !== "" || parsedUrl.password !== "") {
        return reject("unsupported scheme or user information");
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const rawHostname = authorityMatch[1].split(":")[0].toLowerCase();
    const labelsAreValid = hostname.split(".").every((label) =>
        /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    );
    if (hostname !== rawHostname || hostname.length > 253 || !labelsAreValid) {
        return reject("invalid hostname");
    }
    if (hostname === "chs.local") {
        return isTestEnvironment ? returnTo : reject("chs.local is only allowed in test environments", parsedUrl.origin);
    }
    return isAllowlisted(hostname, allowlist) ? returnTo : reject("host is not allowlisted", parsedUrl.origin);
};

/**
 * Validates a root-relative path or an absolute HTTPS destination.
 *
 * @param returnTo Destination to validate; accepted values are returned unchanged.
 * @param allowlist Trusted suffixes beginning with a dot, or exact hostnames.
 * A supplied list replaces the default .gov.uk and .chdev.org suffixes.
 * @param isTestEnvironment Whether to allow the exact chs.local hostname; defaults to false.
 * @returns The original destination when accepted, otherwise null.
 */
export const validateReturnTo = (
    returnTo: string | null | undefined,
    allowlist: readonly string[] = DEFAULT_ALLOWLIST,
    isTestEnvironment: boolean = false
): string | null => {
    if (typeof returnTo !== "string" || returnTo.length === 0) {
        return null;
    }

    if (hasInvalidCharacters(returnTo)) {
        return reject("contains invalid characters");
    }
    if (hasMalformedPathOrFragment(returnTo)) {
        return reject("malformed path or fragment");
    }
    if (returnTo.startsWith("/")) {
        return returnTo.startsWith("//") ? reject("protocol-relative URL") : returnTo;
    }
    return validateAbsoluteReturnTo(returnTo, allowlist, isTestEnvironment);
};
