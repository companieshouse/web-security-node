import { UserProfileKeys } from "@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys";
import { IUserProfile } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import { RequestScopeAndPermissions } from "./RequestScopeAndPermissions";
import {logger, LOG_MESSAGE_APP_NAME} from "./createLogger";

// ********
//
// return TRUE if
//
//   (1) any key in requestScopeAndPermissions.tokenPermissions object is
//       missing from userProfile.tokenPermissions object, OR
//   (2) a value of a key in requestScopeAndPermissions.tokenPermissions object is not
//       in the corresponding value of the same
//       key in userProfile.tokenPermissions
//
// note for (2) above, we would need to map values "create,update,etc" => "create", "update",
//  "etc" to get individual values
//
// ******
export function additionalScopeIsRequired(
    requestScopeAndPermissions: RequestScopeAndPermissions | undefined | null,
    userProfile: IUserProfile,
    userId = "UNKNOWN"  /* tslint:disable-line */
): boolean {

    if (!requestScopeAndPermissions) {
        logger.info(`${LOG_MESSAGE_APP_NAME} userId=${userId}, user has not specified any scopes`);
        return false;
    }

    if (!userProfile.hasOwnProperty(UserProfileKeys.TokenPermissions)) {
        logger.info(`${LOG_MESSAGE_APP_NAME} userId=${userId}, UserProfile missing Token Permissions property`);
        return true;
    }

    const userProfileTokenPermissions = userProfile[UserProfileKeys.TokenPermissions];

    // belt and braces
    if (userProfileTokenPermissions == null) {
        logger.info(`${LOG_MESSAGE_APP_NAME} userId=${userId}, UserProfile Token Permissions property has null value`);
        return true;
    }

    // check each requested key is in the user profile
    /* tslint:disable-next-line */
    for (const key in requestScopeAndPermissions.tokenPermissions) {

        logger.debug(`${LOG_MESSAGE_APP_NAME} userId=${userId} key=${key}, checking UserProfile for token permission key`);

        if (!userProfileTokenPermissions.hasOwnProperty(key)) {
            logger.debug(`${LOG_MESSAGE_APP_NAME} userId=${userId} key=${key}, token permission key is missing in userProfile, so since we request this permission we will need to add it`);
            return true;
        }

        const requestValue = requestScopeAndPermissions.tokenPermissions[key];
        const userProfileValue = userProfileTokenPermissions[key];

        // split, sort, and join the values to compare them irrespective of order
        const normaliseCommaSeparatedString = (value: string): string => {
            return value
                .split(",")                     // Split the string by commas
                .map(item => item.trim())       // Trim whitespace from each item
                .filter(item => item !== "")    // Remove any empty strings
                .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })) // Sorts the array alphabetically
                .join(",");                     // Join the array back into a string
        };

        const requestArray = normaliseCommaSeparatedString(requestValue);
        const userProfileArray = normaliseCommaSeparatedString(userProfileValue);

        if ( ! userProfileArray.includes(requestArray)) {
            logger.debug(`${LOG_MESSAGE_APP_NAME} userId=${userId} key=${key}, user profile does not have all the permissions for the requested token permission key`);
            return true;
        }
    }

    logger.debug(`${LOG_MESSAGE_APP_NAME} userId=${userId}, user profile HAS all the permissions for the requested token permission keys`);
    return false;
}
