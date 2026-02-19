import { UserProfileKeys } from "@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys";
import { IUserProfile } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";

export interface RequestScopeAndPermissions {
    scope: string
    tokenPermissions: IUserProfile[UserProfileKeys.TokenPermissions] // { [permission: string]: string }
  }
