import { IUserProfile } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces';
import { RequestScopeAndPermissions } from '../';
export declare function additionalScopeIsRequired(requestScopeAndPermissions: RequestScopeAndPermissions | undefined | null, userProfile: IUserProfile): boolean;
