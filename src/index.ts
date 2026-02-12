import "@companieshouse/node-session-handler";
import {NextFunction, Request, RequestHandler, Response} from "express";
import {authMiddlewareHelper} from "./private-helpers/authMiddlewareHelper";

export * from "./csrf-protection";
export * from "./scopes-permissions";

export interface AuthOptions {
  returnUrl: string
  chsWebUrl: string
  companyNumber?: string
  acspNumber?:string
  disableSaveCompanyCheckbox?: boolean
}

export const authMiddleware = (options: AuthOptions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
) => {

    return authMiddlewareHelper(options)(req, res, next);
};
