import '@companieshouse/node-session-handler';
import { RequestHandler } from 'express';
export * from './csrf-protection';
export * from './scopes-permissions';
export interface AuthOptions {
    returnUrl: string;
    chsWebUrl: string;
    companyNumber?: string;
    acspNumber?: string;
    disableSaveCompanyCheckbox?: boolean;
}
export declare const authMiddleware: (options: AuthOptions) => RequestHandler;
