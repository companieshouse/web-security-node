import { SessionStore } from '@companieshouse/node-session-handler';
import { RequestHandler } from 'express';
export declare const defaultCsrfTokenFactory: () => string;
export interface CsrfOptions {
    enabled: boolean;
    sessionStore: SessionStore;
    sessionCookieName?: string;
    csrfTokenFactory?: () => string;
    createWhenCsrfTokenAbsent?: boolean;
    headerName?: string;
    parameterName?: string;
    errorWhenNoSessionCookie?: boolean;
}
export declare const CsrfProtectionMiddleware: (csrfOptions: CsrfOptions) => RequestHandler;
