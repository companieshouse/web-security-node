import '@companieshouse/node-session-handler';
import { RequestHandler } from 'express';
import { AuthOptions } from '..';
import { RequestScopeAndPermissions } from './RequestScopeAndPermissions';
export declare const authMiddlewareHelper: (options: AuthOptions, requestScopeAndPermissions?: RequestScopeAndPermissions) => RequestHandler;
