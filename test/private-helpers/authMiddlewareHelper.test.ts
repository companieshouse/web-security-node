import { Response } from "express";
import sinon from "sinon";
import { instance, mock, when } from "ts-mockito";
import { assert } from "chai";
import { Session} from "@companieshouse/node-session-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { ISignInInfo } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import { AuthOptions } from "../../src";
import { authMiddlewareHelper } from "../../src/private-helpers/authMiddlewareHelper";
import { RequestScopeAndPermissions } from "../../src/private-helpers/RequestScopeAndPermissions";

import {
    generateRequest,
    generateResponse,
    generateSignInInfo,
    generateSignInInfoWithTokenPermissions,
    generateSignInInfoAuthedForScope
} from "../mockGeneration";

/*
   All tests with just AuthOptions are in the index.ts
   This file has just has the additional tests for when we add RequestScopeAndPermissions option and
   it a generic test for ny of the functions within the scopes-permissions directory
*/

describe("Test tokenPermissions conditionals in authMiddleware", () => {

    const mockReturnUrlWithScope = "accounts/signin?return_to=origin&additional_scope=test_scope";
    const mockUserId = "sA==";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let testRequestScopeAndPermissions: RequestScopeAndPermissions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
        };
        testRequestScopeAndPermissions = {
            scope: "test_scope",
            tokenPermissions: {
                "test_permission": "create,update"
            }
        };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("When hijack flag is set, should trigger redirect to sign in page", () => {

        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: {
                [SessionKey.Hijacked]: "1"
            }
        });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts, testRequestScopeAndPermissions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnce);
        assert(mockNext.notCalled);
    });

    it("When there is no session and requestScopeAndPermissions, the middleware should not call next and should trigger redirect with additional scope", () => {

        const mockRequest = generateRequest();

        authMiddlewareHelper(opts, testRequestScopeAndPermissions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrlWithScope));
        assert(mockNext.notCalled);
    });

    it("When the user is not logged in the middleware and requestScopeAndPermissions should not call next and should trigger redirect with additional scope", () => {
        const unAuthedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(unAuthedSession), data: {} });
        const result = generateSignInInfoAuthedForScope(mockUserId, 0, "test_scope");

        when(unAuthedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(result);
        authMiddlewareHelper(opts, testRequestScopeAndPermissions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrlWithScope));
        assert(mockNext.notCalled);

    });

    it("When the user is signed in but does in UserProfile not have the privileges in testRequestScopeAndPermissions the middleware should not call next and should trigger redirect", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts, testRequestScopeAndPermissions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrlWithScope));
        assert(mockNext.notCalled);
    });

    it("When the user is signed in and does in UserProfile have the privileges in testRequestScopeAndPermissions the middleware should  call next", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfoWithTokenPermissions(mockUserId, 1));
        authMiddlewareHelper(opts, testRequestScopeAndPermissions)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
    });

    it("When the user is signed in bur client signature is not equal to computed signature, should trigger redirect to sign in page", () => {

        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: {
                [SessionKey.ClientSig]: "abc123"
            }
        });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts, testRequestScopeAndPermissions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnce);
        assert(mockNext.notCalled);
    });

});
