import { assert } from "chai";
import { Response } from "express";
import sinon from "sinon";
import { Session } from "@companieshouse/node-session-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { UserProfileKeys } from "@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys";
import { ISignInInfo } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import { instance, mock, when } from "ts-mockito";
import { AuthOptions } from "../../src";
import { acspManageUsersAuthMiddleware } from "../../src/scopes-permissions";
import {
    generateRequest,
    generateResponse
} from "../mockGeneration";
import { InvalidAcspNumberError } from "../../src/scopes-permissions";

describe("Test acspManageUsersAuthMiddleware options", () => {

    const mockReturnUrlWithScope = "accounts/signin?return_to=origin&additional_scope=https://api.company-information.service.gov.uk/authorized-corporate-service-provider/abc123";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            acspNumber: "abc123",
        };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("When there is no session and acspManageUsersAuthMiddleware, the middleware should not call next and should trigger redirect with additional scope", () => {
        const mockRequest = generateRequest();
        acspManageUsersAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrlWithScope));
        assert(mockNext.notCalled);
    });

    it(`When ACSP number is blank, throw error`, () => {
        const mockRequest = generateRequest();
        opts.acspNumber = "";
        assert.throws(()=> acspManageUsersAuthMiddleware(opts)(mockRequest, mockResponse, mockNext), InvalidAcspNumberError);
        assert(redirectStub.notCalled);
        assert(mockNext.notCalled);
    });

    it(`When ACSP number is 'undefined', throw error`, () => {
        const mockRequest = generateRequest();
        opts.acspNumber = "undefined";
        assert.throws(() => acspManageUsersAuthMiddleware(opts)(mockRequest, mockResponse, mockNext), InvalidAcspNumberError);
        assert(redirectStub.notCalled);
        assert(mockNext.notCalled);
    });

    it(`Should call redirect when user does not have correct permissions`, () => {
        const mockRequest = generateRequest();
        acspManageUsersAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrlWithScope));
        assert(mockNext.notCalled);
    });

    it(`Should call next when user has correct permissions`, () => {
        const sessionMock = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(sessionMock), data: {} });
        const signInInfo = {
            signed_in: 1,
            user_profile: {
                id: "mockUserId",
                [UserProfileKeys.TokenPermissions]: {
                    "acsp_members": "read",
                    "acsp_number": "abc123"
                }
            }
        };
        when(sessionMock.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);
        acspManageUsersAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnceWithExactly());
        assert(redirectStub.notCalled);
    });
});
