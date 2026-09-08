import { Response } from "express";
import sinon from "sinon";
import { assert, expect } from "chai";
import { instance, mock, when } from "ts-mockito";
import { Session } from "@companieshouse/node-session-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { ISignInInfo } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import { UserProfileKeys } from "@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys";
import {
    COMPANY_UPGRADED_AUTH_VALID_UNTIL,
    hasValidUpgradedCompanyAuth,
    hasValidUpgradedCompanyAuthForCompany
} from "../src/private-helpers/authMiddlewareHelper";
import { IUserProfile } from "@companieshouse/node-session-handler/lib/session/model/SessionInterfaces";
import { authMiddleware, AuthOptions } from "../src";
import {
    generateRequest,
    generateResponse,
    generateSignInInfo,
    generateSignInInfoAuthedForCompany
} from "./mockGeneration";

describe("Authentication Middleware", () => {

    const mockReturnUrl = "accounts/signin?return_to=origin";
    const mockUserId = "sA==";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
        };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("When CHS Web Url is blank, throw error", () => {
        const mockRequest = generateRequest();
        opts.chsWebUrl = "";

        expect(() => authMiddleware(opts)(mockRequest, mockResponse, mockNext)).to.throw("Required Field CHS Web URL not set");
        assert(redirectStub.notCalled);
        assert(mockNext.notCalled);
    });

    it("When there is no session the middleware should not call next and should trigger redirect", () => {
        const mockRequest = generateRequest();

        authMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrl));
        assert(mockNext.notCalled);
    });

    it("When the user is not logged in the middleware should not call next and should trigger redirect", () => {
        const unAuthedSession = mock(Session);
        //@ts-ignore
        const mockRequest = generateRequest({ ...instance(unAuthedSession), data: {} });

        when(unAuthedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 0));
        authMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrl));
        assert(mockNext.notCalled);
    });

    it("When the user is logged in the middleware should call next", () => {
        const authedSession = mock(Session);
        //@ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
    });
});

describe("Authentication Middleware with company number", () => {

    const mockReturnUrl = "accounts/signin?return_to=origin&company_number=12345678";
    const mockUserId = "sA==";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678"
        };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("When the user is not authenticated for company the middleware should not call next and should trigger redirect", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrl));
        assert(mockNext.notCalled);
    });

    it("When the user is authenticated for company the middleware should call next", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
            .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678"));
        authMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("Should redirect with company_disable_add_checkbox=true when disableSaveCompanyCheckbox in AuthOptions is true", () => {
        const expectedAuthReturnUrl = "accounts/signin?return_to=origin&company_number=12345678&company_disable_add_checkbox=true";

        const authOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            disableSaveCompanyCheckbox: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddleware(authOptions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl));
        assert(mockNext.notCalled);
    });

    it("Should redirect without company_disable_add_checkbox query parm when disableSaveCompanyCheckbox is false", () => {
        const expectedAuthReturnUrl = "accounts/signin?return_to=origin&company_number=12345678";

        const authOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            disableSaveCompanyCheckbox: false
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddleware(authOptions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl));
        assert(mockNext.notCalled);
    });

    it("Should redirect with company_force_auth=true when companyForceAuth is true when the user is authenticated for company", () => {
        const expectedAuthReturnUrl = "accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true";

        const forceAuthOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            companyForceAuth: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo))
            .thenReturn(generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678"));
        authMiddleware(forceAuthOptions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl));
        assert(mockNext.notCalled);
    });

    it("Should redirect with company_force_auth=true when companyForceAuth is true when the user is not authenticated for company", () => {
        const expectedAuthReturnUrl = "accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true";

        const forceAuthOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            companyForceAuth: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddleware(forceAuthOptions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl));
        assert(mockNext.notCalled);
    });

    it("Should call next when companyForceAuth is true and upgraded company auth is still valid", () => {
        const futureTimestamp = Math.floor(Date.now() / 1000) + 600;
        const forceAuthOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            companyForceAuth: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        const signInInfo = generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678");
        signInInfo.user_profile![UserProfileKeys.TokenPermissions] = {
            "company_upgraded_auth_valid_until": String(futureTimestamp)
        };
        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);

        authMiddleware(forceAuthOptions)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("Should redirect when companyForceAuth is true and upgraded company auth has expired", () => {
        const pastTimestamp = Math.floor(Date.now() / 1000) - 600;
        const expectedAuthReturnUrl = "accounts/signin?return_to=origin&company_number=12345678&company_force_auth=true";
        const forceAuthOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            companyForceAuth: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        const signInInfo = generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678");
        signInInfo.user_profile![UserProfileKeys.TokenPermissions] = {
            "company_upgraded_auth_valid_until": String(pastTimestamp)
        };
        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);

        authMiddleware(forceAuthOptions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl));
        assert(mockNext.notCalled);
    });

    it("Should redirect when companyForceAuth is true and the valid upgraded company auth was obtained for a different company", () => {
        const futureTimestamp = Math.floor(Date.now() / 1000) + 600;
        const expectedAuthReturnUrl = "accounts/signin?return_to=origin&company_number=22222222&company_force_auth=true";
        const forceAuthOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "22222222",
            companyForceAuth: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        // upgraded auth was obtained for company 11111111, not the company being accessed
        const signInInfo = generateSignInInfoAuthedForCompany(mockUserId, 1, "11111111");
        signInInfo.user_profile![UserProfileKeys.TokenPermissions] = {
            [COMPANY_UPGRADED_AUTH_VALID_UNTIL]: String(futureTimestamp)
        };
        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);

        authMiddleware(forceAuthOptions)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(expectedAuthReturnUrl));
        assert(mockNext.notCalled);
    });

    it("Should call next when companyForceAuth is true and the session is authorised for the same company", () => {
        const futureTimestamp = Math.floor(Date.now() / 1000) + 600;
        const forceAuthOptions = {
            returnUrl: "origin",
            chsWebUrl: "accounts",
            companyNumber: "12345678",
            companyForceAuth: true
        };
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });

        const signInInfo = generateSignInInfoAuthedForCompany(mockUserId, 1, "12345678");
        signInInfo.user_profile![UserProfileKeys.TokenPermissions] = {
            [COMPANY_UPGRADED_AUTH_VALID_UNTIL]: String(futureTimestamp)
        };
        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(signInInfo);

        authMiddleware(forceAuthOptions)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

});

describe("hasValidUpgradedCompanyAuthForCompany", () => {

    const futureTimestamp = Math.floor(Date.now() / 1000) + 600;
    const pastTimestamp = Math.floor(Date.now() / 1000) - 600;

    const userProfileWith = (tokenPermissions: Record<string, string>): IUserProfile => ({
        id: "sA==",
        [UserProfileKeys.TokenPermissions]: tokenPermissions
    });

    it("returns true when the timestamp is valid and the session is authorised for the company", () => {
        const userProfile = userProfileWith({ [COMPANY_UPGRADED_AUTH_VALID_UNTIL]: String(futureTimestamp) });
        const signInInfo: ISignInInfo = { signed_in: 1, company_number: "12345678", user_profile: userProfile };
        assert(hasValidUpgradedCompanyAuthForCompany("12345678", signInInfo, userProfile) === true);
    });

    it("returns false when the timestamp is valid but the session is authorised for another company", () => {
        const userProfile = userProfileWith({ [COMPANY_UPGRADED_AUTH_VALID_UNTIL]: String(futureTimestamp) });
        const signInInfo: ISignInInfo = { signed_in: 1, company_number: "11111111", user_profile: userProfile };
        assert(hasValidUpgradedCompanyAuthForCompany("12345678", signInInfo, userProfile) === false);
    });

    it("returns false when the session is not authorised for any company", () => {
        const userProfile = userProfileWith({ [COMPANY_UPGRADED_AUTH_VALID_UNTIL]: String(futureTimestamp) });
        const signInInfo: ISignInInfo = { signed_in: 1, user_profile: userProfile };
        assert(hasValidUpgradedCompanyAuthForCompany("12345678", signInInfo, userProfile) === false);
    });

    it("returns false when the timestamp has expired even if the company matches", () => {
        const userProfile = userProfileWith({
            [COMPANY_UPGRADED_AUTH_VALID_UNTIL]: String(pastTimestamp)
        });
        const signInInfo: ISignInInfo = { signed_in: 1, company_number: "12345678", user_profile: userProfile };
        assert(hasValidUpgradedCompanyAuthForCompany("12345678", signInInfo, userProfile) === false);
    });

});

describe("hasValidUpgradedCompanyAuth", () => {

    it("returns true when company_upgraded_auth_valid_until is in the future", () => {
        const futureTimestamp = Math.floor(Date.now() / 1000) + 600;
        const userProfile: IUserProfile = {
            [UserProfileKeys.TokenPermissions]: {
                "company_upgraded_auth_valid_until": String(futureTimestamp)
            }
        };
        assert(hasValidUpgradedCompanyAuth(userProfile) === true);
    });

    it("returns false when company_upgraded_auth_valid_until is in the past", () => {
        const pastTimestamp = Math.floor(Date.now() / 1000) - 600;
        const userProfile: IUserProfile = {
            [UserProfileKeys.TokenPermissions]: {
                "company_upgraded_auth_valid_until": String(pastTimestamp)
            }
        };
        assert(hasValidUpgradedCompanyAuth(userProfile) === false);
    });

    it("returns false when company_upgraded_auth_valid_until is missing", () => {
        const userProfile: IUserProfile = {
            [UserProfileKeys.TokenPermissions]: {}
        };
        assert(hasValidUpgradedCompanyAuth(userProfile) === false);
    });

    it("returns false when token permissions are entirely absent", () => {
        const userProfile: IUserProfile = {};
        assert(hasValidUpgradedCompanyAuth(userProfile) === false);
    });

    it("returns false when company_upgraded_auth_valid_until is not a valid number", () => {
        const userProfile: IUserProfile = {
            [UserProfileKeys.TokenPermissions]: {
                "company_upgraded_auth_valid_until": "not-a-number"
            }
        };
        assert(hasValidUpgradedCompanyAuth(userProfile) === false);
    });

});



