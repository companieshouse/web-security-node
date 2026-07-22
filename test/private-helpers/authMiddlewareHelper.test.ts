import { Request, Response } from "express";
import crypto from "crypto";
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

describe("IP extraction from X-Forwarded-For", () => {

    const mockUserId = "sA==";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    // The signature is SHA1(userAgent + ip + COOKIE_SECRET).
    // In tests: user-agent header is absent (→ "" per the null-coalescing fix matching Java),
    // COOKIE_SECRET env var is not set (→ undefined in template literal → "undefined").
    // So the hash input is `${ip}undefined`.
    const signatureForIp = (ip: string): string =>
        crypto.createHash("sha1").update(`${ip}undefined`, "utf8").digest("hex");

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = { returnUrl: "origin", chsWebUrl: "accounts" };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("uses rightmost public IP when X-Forwarded-For contains a spoofed leftmost entry", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "5.5.5.5, 1.2.3.4, 10.0.0.1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("uses the single IP when X-Forwarded-For contains only one entry", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "1.2.3.4";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("falls back to leftmost IP when all X-Forwarded-For entries are private", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("10.0.0.1") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "10.0.0.1, 192.168.1.1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("does not use the leftmost IP when a rightmost public IP is present (confirms no regression to old behaviour)", () => {
        const authedSession = mock(Session);
        // Store a signature computed from the leftmost (spoofed) IP — this should NOT match
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("5.5.5.5") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "5.5.5.5, 1.2.3.4, 10.0.0.1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnce);
        assert(mockNext.notCalled);
    });

    it("treats 172.16–31.x.x addresses as private", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "1.2.3.4, 172.16.0.1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("treats ::1 (IPv6 loopback) as private and falls back to leftmost", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("10.0.0.1") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "10.0.0.1, ::1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("treats IPv4-mapped IPv6 private addresses (::ffff:10.x.x.x) as private", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "1.2.3.4, ::ffff:10.0.0.1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("handles X-Forwarded-For supplied as an array (multiple header instances)", () => {
        const authedSession = mock(Session);
        // Express joins multiple instances of the same header into an array.
        // Array.toString() joins with commas, producing the same format as a single header.
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string[]>)["x-forwarded-for"] = ["5.5.5.5", "1.2.3.4, 10.0.0.1"] as any;

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("ignores empty/whitespace-only entries in X-Forwarded-For", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = " , 1.2.3.4, 10.0.0.1";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("falls back to socket.remoteAddress when X-Forwarded-For contains only whitespace/empty entries", () => {
        const authedSession = mock(Session);
        // All entries are stripped by the empty-string filter; falls back to socket.remoteAddress ?? ""
        // In tests there is no socket, so the signature is sha1("undefined") — the default ClientSig.
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data: {} });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "  ,  ,  ";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("uses X-REAL-IP when X-Forwarded-For is absent (matches web-security-java fallback)", () => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({
            ...instance(authedSession),
            data: { [SessionKey.ClientSig]: signatureForIp("1.2.3.4") }
        });
        (mockRequest.headers as Record<string, string>)["x-real-ip"] = "1.2.3.4";

        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

});

describe("Dual-signature migration", () => {

    const mockUserId = "sA==";

    let redirectStub: sinon.SinonStub;
    let opts: AuthOptions;
    let mockResponse: Response;
    let mockNext: sinon.SinonStub;

    // V2 = SHA1(userAgent + COOKIE_SECRET), no IP. Here both are unset, so the input is "undefined".
    const v2Signature = (): string =>
        crypto.createHash("sha1").update("undefined", "utf8").digest("hex");

    // V1 = SHA1(userAgent + ip + COOKIE_SECRET); input here is `${ip}undefined`.
    const signatureForIp = (ip: string): string =>
        crypto.createHash("sha1").update(`${ip}undefined`, "utf8").digest("hex");

    // Builds a signed-in request seeded with the given session signature data.
    const buildSignedInRequest = (data: Record<string, string>): Request => {
        const authedSession = mock(Session);
        // @ts-ignore
        const mockRequest = generateRequest({ ...instance(authedSession), data });
        when(authedSession.get<ISignInInfo>(SessionKey.SignInInfo)).thenReturn(generateSignInInfo(mockUserId, 1));
        return mockRequest;
    };

    beforeEach(() => {
        redirectStub = sinon.stub();
        opts = { returnUrl: "origin", chsWebUrl: "accounts" };
        mockResponse = generateResponse();
        mockResponse.redirect = redirectStub;
        mockNext = sinon.stub();
    });

    it("validates against V2 first and calls next when the V2 signature matches", () => {
        const mockRequest = buildSignedInRequest({ [SessionKey.ClientSigV2]: v2Signature() });

        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("ignores IP changes when a matching V2 signature is present (fixes cross-service false hijack)", () => {
        const mockRequest = buildSignedInRequest({
            [SessionKey.ClientSig]: signatureForIp("9.9.9.9"),
            [SessionKey.ClientSigV2]: v2Signature()
        });
        (mockRequest.headers as Record<string, string>)["x-forwarded-for"] = "1.2.3.4";

        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
    });

    it("redirects to sign in when a V2 signature is present but does not match", () => {
        const mockRequest = buildSignedInRequest({ [SessionKey.ClientSigV2]: "does-not-match" });

        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnce);
        assert(mockNext.notCalled);
        // both signatures cleared on a possible hijack
        assert.isUndefined(mockRequest.session!.data[SessionKey.ClientSig]);
        assert.isUndefined(mockRequest.session!.data[SessionKey.ClientSigV2]);
    });

    it("falls back to legacy V1 validation and backfills V2 when only V1 is present", () => {
        const mockRequest = buildSignedInRequest({ [SessionKey.ClientSig]: signatureForIp("") });

        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
        assert.strictEqual(mockRequest.session!.data[SessionKey.ClientSigV2], v2Signature());
    });

    it("writes both V1 and V2 signatures on first sign-in when neither is present", () => {
        const mockRequest = buildSignedInRequest({ [SessionKey.ClientSig]: "", [SessionKey.ClientSigV2]: "" });

        authMiddlewareHelper(opts)(mockRequest, mockResponse, mockNext);
        assert(mockNext.calledOnce);
        assert(redirectStub.notCalled);
        assert.strictEqual(mockRequest.session!.data[SessionKey.ClientSig], signatureForIp(""));
        assert.strictEqual(mockRequest.session!.data[SessionKey.ClientSigV2], v2Signature());
    });

});
