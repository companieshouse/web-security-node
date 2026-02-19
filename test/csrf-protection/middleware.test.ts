import { Response } from "express";
import sinon from "sinon";
import { assert } from "chai";
import { instance, mock, when } from "ts-mockito";
import { Session, SessionStore } from "@companieshouse/node-session-handler";
import { SessionKey } from "@companieshouse/node-session-handler/lib/session/keys/SessionKey";
import { Cookie } from "@companieshouse/node-session-handler/lib/session/model/Cookie";

import {
    generateRequest,
    generateResponse,
} from "../mockGeneration";

import {
    CsrfError,
    CsrfOptions,
    SessionUnsetError,
    CsrfTokensMismatchError,
    MissingCsrfSessionToken,
    CsrfProtectionMiddleware,
} from "../../src/csrf-protection";

describe("csrf-protection/middleware", () => {

    describe("CSRF Middleware enabled", () => {
        let redirectStub: sinon.SinonStub;
        let opts: CsrfOptions;
        let mockResponse: Response;
        let mockNext: sinon.SinonStub;
        let sessionStore: SessionStore;
        let cookie: Cookie;
        const newCsrfToken = "497a33e7-47be-4508-bf9d-0dd087fcf53b";

        beforeEach(() => {
            sinon.restore();
            sinon.reset();
            redirectStub = sinon.stub();
            sessionStore = mock(SessionStore);
            opts = {
                enabled: true,
                // @ts-ignore
                sessionStore: sinon.mock(sessionStore),
                csrfTokenFactory: () => newCsrfToken
            };
            mockResponse = generateResponse();
            mockResponse.redirect = redirectStub;
            mockNext = sinon.stub();
            cookie = Cookie.createNew("c-is-for-cookie-which-is-good-enough-for-me");
        });

        afterEach(() => {
            sinon.restore();
        });

        it("calls next with no args when csrf token in request headers matches csrf token in session", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), csrfToken, undefined, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly());
        });

        it("calls next with no args when csrf token in request body matches csrf token in session", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, csrfToken, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly());
        });

        it("calls next with error when csrf token in header does not match", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), "58ff006d-8c3c-4590-aa3c-c7c594fb422e", undefined, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfTokensMismatchError && error.message === "Invalid CSRF token.")));
        });

        it("calls next with error when csrf token in body does not match", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, "58ff006d-8c3c-4590-aa3c-c7c594fb422e", "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfTokensMismatchError && error.message === "Invalid CSRF token.")));
        });

        it("calls next with no args when not post", () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock));

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWith());
        });

        it("prioritises body over header", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), "e1f1ba25-e129-490c-9675-47805b878dcd", csrfToken, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly());
        });

        it("Generates csrf token and stores in session when not found in session for non-mutable request", async () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock));
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
            // @ts-ignore
            opts.sessionStore.expects("store").once().withArgs(
                sinon.match.defined,
                sinon.match({
                    [SessionKey.Expires]: 1223123454,
                    [SessionKey.CsrfToken]: newCsrfToken
                })
            );

            CsrfProtectionMiddleware({
                ...(opts),
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext);

            sinon.verify();

        });

        it("does not generate csrf token or store in session when not found in session for non-mutable request and not instructed to", async () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock));
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: false,
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext);

            sinon.verify();

            assert(mockNext.calledOnceWith());
        });

        it("raises error when post and no session set", async () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(undefined, csrfToken, undefined, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });


            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: false,
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext);

            sinon.verify();

            const nextCall = mockNext.getCall(0);

            assert(nextCall.args[0] instanceof SessionUnsetError);
            assert(nextCall.args[0].message == "Session not set.");
        });

        it("calls next when get and no session set", async () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(undefined);
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });

            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: false,
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext);

            sinon.verify();

            assert(mockNext.calledOnceWith());
        });

        it("sets the csrf token as part of locals", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), "e1f1ba25-e129-490c-9675-47805b878dcd", csrfToken, "POST");
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert.equal(mockResponse.locals.csrfToken, csrfToken);
        });

        it("throws error when csrf token not found in session for mutable request", async () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock));
            mockRequest.method = "POST";
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext);

            sinon.verify();

            assert(mockNext.calledWithMatch(sinon.match((error) =>
                error instanceof MissingCsrfSessionToken && error.message === "Session does not include CSRF token.")));

        });

        it("can identify Csrf error", () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock));
            mockRequest.method = "POST";
            mockRequest.cookies = {
                "_SID": cookie.value
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(undefined);
            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                sessionStore: sessionStore
            })(mockRequest, mockResponse, mockNext);

            sinon.verify();

            assert(mockNext.calledWithMatch(sinon.match((error) => error instanceof CsrfError)));
        });

        /*
        The following tests use a separate stub for next function as sinon was
        not working as expected - it was causing false positives therefore using
        a custom stub which collects the calls manually and performs assertions
        on them
        */

        it("does nothing if there is a session and no cookie in the request", () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock));
            mockRequest.cookies = {};

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });

            // Array of calls to next
            let nextCalls: any[] = [];

            // stubbed next which adds the call args to next to the nextCalls array
            const nextStub = (err?: any) => {
                console.warn(`Called with ${err}`);

                nextCalls = [
                    ...nextCalls,
                    err
                ];
            };

            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: true,
                sessionStore: sessionStore
            })(mockRequest, mockResponse, nextStub);

            sinon.verify();

            assert(nextCalls.length === 1, "next has been called once");
            assert(typeof nextCalls[0] === "undefined", "next has been called with no args");
        });

        it("does not error when POST with no session cookie and errorWhenNoSessionCookie is false", () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
            mockRequest.cookies = {};

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });

            // Array of calls to next
            let nextCalls: any[] = [];

            // stubbed next which adds the call args to next to the nextCalls array
            const nextStub = (err?: any) => {
                console.warn(`Called with ${err}`);

                nextCalls = [
                    ...nextCalls,
                    err
                ];
            };

            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: true,
                sessionStore: sessionStore,
                errorWhenNoSessionCookie: false
            })(mockRequest, mockResponse, nextStub);

            assert(nextCalls.length === 1, "next has been called once");
            assert(typeof nextCalls[0] === "undefined", "next has been called with no args");

            sinon.verify();
        });

        it("errors when POST with no session cookue and errorWhenNoSessionCookie is true", () => {
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");
            mockRequest.cookies = {};

            when(sessionMock.data).thenReturn({
                [SessionKey.Expires]: 1223123454
            });

            // Array of calls to next
            let nextCalls: any[] = [];

            // stubbed next which adds the call args to next to the nextCalls array
            const nextStub = (err?: any) => {
                console.warn(`Called with ${err}`);

                nextCalls = [
                    ...nextCalls,
                    err
                ];
            };

            // @ts-ignore
            opts.sessionStore.expects("store").never();

            CsrfProtectionMiddleware({
                ...(opts),
                createWhenCsrfTokenAbsent: true,
                sessionStore: sessionStore,
                errorWhenNoSessionCookie: true
            })(mockRequest, mockResponse, nextStub);

            assert(nextCalls.length === 1, "next has been called once");
            assert(nextCalls[0] instanceof SessionUnsetError, "next Called with CsrfError");

            sinon.verify();
        });


        describe("custom header", () => {
            it("can locate csrf token in custom header", () => {
                const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
                const customHeaderName = "custom-csrf-token-header";

                const sessionMock = mock(Session);
                const mockRequest = generateRequest(instance(sessionMock), "blah", undefined);

                mockRequest.headers[customHeaderName] = csrfToken;
                mockRequest.method = "POST";
                mockRequest.cookies = {
                    "_SID": cookie.value
                };

                when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

                CsrfProtectionMiddleware({
                    enabled: true,
                    headerName: customHeaderName,
                    sessionStore: {} as SessionStore,
                    csrfTokenFactory: () => newCsrfToken
                })(mockRequest, mockResponse, mockNext);

                assert(mockNext.calledOnceWithExactly());
            });
        });

        describe("custom field", () => {

            it("can locate csrf token in field in body", () => {
                const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
                const customParameterName = "custom-csrf-token-parameter";

                const sessionMock = mock(Session);
                const mockRequest = generateRequest(instance(sessionMock), undefined, "undefined");

                mockRequest.method = "POST";
                mockRequest.body = {
                    [customParameterName]: csrfToken
                };
                mockRequest.cookies = {
                    "_SID": cookie.value
                };

                when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

                CsrfProtectionMiddleware({
                    enabled: true,
                    parameterName: customParameterName,
                    sessionStore: {} as SessionStore,
                    csrfTokenFactory: () => newCsrfToken
                })(mockRequest, mockResponse, mockNext);

                assert(mockNext.calledOnceWithExactly());
            });
        });
    });

    describe("CSRF Middleware disabled", () => {

        let redirectStub: sinon.SinonStub;
        let opts: CsrfOptions;
        let mockResponse: Response;
        let mockNext: sinon.SinonStub;

        beforeEach(() => {
            redirectStub = sinon.stub();
            opts = {
                enabled: false,
                sessionStore: {} as SessionStore,
                csrfTokenFactory: () => "newCsrfToken"
            };
            mockResponse = generateResponse();
            mockResponse.redirect = redirectStub;
            mockNext = sinon.stub();
        });

        it("Calls next", () => {
            const csrfToken = "0fb9a779-2262-410f-a075-7f1359f142b6";
            const sessionMock = mock(Session);
            const mockRequest = generateRequest(instance(sessionMock), undefined, undefined, "POST");

            mockRequest.cookies = {
                "_SID": "123234344545"
            };

            when(sessionMock.get<string>(SessionKey.CsrfToken)).thenReturn(csrfToken);

            CsrfProtectionMiddleware(opts)(mockRequest, mockResponse, mockNext);

            assert(mockNext.calledOnceWithExactly());
        });
    });
});
