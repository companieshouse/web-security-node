import { assert } from "chai";
import { Response } from "express";
import sinon from "sinon";
import { AuthOptions } from "../../src";
import { acspProfileCreateAuthMiddleware } from "../../src/scopes-permissions";
import {
    generateRequest,
    generateResponse
} from "../mockGeneration";

describe("Test tokenPermissions conditionals in acspProfileCreateAuthMiddleware wrapper", () => {

    const mockReturnUrlWithScope = "accounts/signin?return_to=origin&additional_scope=https://identity.company-information.service.gov.uk/acsp-profile.create";

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

    it("When there is no session and acspProfileCreate, the middleware should not call next and should trigger redirect with additional scope", () => {

        const mockRequest = generateRequest();

        acspProfileCreateAuthMiddleware(opts)(mockRequest, mockResponse, mockNext);
        assert(redirectStub.calledOnceWith(mockReturnUrlWithScope));
        assert(mockNext.notCalled);
    });

});
