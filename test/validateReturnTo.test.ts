import { expect } from "chai";
import { validateReturnTo } from "../src";
import sinon from "sinon";
import { logger } from "../src/private-helpers/createLogger";

describe("validateReturnTo", () => {
    let errorStub: sinon.SinonStub;

    beforeEach(() => {
        errorStub = sinon.stub(logger, "error");
    });

    afterEach(() => {
        sinon.restore();
    });

    it("returns a relative path unchanged", () => {
        expect(validateReturnTo("/dashboard")).to.equal("/dashboard");
    });

    it("returns null for missing or empty input", () => {
        expect(validateReturnTo(null)).to.equal(null);
        expect(validateReturnTo(undefined)).to.equal(null);
        expect(validateReturnTo("")).to.equal(null);
    });

    it("rejects a protocol-relative URL", () => {
        expect(validateReturnTo("//evil.example.com")).to.equal(null);
    });

    it("rejects a path containing a backslash", () => {
        expect(validateReturnTo("/\\evil.example.com")).to.equal(null);
    });

    it("rejects an untrusted host containing a trusted name", () => {
        expect(validateReturnTo("https://www.gov.uk.evil.example.com")).to.equal(null);
    });

    it("returns a trusted HTTPS URL unchanged", () => {
        const url = "https://www.gov.uk/search?query=company";
        expect(validateReturnTo(url)).to.equal(url);
    });

    it("accepts a chdev.org subdomain", () => {
        const url = "https://service.chdev.org/path";
        expect(validateReturnTo(url)).to.equal(url);
    });

    it("uses a custom allowlist when one is supplied", () => {
        const url = "https://portal.example.org/path";
        expect(validateReturnTo(url, [".example.org"])).to.equal(url);
        expect(validateReturnTo("https://www.gov.uk", [".example.org"])).to.equal(null);
    });

    it("compares hostnames without changing the original URL", () => {
        const url = "https://WWW.GOV.UK/Path";
        expect(validateReturnTo(url)).to.equal(url);
    });

    it("rejects HTTP and malformed URLs", () => {
        expect(validateReturnTo("http://www.gov.uk")).to.equal(null);
        expect(validateReturnTo("https://[broken")).to.equal(null);
    });

    it("rejects URLs containing user information", () => {
        expect(validateReturnTo("https://user@www.gov.uk/path")).to.equal(null);
    });

    it("rejects control characters in a path", () => {
        expect(validateReturnTo("/dash\nboard")).to.equal(null);
    });

    it("rejects every raw C0, DEL and C1 control character", () => {
        for (let code = 0; code <= 0x9f; code++) {
            if (code <= 0x1f || code >= 0x7f) {
                const character = String.fromCodePoint(code);
                expect(validateReturnTo(`/a${character}b`), `relative path, code ${code}`).to.equal(null);
                expect(validateReturnTo(`https://www.gov.uk/a${character}b`), `HTTPS URL, code ${code}`).to.equal(null);
            }
        }
    });

    it("does not trust chs.local by default, even if it is allowlisted", () => {
        const url = "https://chs.local/dashboard";
        expect(validateReturnTo(url)).to.equal(null);
        expect(validateReturnTo(url, ["chs.local"])).to.equal(null);
    });

    it("accepts chs.local when the test-environment flag is enabled", () => {
        const url = "https://chs.local/dashboard";
        expect(validateReturnTo(url, undefined, true)).to.equal(url);
    });

    it("does not allow a different local host when the test flag is enabled", () => {
        expect(validateReturnTo("https://other.local", undefined, true)).to.equal(null);
    });

    it("rejects percent-encoded hostnames", () => {
        expect(validateReturnTo("https://%77ww.gov.uk")).to.equal(null);
    });

    it("rejects hostnames with empty labels", () => {
        expect(validateReturnTo("https://www..gov.uk")).to.equal(null);
    });

    it("rejects an empty user-info prefix", () => {
        expect(validateReturnTo("https://@www.gov.uk")).to.equal(null);
    });

    it("rejects the trailing-dot form of chs.local", () => {
        const url = "https://chs.local.";
        expect(validateReturnTo(url, ["chs.local."])).to.equal(null);
        expect(validateReturnTo(url, ["chs.local."], true)).to.equal(null);
    });

    it("enforces the hostname label length limit", () => {
        const validUrl = `https://${"a".repeat(63)}.gov.uk`;
        const invalidUrl = `https://${"a".repeat(64)}.gov.uk`;

        expect(validateReturnTo(validUrl)).to.equal(validUrl);
        expect(validateReturnTo(invalidUrl)).to.equal(null);
    });

    it("enforces the total hostname length limit", () => {
        const label = "a".repeat(63);
        const prefix = [label, label, label].join(".");
        const validHost = `${prefix}.${"a".repeat(54)}.gov.uk`;
        const invalidHost = `${prefix}.${"a".repeat(55)}.gov.uk`;
        const validUrl = `https://${validHost}`;

        expect(validHost.length).to.equal(253);
        expect(invalidHost.length).to.equal(254);
        expect(validateReturnTo(validUrl)).to.equal(validUrl);
        expect(validateReturnTo(`https://${invalidHost}`)).to.equal(null);
    });

    it("rejects malformed percent escapes", () => {
        for (const url of ["https://www.gov.uk/%ZZ", "/bad%"] ) {
            expect(validateReturnTo(url), url).to.equal(null);
        }
    });

    it("rejects unescaped whitespace", () => {
        for (const url of ["https://www.gov.uk/a b", "/dash board", "/dash\u00a0board"]) {
            expect(validateReturnTo(url), url).to.equal(null);
        }
    });

    it("rejects forbidden raw URI characters and repeated fragment delimiters", () => {
        for (const url of ["https://www.gov.uk/a|b", "/a|b", "/a[1]", "/dashboard#a#b"]) {
            expect(validateReturnTo(url), url).to.equal(null);
        }
    });

    it("preserves valid encoding and valid query characters", () => {
        for (const url of ["https://www.gov.uk/a%20b", "/a%20b", "https://www.gov.uk/café", "/search?q=[1]"]) {
            expect(validateReturnTo(url), url).to.equal(url);
        }
    });

    it("logs a rejected URL as an error", () => {
        const url = "https://evil.example.com";

        expect(validateReturnTo(url)).to.equal(null);
        expect(errorStub.calledOnce).to.equal(true);
        expect(errorStub.firstCall.args[0]).to.include(url);
    });

    for (const url of [
        "//evil.example.com",
        "http://www.gov.uk",
        "/\\evil.example.com",
        "/dashboard#a#b",
        "https://user@www.gov.uk",
        "https://www..gov.uk",
        "https://chs.local"
    ]) {
        it(`logs exactly one error when rejecting ${url}`, () => {
            expect(validateReturnTo(url)).to.equal(null);
            expect(errorStub.calledOnce).to.equal(true);
        });
    }

    it("does not log the path or query of a rejected URL", () => {
        validateReturnTo("https://evil.example.com/account?token=secret");

        expect(errorStub.firstCall.args[0]).to.include("https://evil.example.com");
        expect(errorStub.firstCall.args[0]).to.not.include("token=secret");
    });

    it("does not log accepted or missing values", () => {
        validateReturnTo("/dashboard");
        validateReturnTo("https://www.gov.uk");
        validateReturnTo(null);
        validateReturnTo("");

        expect(errorStub.called).to.equal(false);
    });
});
