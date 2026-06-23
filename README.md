# web-security-node

Security for web applications in node

- [web-security-node](#web-security-node)
  - [Authorisation](#authorisation)
  - [Cross Site Request Forgery (CSRF) protection](#cross-site-request-forgery-csrf-protection)
    - [Installation instructions](#installation-instructions)
    - [API](#api)
      - [`CsrfOptions` interface](#csrfoptions-interface)
        - [Properties](#properties)
      - [`CsrfProtectionMiddleware` function](#csrfprotectionmiddleware-function)
        - [Parameters](#parameters)
      - [`defaultCsrfTokenFactory` function](#defaultcsrftokenfactory-function)
      - [Exceptions](#exceptions)
  - [Code Structure](#code-structure)

## Compatible Node versions

This package has been upgraded to be compatible with Node v24. Presently, it's backward compatible with v20 and v18 but compatibility is primarily required for v24 as all CH Node services are in the process of being upgraded to v24.

## Authorisation

With the introduction of Verification for certain business functions, the way `*-web` applications use authentication is now in two main categories - see [Integrating Verification into the Authentication Service scopes and permissions](https://companieshouse.atlassian.net/wiki/spaces/IDV/pages/4538695803/Integrating+Verification+into+the+Authentication+Service+scopes+and+permissions#oauth-web-(and-oauth-signin-java-library)) for background information.

- The application needs a specific OAUTH scope, in which case authentication needs to be done using one of the functions in the `src/scopes-permissions` directory. **OR**
- A user just needs to be logged in (or do a company login), in which case the `authMiddleware` function in `src/index.ts` is used

When a `*-web` applications is architected, it will be decided if authorisation needs a specific OAuth scope or not. If it does, if one is not present then a new function needs to be developed in the `src/scopes-permissions` directory.

## Cross Site Request Forgery (CSRF) protection

This library provides a Express middleware Request Handler which will protect
an application from Cross Site Request Forgery (CSRF) attacks. The middleware
works by looking for a token within the request which should match a token held
within the CHS session. The middleware will expect all requests from methods
which modify data (for example `POST`/`DELETE`/`PUT`) to include the CSRF
token. This implements a
[Synchronisation Token Pattern approach](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)

> [!IMPORTANT]
> If you are submitting requests which are of type `multipart/form-data` then
> you will will need to send the CSRF token as a header, by default: this is
> the header `x-csrf-token` but can be customised using the options.

> [!WARNING]
> Depending on how your application validates requests you may need to register
> the new attribute `_csrf` with your validation framework.
> `registered-email-address-web` uses the `joi` framework which required it
> [being registered in its schema](https://github.com/companieshouse/registered-email-address-web/blob/main/src/schemas/change_email_address_schema.ts).
> Take care when implementing that you understand what impact the new attribute
> will have on your handling of forms.

### Installation instructions

1. Install the library (if not already installed).

    ```sh
    npm i @companieshouse/web-security-node@^4.1.0
    ```

2. Define the options for the middleware and add the middleware to the
  application. Optionally, you can add the error handler too.

    ```typescript
    import { CsrfProtectionMiddleware } from " @companieshouse/web-security-node"
    import {
        SessionStore,
        SessionMiddleware,
        EnsureSessionCookiePresentMiddleware
    } from '@companieshouse/node-session-handler';
    import express from "express";
    import cookieParser from 'cookie-parser';
    import Redis from 'ioredis';


    const app = express();

    // apply other middlewares

    app.use(cookieParser());
    app.use(express.urlencoded({ extended: true }));
    const cookieName = '__SID'

    const cookieConfig = {
        cookieName,
        cookieSecret: config.COOKIE_SECRET,
        cookieDomain: config.COOKIE_DOMAIN,
        cookieTimeToLiveInSeconds: parseInt(config.DEFAULT_SESSION_EXPIRATION, 10)
    };
    const sessionStore = new SessionStore(new Redis(`redis://${config.CACHE_SERVER}`));
    // Important the session Middleware is required before this middleware since the
    // token is stored within the session
    app.use(SessionMiddleware(cookieConfig, sessionStore));
    const csrfMiddlewareOptions = {
        sessionStore,
        enabled: true,
        sessionCookieName: cookieName
    }
    app.use(createLoggerMiddleware(config.applicationNamespace));

    // Recommended to use the EnsureSessionCookiePresentMiddleware from
    // `node-session-handler` too - see subsequent note
    app.use(EnsureSessionCookiePresentMiddleware(cookieConfig))

    // It is important that CSRF Protection follows the Sesion and urlencoded
    // Middlewares, maybe put at end of the middleware chain (before
    // controllers)
    app.use(CsrfProtectionMiddleware(csrfMiddlewareOptions))
    app.use(helmet());

    // Add other middlewares and routers

    ```

    **Note** the addition of: `EnsureSessionCookiePresentMiddleware` ensures
    that there is a session cookie in the request before handling the CSRF
    token. This is important because the CSRF middleware cannot add the CSRF to
    the session without a session cookie. Without this step any mutable requests
    following an unauthenticated action will fail. If your application is only
    authenticated this may not be as applicable.

    <br>

    To exclude CsrfProtectionMiddleware from specific paths:

    for example the /limited-partnerships/healthcheck endpoint
    ```typescript
    const excludedPaths = /\/limited-partnerships\/((?!healthcheck).)*/;
    ```

    or, for the /limited-partnerships/healthcheck and /limited-partnerships/start end-points
    ```typescript
    const excludedPaths = /\/limited-partnerships\/((?!healthcheck|start).)*/;
    ```

    or, for the /register-an-overseas-entity/healthcheck endpoint (where the base URL changes based on the type of web journey)
    ```typescript
    const excludedPaths = /^\/(?!register-an-overseas-entity\/healthcheck).*/;
    ```

    then add it to the middleware call
    ```typescript
    app.use(excludedPaths, csrfProtectionMiddleware);
    ```

3. Amend the `Nunjucks` configuration to add the third-party templates from this library:

    ```typescript
    nunjucks
      .configure([
          "dist/views",
          "node_modules/govuk-frontend/",
          "node_modules/govuk-frontend/components/",
          "node_modules/@companies-house/"
      ], nunjucksConfig)
    ```

4. In each form which submits data (or modifies data) add the following macro call

    ```nunjucks
    {% from "web-security-node/components/csrf-token-input/macro.njk" import csrfTokenInput %}

    <form action="POST">
        {{
            csrfTokenInput({
                csrfToken: csrfToken
            })
        }}
        <!-- Other form items ommitted -->
    </form>
    ```

5. Create an CSRF error page template and add the following macro call (or
  amend an existing template)

    ```nunjucks
    {% from "web-security-node/components/csrf-error/macro.njk" import csrfError %}

    {{
      csrfError({})
    }}
    ```

6. Create an error handler for CSRF Errors, you could start with:

    ```typescript
    import { ErrorRequestHandler, NextFunction, Request, Response } from 'express'
    import {
        CsrfError
    } from '@companieshouse/web-security-node'

    // TODO: Enter the template name here instead of <TEMPLATE NAME>
    const csrfErrorTemplateName = "<TEMPLATE NAME>";

    const csrfErrorHandler = (err: CsrfError | Error, _: Request,
      res: Response, next: NextFunction) => {

      // handle non-CSRF Errors immediately
      if (!(err instanceof CsrfError)) {
        next(err);
      }

      return res.status(403).render(
        csrfErrorTemplateName, {
          // TODO: Complete this with any information required by your error
          // template, the CSRF Error component requires no information currently
        }
      )
    };
    ```

7. Add the error handler to your application before the default Error Handler
  (to prevent CSRF errors being handled as normal exceptions.)

### API

#### `CsrfOptions` interface

Provides configuration to the middleware.

##### Properties

- `enabled` (*boolean* **required**) - whether or not to apply CSRF protections
- `sessionStore` (*SessionStore* **required**) - a SessionStore instance to
  manage the CHS session
- `sessionCookieName` (*string*) - name of the cookie storing the signed
  Session ID
- `csrfTokenFactory` (*supplier of string*) - a callable when called will
  return a string to use as the session's CSRF token. Has signature:

    ```typescript
    () => string
    ```

    Defaults to a uuid supplier if not supplied.

- `createWhenCsrfTokenAbsent` (*boolean*) - whether to generate a new CSRF
  token if not present in the session. Only run on non-mutable requests (e.g.
  GET)
- `headerName` (*string*) - name of the header to check. Defaults to
  `X-CSRF-TOKEN`
- `parameterName` (*string*) - name of the parameter in the request body to
  check. Defaults to `_csrf`.
- `errorWhenNoSessionCookie` (*boolean*) - defines the behaviour when a mutable
  request is received without a session cookie. When true will raise an error
  when the request does not contain a Cookie with Session ID, when false will
  do nothing and call next handler without an error (assuming this will be
  handled separately). This likely will be handled in a different handler
  therefore should not expect there to be a CSRF token
  to validate the request against. Defaults to `false`.

#### `CsrfProtectionMiddleware` function

A Request Handler capable of being used as a express Middleware function. Its
responsibility is checking that all mutable requests include a CSRF token which
indicates that they originated from the same CHS session and not an CSRF
attempt. The middleware expects that all mutable requests contain a token which
matches a token stored within the CHS session. It will add `csrfToken` to
locals so that views can reference it as a variable.

##### Parameters

- `options` - (`CsrfOptions` **required**) - the configuration for the
  middleware is provided as an object which implements the interface
  `CsrfOptions`

#### `defaultCsrfTokenFactory` function

This function is the default CSRF issuing function, it essentially provides an
uuid.

#### Exceptions

**`CsrfError`** - Base class for all errors thrown by middleware

**`SessionUnsetError`** - Thrown when a mutable request is received and the
session has not been set on the request. Likely due to application
misconfiguration. Check that the session handler is placed **before** the CSRF
middleware.

**`CsrfTokensMismatchError`** - Thrown when the CSRF token is either missing
in the mutable request or does not match the CSRF token within the CHS session.

**`MissingCsrfSessionToken`** - Thrown when there is no CSRF token within the
session to match the request's Token against.

## Code Structure

For all parts of the API that this library provides, put the code in directories that have an `index.ts` file so that clients can import the code `from "@companieshouse/web-security-node"` .

For code private to this library, add these files in the `src/private-helpers` directory (these need to be imported within this project using the filename with path)
