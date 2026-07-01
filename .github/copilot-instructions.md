# Copilot Instructions — web-security-node

This is a **published Node.js library** (`@companieshouse/web-security-node`) providing security middleware for Companies House Express applications. It is not a web service — it has no server, routes, or views of its own. The `dist/` and `components/` directories are the published artefacts.

## Commands

```bash
npm test                        # Run all tests (Mocha + nyc coverage)
npm test -- --grep "pattern"    # Run a single test or describe block
npm run build                   # Compile TypeScript to dist/
npm run lint                    # ESLint across src/ and test/
npm run lint:fix                # Auto-fix lint issues
```

Tests run via `ts-node` directly against `test/**/*.test.ts` — no build step needed before testing.

## Architecture

The library exposes three distinct concerns, each in its own directory under `src/`:

### 1. `src/index.ts` — General authentication (`authMiddleware`)
Used when a consuming service only needs the user to be signed in (with optional company-level authorisation). Redirects to `{chsWebUrl}/signin?return_to={returnUrl}` when unauthenticated. Also detects session hijacking via a SHA1 signature of `User-Agent + IP + COOKIE_SECRET` stored in `SessionKey.ClientSig`.

### 2. `src/scopes-permissions/` — OAuth scope-gated middlewares
Used when a consuming service needs a specific OAuth scope/token permission. Three concrete middlewares exist:
- `acspProfileCreateAuthMiddleware` — requires `acsp_profile: create` permission
- `acspManageUsersAuthMiddleware` — requires `acsp_members: read` + ACSP number match
- `userOneLoginDirectAuthMiddleware` — requires `one_login: read` permission

All three delegate to `authMiddlewareHelper` in `src/private-helpers/`, passing an `AuthOptions` object and a `RequestScopeAndPermissions` object. If a new scope-gated middleware is needed, add it here following the same pattern.

### 3. `src/csrf-protection/` — CSRF middleware (`CsrfProtectionMiddleware`)
Implements the Synchronisation Token Pattern. Stores a UUID token in `SessionKey.CsrfToken` in the CHS Redis session, exposes it via `res.locals.csrfToken` for Nunjucks templates, and validates it on mutable requests (`POST`, `PUT`, `DELETE`, `PATCH`). Requires `SessionMiddleware` to run before it in the Express chain.

### `src/private-helpers/` — Internal implementation
All code here is **not exported** and must not appear in `src/index.ts` or feature `index.ts` barrel files. Key files:
- `authMiddlewareHelper.ts` — core auth logic shared by all auth middlewares
- `additionalScopeIsRequired.ts` — compares `tokenPermissions` in the session's `UserProfile` against what the middleware requires
- `RequestScopeAndPermissions.ts` — the interface tying scope URL to required token permissions

### `components/` — Nunjucks macros (published alongside `dist/`)
- `csrf-token-input/macro.njk` — renders the hidden `_csrf` form field
- `csrf-error/macro.njk` — renders the CSRF error page fragment

## Key conventions

**Public API rule:** Every feature directory has an `index.ts` barrel. Only add to a barrel if the export is intended for library consumers. Internal helpers go in `src/private-helpers/` and are imported by path, never via a barrel.

**Test helpers:** `test/mockGeneration.ts` provides `generateRequest`, `generateResponse`, `generateSignInInfo`, and variants. Use these rather than reimplementing session/request mocks in individual test files.

**Test framework:** Mocha + Chai (`assert`/`expect`) + Sinon stubs + `ts-mockito` for class mocking. There is no Jest in this repo — do not use Jest syntax. Note: CH Node.js standards specify Jest as the standard test framework; this repo pre-dates that and has not been migrated. This is worth addressing in a future piece of work.

**Token permission matching:** `additionalScopeIsRequired` normalises comma-separated permission strings (sorts alphabetically, trims whitespace) before comparing. Keep this in mind when writing tests with token permission values like `"create,update"` vs `"update,create"`.

**`@ts-ignore` usage:** The codebase has a few deliberate `// @ts-ignore` comments on session data writes (e.g. setting `SessionKey.ClientSig`). These are intentional — the session handler types don't expose direct data writes, so direct property assignment is used.

**No CSRF token in `multipart/form-data`:** The CSRF token must be sent as the `x-csrf-token` header for multipart requests since the body parser won't populate `req.body._csrf`.
