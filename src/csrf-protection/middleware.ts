import { Session, SessionStore } from '@companieshouse/node-session-handler'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { Cookie } from '@companieshouse/node-session-handler/lib/session/model/Cookie'
import { createLogger } from '@companieshouse/structured-logging-node'
import { NextFunction, Request, RequestHandler, Response } from 'express'
import expressAsyncHandler from 'express-async-handler'
import { v4 as uuidv4 } from 'uuid'
import {
    CsrfTokensMismatchError,
    MissingCsrfSessionToken,
    SessionUnsetError
} from './errors'

const APP_NAME = 'web-security-node'
const logger = createLogger(APP_NAME)

const DEFAULT_CSRF_TOKEN_HEADER = 'x-csrf-token'
const DEFAULT_CSRF_TOKEN_PARAMETER_NAME = '_csrf'
const MUTABLE_METHODS = ['POST', 'DELETE', 'PUT', 'PATCH']
const DEFAULT_CHS_SESSION_COOKIE_NAME = '_SID'

/**
 * The token factory which is used by default when not supplied in the
 * middleware configuration. Essentially generates a UUID.
 * @returns CSRF Token - i.e. a uuid
 */
export const defaultCsrfTokenFactory = () => uuidv4()

/**
 * Provides the options to the filtering middleware.
 */
export interface CsrfOptions {
    /**
     * Whether or not the filter should filter requests.
     */
    enabled: boolean

    /**
     * SessionStore for updating the CHS session
     */
    sessionStore: SessionStore

    /**
     * Name of the cookie storing the signed CHS session ID
     */
    sessionCookieName?: string,

    /**
     * Supplies a new CSRF token value
     * @returns a new unique CSRF token value
     */
    csrfTokenFactory?: () => string,

    /**
     * When true the filter will generate a new CSRF token upon a immutable
     * request and store within the session. False may cause an application
     * to fail when it is absent.
     */
    createWhenCsrfTokenAbsent?: boolean

    /**
     * Name of the request header to look for the CSRF token
     */
    headerName?: string

    /**
     * Name of the field in the request body for the CSRF token
     */
    parameterName?: string

    /**
     * When set to true will expect there to be a Cookie referencing the
     * Session. When false it will perform no further processing.
     */
    errorWhenNoSessionCookie?: boolean
}

/**
 * Express middleware which will filter out requests believed to be as a result
 * of Cross Site Request Forgery attacks. These are identified by requests
 * to mutable endpoints which do not contain the expected CSRF token. This
 * is implementing the Synchronisation Token Pattern approach.
 *
 * Depending on the the properties provided will modify the behaviour
 */
export const CsrfProtectionMiddleware = (csrfOptions: CsrfOptions): RequestHandler => {
    return expressAsyncHandler(csrfFilter(csrfOptions))
}

const csrfFilter = (options: CsrfOptions): RequestHandler => {
    return async (req: Request, res: Response, next: NextFunction): Promise<any> => {
        const appName = 'CH Web Security Node'

        // When disabled just continue chain
        if (!options.enabled) {
            console.debug('CSRF protections disabled')
            return next()
        }

        try {
            // This filter requires the session to be set on the request - fail
            // the request if there is no session set, probably the result of
            // application misconfiguration
            if (!req.session) {
                logger.error(`${appName} - handler: Session object is missing!`)

                if (MUTABLE_METHODS.includes(req.method)) {
                    throw new SessionUnsetError('Session not set.')
                } else {
                    return next()
                }
            }

            const headerName = options.headerName || DEFAULT_CSRF_TOKEN_HEADER
            const parameterName = options.parameterName || DEFAULT_CSRF_TOKEN_PARAMETER_NAME
            const csrfTokenFactory = options.csrfTokenFactory || defaultCsrfTokenFactory
            const cookieName = options.sessionCookieName || DEFAULT_CHS_SESSION_COOKIE_NAME
            const errorWhenNoSessionCookie = options.errorWhenNoSessionCookie || false

            const hasSessionCookie = typeof req.cookies[cookieName] !== 'undefined'

            const sessionCsrfToken = req.session.get<string>(SessionKey.CsrfToken)

            // The token is assigned as a local so that views can reference it, this function
            // will apply the supplied token to the variable
            const applyCsrfTokenToLocals = (csrfTokenToUse: string) => res.locals.csrfToken = csrfTokenToUse

            if (MUTABLE_METHODS.includes(req.method)) {
                if (!hasSessionCookie && errorWhenNoSessionCookie) {
                    logger.error('Request does not have cookie present.')

                    return next(new SessionUnsetError('Performing mutable request and no Session Cookie present'))
                } else if (!hasSessionCookie) {
                    logger.info('WARNING: Request does not have cookie present and ' +
                        'performing a mutable request. Not performing further validation.')

                    return next()
                }

                // When the request is for a method which likely mutates the
                // state of the application check that it is possible
                // to perform the check and check the tokens match
                if (!sessionCsrfToken) {
                    throw new MissingCsrfSessionToken('Session does not include CSRF token.')
                }

                // Token most likely to be in the request body so prioritise over headers
                // it is also the hardest for an attacker to modify
                const csrfTokenInRequest = req?.body?.[parameterName] || req.headers[headerName]

                if (csrfTokenInRequest !== sessionCsrfToken) {
                    logger.error('Possible csrf attack mitigated')
                    throw new CsrfTokensMismatchError('Invalid CSRF token.')
                }

                applyCsrfTokenToLocals(sessionCsrfToken)
            } else if (!sessionCsrfToken && hasSessionCookie) {
                if (options.createWhenCsrfTokenAbsent !== false) {
                    // When there is no CSRF token in the CHS session and the options
                    // generate a new token and store in the session
                    const csrfToken = csrfTokenFactory()
                    const newSessionData = {
                        ...(req.session.data),
                        [SessionKey.CsrfToken]: csrfToken
                    }

                    req.session = new Session(newSessionData)

                    await options.sessionStore.store(
                        Cookie.createFrom(req.cookies[cookieName]),
                        newSessionData
                    )

                    applyCsrfTokenToLocals(csrfToken)
                } else {
                    throw new MissingCsrfSessionToken('CSRF token not found in session.')
                }
            } else if (sessionCsrfToken) {
                applyCsrfTokenToLocals(sessionCsrfToken)
            }

            return next()
        } catch (err) {
            logger.errorRequest(req, `Could not handle CSRF validation: ${err}`)
            return next(err)
        }
    }
}
