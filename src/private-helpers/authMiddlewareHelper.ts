import '@companieshouse/node-session-handler'
import {SessionKey} from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import {SignInInfoKeys} from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import {ISignInInfo, IUserProfile} from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'
import {NextFunction, Request, RequestHandler, Response} from 'express'
import {AuthOptions} from '..'
import {additionalScopeIsRequired}  from './additionalScopeIsRequired'
import {logger} from './createLogger'
import {RequestScopeAndPermissions} from './RequestScopeAndPermissions'


export const authMiddlewareHelper = (options: AuthOptions, requestScopeAndPermissions?: RequestScopeAndPermissions): RequestHandler => (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    const appName = 'CH Web Security Node'

    logger.debug(`${appName} - handler: in auth helper function`)
  
    if (!options.chsWebUrl) {
      logger.error(`${appName} - handler: Required Field CHS Web URL not set`)
      throw new Error('Required Field CHS Web URL not set')
    }
  
    let redirectURI = `${options.chsWebUrl}/signin?return_to=${options.returnUrl}`
  
    if(options.companyNumber) {
      redirectURI = redirectURI.concat(`&company_number=${options.companyNumber}`)
    }
  
    if ( ! req.session)  {
      if(requestScopeAndPermissions) {
        redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`)
      }
  
      logger.debug(`${appName} - handler: Session object is missing!`)
      return res.redirect(redirectURI)
    }
  
    const signInInfo: ISignInInfo = req.session.get<ISignInInfo>(SessionKey.SignInInfo) || {}
    const signedIn: boolean = signInInfo![SignInInfoKeys.SignedIn] === 1
    const userProfile: IUserProfile = signInInfo![SignInInfoKeys.UserProfile] || {}
    const userId: string | undefined = userProfile?.id
  
    if (requestScopeAndPermissions && additionalScopeIsRequired(requestScopeAndPermissions, userProfile)) {
      redirectURI = redirectURI.concat(`&additional_scope=${requestScopeAndPermissions.scope}`)
      logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Updating URL to: ${redirectURI}`)
    }
  
    if (!signedIn) {
      logger.info(`${appName} - handler: userId=${userId}, Not signed in... Redirecting to: ${redirectURI}`)
      return res.redirect(redirectURI)
    }
  
    if (options.companyNumber && !isAuthorisedForCompany(options.companyNumber, signInInfo)) {
      logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${options.companyNumber}... Redirecting to: ${redirectURI}`)
      return res.redirect(redirectURI)
    }
  
    if (requestScopeAndPermissions && additionalScopeIsRequired(requestScopeAndPermissions, userProfile)) {
      logger.info(`${appName} - handler: userId=${userId}, Not Authorised for ${requestScopeAndPermissions}... Redirecting to: ${redirectURI}`)
      return res.redirect(redirectURI)
    }
  
    logger.debug(`${appName} - handler: userId=${userId} authenticated successfully`)
    return next()
  }

  function isAuthorisedForCompany(companyNumber: string, signInInfo: ISignInInfo): boolean {
    const authorisedCompany = signInInfo[SignInInfoKeys.CompanyNumber]
    if (!authorisedCompany) {
      return false
    }
  
    return authorisedCompany.localeCompare(companyNumber) === 0
  }
  
  