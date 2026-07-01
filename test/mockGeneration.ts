import { Request, Response } from 'express'
import sinon from 'sinon'
import { Session } from '@companieshouse/node-session-handler'
import { SignInInfoKeys} from '@companieshouse/node-session-handler/lib/session/keys/SignInInfoKeys'
import { UserProfileKeys } from '@companieshouse/node-session-handler/lib/session/keys/UserProfileKeys'
import { SessionKey } from '@companieshouse/node-session-handler/lib/session/keys/SessionKey'
import { ISignInInfo } from '@companieshouse/node-session-handler/lib/session/model/SessionInterfaces'

export function generateResponse(): Response {
  const res: Response = Object.create(require('express').response)
  res.redirect = sinon.stub().withArgs(sinon.match.any)
  res.locals = {}
  return res
}

export function generateSignInInfo(mockUserId: string, signedIn: number): ISignInInfo {
  return {
    signed_in: signedIn,
    user_profile: {
      id: mockUserId
    }
  }
}

export function generateSignInInfoWithTokenPermissions(mockUserId: string, signedIn: number): ISignInInfo {
  return {
    signed_in: signedIn,
    user_profile: {
      id: mockUserId,
      [UserProfileKeys.TokenPermissions]: {
        "overseas_entities": "create,update,delete",
        "user_orders": "create,read,update,delete",
        "acsp_profile": "create",
        "test_permission": "create,update"
      }
    }
  }
}

export function generateSignInInfoAuthedForCompany(
    mockUserId: string,
    signedIn: number,
    companyNumber: string
): ISignInInfo {
  const signInInfo: ISignInInfo = generateSignInInfo(mockUserId, signedIn)
  signInInfo[SignInInfoKeys.CompanyNumber] = companyNumber
  return signInInfo
}

export function generateSignInInfoAuthedForScope(
    mockUserId: string,
    signedIn: number,
    additionScope: string
): ISignInInfo {
  const signInInfo: ISignInInfo = generateSignInInfo(mockUserId, signedIn)
  signInInfo[SignInInfoKeys.AdditionalScope] = additionScope
  return signInInfo
}

export function generateRequest(
    requestSession?: Session,
    csrfTokenInHeader?: string,
    csrfTokenInBody?: string,
    method: 'GET' | 'POST' | "DELETE" = "GET"
): Request {

  const headers = {
    ...(
      csrfTokenInHeader
      ? {
        "x-csrf-token": csrfTokenInHeader
      }
      : {}
    ),
    host: "localhost"
  }

  const body = csrfTokenInBody
    ? {
      "_csrf": csrfTokenInBody
    }
    : {}

  const request: Request = {
    headers,
    method,
    body
  } as Request

  if (requestSession) {
    request.session = requestSession
    if (requestSession.data) {
      request.session.data = {
        ...request.session.data,
        [SessionKey.ClientSig]: request.session.data[SessionKey.ClientSig] ?? "d5d4cd07616a542891b7ec2d0257b3a24b69856e",
        [SessionKey.Hijacked]: request.session.data[SessionKey.Hijacked] ?? "0"
      }
    }
  }
  return request
}
