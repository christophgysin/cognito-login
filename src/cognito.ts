import * as crypto from 'crypto'
import { promisify } from 'util'
import * as AWS from 'aws-sdk'
// TODO: use imports?
const { DateHelper, AuthenticationHelper } = require('amazon-cognito-identity-js')
const { default: BigInteger } = require('../node_modules/amazon-cognito-identity-js/lib/BigInteger')

type BigInteger = typeof BigInteger

class AuthenticationHelperPromise extends AuthenticationHelper {
  constructor(poolName: string) {
    super(poolName)
  }
  getLargeAValue(): Promise<BigInteger> {
    return promisify(super.getLargeAValue.bind(this))(arguments)
  }
  getPasswordAuthenticationKey(username: string, password: string, serverBValue: BigInteger, salt: BigInteger): Promise<Buffer> {
    return promisify(super.getPasswordAuthenticationKey.bind(this))(username, password, serverBValue, salt)
  }
}

type ChallengeParameters = {
  USERNAME: string,
  SECRET_BLOCK: string,
  SRP_B: string,
  SALT: string,
}
type ChallengeResponse = {
  ChallengeName: 'SMS_MFA' | 'SOFTWARE_TOKEN_MFA' | 'SELECT_MFA_TYPE' | 'MFA_SETUP' | 'PASSWORD_VERIFIER' | 'CUSTOM_CHALLENGE' |
                 'DEVICE_SRP_AUTH' | 'DEVICE_PASSWORD_VERIFIER' | 'ADMIN_NO_SRP_AUTH' | 'NEW_PASSWORD_REQUIRED',
  ChallengeParameters: ChallengeParameters,
  Session: string,
  AuthenticationResult: object,
}

export default class Auth {
  private cognito: any
  private authHelper: AuthenticationHelperPromise
  private passwordFunc: () => Promise<string>
  private mfaFunc: () => Promise<string>
  private poolName: string

  constructor(readonly poolId: string, readonly clientId: string, readonly username: string, passwordFunc: () => Promise<string>, mfaFunc: () => Promise<string>) {
    const [region, poolName] = poolId.split('_')
    this.poolName = poolName
    this.cognito = new AWS.CognitoIdentityServiceProvider({
      apiVersion: '2016-04-18',
      region,
      credentials: new AWS.Credentials('', '', ''),
    })
    this.authHelper = new AuthenticationHelperPromise(poolName)
    this.passwordFunc = passwordFunc
    this.mfaFunc = mfaFunc
  }

  async login() {
    const response = await this.initiateAuth()
    const { AuthenticationResult: auth } = await this.handleChallenge(response)
    return auth
  }

  async handleChallenge(response: ChallengeResponse): Promise<ChallengeResponse> {
    const {
      ChallengeName: challenge,
      ChallengeParameters: parameters,
      Session: session,
    } = response

    switch (challenge) {
      case 'PASSWORD_VERIFIER':
        return this.handleChallenge(await this.verifyPassword(parameters))
      case 'SOFTWARE_TOKEN_MFA':
        return this.handleChallenge(await this.verifyMfa(session))
      case 'SMS_MFA':
        return this.handleChallenge(await this.verifySms(session))
      case undefined:
        return Promise.resolve(response)
      default:
        throw new Error(`Challenge not implemented: ${challenge}`)
    }
  }

  async initiateAuth() {
    const a = await this.authHelper.getLargeAValue()
    const srpA = a.toString(16)

    const params = {
      ClientId: this.clientId,
      AuthFlow: 'USER_SRP_AUTH',
      AuthParameters: {
        USERNAME: this.username,
        SRP_A: srpA,
      },
    }
    return this.cognito.initiateAuth(params).promise()
  }

  async verifyPassword(challengeParameters: ChallengeParameters) {
    const {
      USERNAME,
      SECRET_BLOCK,
      SRP_B,
      SALT,
    } = challengeParameters

    const password = await this.passwordFunc()
    const srpB = new BigInteger(SRP_B, 16)
    const salt = new BigInteger(SALT, 16)
    const key = await this.authHelper.getPasswordAuthenticationKey(USERNAME, password, srpB, salt)

    const timestamp = new DateHelper().getNowString()
    const signature = crypto.createHmac('sha256', key)
      .update(this.poolName, 'utf8')
      .update(USERNAME, 'utf8')
      .update(SECRET_BLOCK, 'base64')
      .update(timestamp, 'utf8')
      .digest('base64')

    const params = {
      ChallengeName: 'PASSWORD_VERIFIER',
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME,
        PASSWORD_CLAIM_SECRET_BLOCK: SECRET_BLOCK,
        PASSWORD_CLAIM_SIGNATURE: signature,
        TIMESTAMP: timestamp,
      },
    }
    return this.cognito.respondToAuthChallenge(params).promise()
  }

  async verifyMfa(session: string) {
    const mfaCode = await this.mfaFunc()

    const params = {
      ChallengeName: 'SOFTWARE_TOKEN_MFA',
      Session: session,
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME: this.username,
        SOFTWARE_TOKEN_MFA_CODE: mfaCode,
      },
    }
    return this.cognito.respondToAuthChallenge(params).promise()
  }

  async verifySms(session: string) {
    const mfaCode = await this.mfaFunc()

    const params = {
      ChallengeName: 'SMS_MFA',
      Session: session,
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME: this.username,
        SMS_MFA_CODE: mfaCode,
      },
    }
    return this.cognito.respondToAuthChallenge(params).promise()
  }
}
