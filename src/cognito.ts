import * as crypto from 'crypto'
import { promisify } from 'util'
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  RespondToAuthChallengeCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider'
// TODO: use imports?
const { DateHelper, AuthenticationHelper } = require('amazon-cognito-identity-js')
const { default: BigInteger } = require('../node_modules/amazon-cognito-identity-js/lib/BigInteger')

type BigInteger = typeof BigInteger

class AuthenticationHelperPromise extends AuthenticationHelper {
  constructor(poolName: string) {
    super(poolName)
  }
  getLargeAValuePromise(): Promise<BigInteger> {
    return promisify(super.getLargeAValue.bind(this))()
  }
  getPasswordAuthenticationKeyPromise(username: string, password: string, serverBValue: BigInteger, salt: BigInteger): Promise<Buffer> {
    return promisify(super.getPasswordAuthenticationKey.bind(this))(username, password, serverBValue, salt)
  }
}

type StringOrPromise = string | Promise<string>

type AuthOptions = {
  username: string | (() => StringOrPromise),
  password: string | (() => StringOrPromise),
  mfa: string | (() => StringOrPromise),
  newPassword: string | (() => StringOrPromise),
}

type ChallengeParameters = { [key: string]: string }

export default class Auth {
  private cognito: CognitoIdentityProviderClient
  private authHelper: AuthenticationHelperPromise
  private poolName: string

  constructor(readonly poolId: string, readonly clientId: string, readonly options: AuthOptions) {
    const [region, poolName] = poolId.split('_')
    this.poolName = poolName
    this.cognito = new CognitoIdentityProviderClient({
      apiVersion: '2016-04-18',
      region,
    })
    this.authHelper = new AuthenticationHelperPromise(poolName)
  }

  async getUsername(): Promise<string> {
    const { username } = this.options
    this.options.username = (typeof username === 'string') ? username : await username()
    return this.options.username
  }

  async getPassword(): Promise<string> {
    const { password } = this.options
    this.options.password = (typeof password === 'string') ? password : await password()
    return this.options.password
  }

  async getMfa(): Promise<string> {
    const { mfa } = this.options
    this.options.mfa = (typeof mfa === 'string') ? mfa : await mfa()
    return this.options.mfa
  }

  async login() {
    const response = await this.initiateAuth()
    const { AuthenticationResult: auth } = await this.handleChallenge(response)
    return auth
  }

  async handleChallenge(response: RespondToAuthChallengeCommandOutput): Promise<RespondToAuthChallengeCommandOutput> {
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
    const a = await this.authHelper.getLargeAValuePromise()
    const srpA = a.toString(16)

    const params = {
      ClientId: this.clientId,
      AuthFlow: 'USER_SRP_AUTH',
      AuthParameters: {
        USERNAME: await this.getUsername(),
        SRP_A: srpA,
      },
    }
    return this.cognito.send(new InitiateAuthCommand(params))
  }

  async verifyPassword(challengeParameters: ChallengeParameters) {
    const {
      USERNAME,
      SECRET_BLOCK,
      SRP_B,
      SALT,
    } = challengeParameters

    const password = await this.getPassword()
    const srpB = new BigInteger(SRP_B, 16)
    const salt = new BigInteger(SALT, 16)
    const key = await this.authHelper.getPasswordAuthenticationKeyPromise(USERNAME, password, srpB, salt)

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
    return this.cognito.send(new RespondToAuthChallengeCommand(params))
  }

  async verifyMfa(session: string) {
    const params = {
      ChallengeName: 'SOFTWARE_TOKEN_MFA',
      Session: session,
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME: await this.getUsername(),
        SOFTWARE_TOKEN_MFA_CODE: await this.getMfa(),
      },
    }
    return this.cognito.send(new RespondToAuthChallengeCommand(params))
  }

  async verifySms(session: string) {

    const params = {
      ChallengeName: 'SMS_MFA',
      Session: session,
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME: await this.getUsername(),
        SMS_MFA_CODE: await this.getMfa(),
      },
    }
    return this.cognito.send(new RespondToAuthChallengeCommand(params))
  }
}
