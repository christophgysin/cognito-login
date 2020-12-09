const crypto = require('crypto');
const { promisify } = require('util')
const AWS = require('aws-sdk')
const { DateHelper, AuthenticationHelper } = require('amazon-cognito-identity-js')
const { default: BigInteger } = require('../node_modules/amazon-cognito-identity-js/lib/BigInteger')

class AuthenticationHelperPromise extends AuthenticationHelper {
  constructor(...args) {
    super(...args)
    this.getLargeAValue = promisify(super.getLargeAValue.bind(this))
    this.getPasswordAuthenticationKey = promisify(super.getPasswordAuthenticationKey.bind(this))
  }
}

class Auth {
  constructor(poolId, clientId) {
    const [region, poolName] = poolId.split('_')
    this.poolName = poolName
    this.clientId = clientId
    this.cognito = new AWS.CognitoIdentityServiceProvider({
      region,
      credentials: new AWS.Credentials('', '', ''),
      apiVersion: '2016-04-18',
    })

    this.authHelper = new AuthenticationHelperPromise(poolName)
  }

  async login(username, passwordFunc, mfaFunc) {
    this.username = username
    this.passwordFunc = passwordFunc
    this.mfaFunc = mfaFunc

    const response = await this.initiateAuth(username)
    return this.handleChallenge(response)
  }

  async handleChallenge(response) {
    const {
      ChallengeName: challenge,
      ChallengeParameters: parameters,
      Session: session,
      AuthenticationResult: auth,
    } = response

    switch (challenge) {
      case 'PASSWORD_VERIFIER':
        return this.handleChallenge(await this.verifyPassword(parameters, this.passwordFunc))
      case 'SOFTWARE_TOKEN_MFA':
        return this.handleChallenge(await this.verifyMfa(this.username, session, this.mfaFunc))
      case undefined:
        return auth
      default:
        throw new Error(`Challenge not implemented: ${challenge}`)
    }
  }

  async initiateAuth(username) {
    const a = await this.authHelper.getLargeAValue()
    const srpA = a.toString(16)

    const params = {
      ClientId: this.clientId,
      AuthFlow: 'USER_SRP_AUTH',
      AuthParameters: {
        USERNAME: username,
        SRP_A: srpA,
      },
    }
    return this.cognito.initiateAuth(params).promise()
  }

  async verifyPassword(challengeParameters, passwordFunc) {
    const {
      USERNAME,
      SECRET_BLOCK,
      SRP_B,
      SALT,
    } = challengeParameters

    const password = await passwordFunc()
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
        TIMESTAMP: timestamp,
        PASSWORD_CLAIM_SIGNATURE: signature,
      },
    }
    return this.cognito.respondToAuthChallenge(params).promise()
  }

  async verifyMfa(username, session, mfaFunc) {
    const mfaCode = await mfaFunc()

    const params = {
      ChallengeName: 'SOFTWARE_TOKEN_MFA',
      Session: session,
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME: username,
        SOFTWARE_TOKEN_MFA_CODE: mfaCode,
      },
    }
    return this.cognito.respondToAuthChallenge(params).promise()
  }
}

module.exports = {
  Auth,
}
