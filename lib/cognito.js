const { promisify } = require('util')
const AWS = require('aws-sdk')
const CryptoJS = require('crypto-js/core')
const Base64 = require('crypto-js/enc-base64')
const HmacSHA256 = require('crypto-js/hmac-sha256')
const { DateHelper, AuthenticationHelper } = require('amazon-cognito-identity-js')
const { default: BigInteger } = require('../node_modules/amazon-cognito-identity-js/lib/BigInteger')

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

    const authHelper = new AuthenticationHelper(poolName)
    this.getLargeAValue = promisify(authHelper.getLargeAValue.bind(authHelper))
    this.getPasswordAuthKey = promisify(authHelper.getPasswordAuthenticationKey.bind(authHelper))
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
    const a = await this.getLargeAValue()
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
    const srpB = new BigInteger(SRP_B, 16)
    const salt = new BigInteger(SALT, 16)
    const timestamp = new DateHelper().getNowString()

    const message = CryptoJS.lib.WordArray.create(Buffer.concat([
      Buffer.from(this.poolName, 'utf-8'),
      Buffer.from(USERNAME, 'utf-8'),
      Buffer.from(SECRET_BLOCK, 'base64'),
      Buffer.from(timestamp, 'utf8'),
    ]))
    const password = await passwordFunc()
    const hkdf = await this.getPasswordAuthKey(USERNAME, password, srpB, salt)
    const key = CryptoJS.lib.WordArray.create(hkdf)
    const signatureString = Base64.stringify(HmacSHA256(message, key))

    const params = {
      ChallengeName: 'PASSWORD_VERIFIER',
      ClientId: this.clientId,
      ChallengeResponses: {
        USERNAME,
        PASSWORD_CLAIM_SECRET_BLOCK: SECRET_BLOCK,
        TIMESTAMP: timestamp,
        PASSWORD_CLAIM_SIGNATURE: signatureString,
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
