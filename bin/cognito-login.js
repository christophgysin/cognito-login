#!/usr/bin/env node
const readline = require('readline')
const { Writable } = require('stream')
const { Auth } = require('../lib/cognito')

const {
  COGNITO_CLIENT_ID,
  COGNITO_USER_POOL_ID,
} = process.env

const prompt = (msg) => async () => {
  const mutableStdout = new Writable({
    write(chunk, encoding, callback) {
      if (!this.muted) {
        process.stdout.write(chunk, encoding)
      }
      callback()
    },
  })
  mutableStdout.muted = false

  const rl = readline.createInterface({
    input: process.stdin,
    output: mutableStdout,
    terminal: true,
  })

  return new Promise((resolve) => {
    rl.question(`${msg}: `, (password) => {
      rl.close()
      resolve(password)
      mutableStdout.muted = false
      mutableStdout.write('\n')
    })
    mutableStdout.muted = true
  })
}

const promptForPassword = prompt('Password')
const promptForMFA = prompt('MFA')

const main = async () => {
  const args = process.argv.slice(2)
  if (args.length < 1) {
    console.error('Usage: login <username> [password]')
    process.exit(1)
  }

  const [
    username,
    passwordArg,
    mfaArg,
  ] = args

  const passwordFunc = (passwordArg !== undefined) ? () => passwordArg : promptForPassword
  const mfaFunc = (mfaArg !== undefined) ? () => mfaArg : promptForMFA
  const auth = await new Auth(COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID)
    .login(username, passwordFunc, mfaFunc)
  console.log('auth:', auth)
}

Promise.resolve(main())
  .catch((error) => console.error(error))
