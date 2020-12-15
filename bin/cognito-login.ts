#!/usr/bin/env ts-node
import * as readline from 'readline'
import { Writable } from 'stream'
import Auth from '../src/cognito'

const {
  COGNITO_CLIENT_ID: clientId,
  COGNITO_USER_POOL_ID: poolId,
} = process.env

class Muteable extends Writable {
  private muted: boolean = false

  constructor(private stream: Writable) {
    super()
  }

  mute() {
    this.muted = true
  }
  unmute() {
    this.muted = false
  }

  write(chunk: any, cb?: (error: Error | null | undefined) => void): boolean;
  write(chunk: any, encoding: BufferEncoding, cb?: (error: Error | null | undefined) => void): boolean;
  write(chunk: any, encodingOrCb?: any, cb?: (error: Error | null | undefined) => void): boolean {
    if (encodingOrCb && typeof encodingOrCb == "function") {
      if (!this.muted) {
        return this.stream.write(chunk, encodingOrCb)
      }
      return true
    }

    if (!this.muted) {
      return this.stream.write(chunk, encodingOrCb, cb)
    }
    return true
  }
}

const prompt = (msg: string, hidden: boolean = false) => async (): Promise<string> => {
  const stdout = new Muteable(process.stdout)

  const rl = readline.createInterface({
    input: process.stdin,
    output: stdout,
    terminal: true,
  })

  return new Promise((resolve) => {
    rl.question(`${msg}: `, (password: string) => {
      rl.close()
      resolve(password)
      stdout.unmute()
      stdout.write('\n')
    })
    if (hidden) {
      stdout.mute()
    }
  })
}

const main = async () => {
  const [
    username,
    passwordArg,
    mfaArg,
  ] = process.argv.slice(2)

  const auth = new Auth(poolId, clientId, {
    username: username ?? prompt('Username'),
    password: passwordArg ?? prompt('Password', true),
    mfa: mfaArg ?? prompt('MFA', true),
    newPassword: prompt('New Password', true),
  })
  const credentials = await auth.login()
  console.log(credentials)
}

Promise.resolve(main())
  .catch((error) => console.error(error))
