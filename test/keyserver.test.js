const crypto = require('crypto')
const has = require('has')
const protocol = require('../keyserver')
const tape = require('tape')

tape('keyserver protocol', test => {
  // client login

  const clientLogin = protocol.client.login({
    password: 'apple sauce',
    email: 'user@example.com'
  })

  test.assert(has(clientLogin, 'clientStretchedPassword'))
  test.assert(clientLogin.clientStretchedPassword.length === 32)
  test.assert(has(clientLogin, 'authenticationToken'))
  test.assert(clientLogin.authenticationToken.length === 32)

  // server register

  const serverRegister = protocol.server.register({
    clientStretchedPassword: clientLogin.clientStretchedPassword,
    authenticationToken: clientLogin.authenticationToken
  })

  test.assert(has(serverRegister, 'authenticationSalt'))
  test.assert(serverRegister.authenticationSalt.length === 16)
  test.assert(has(serverRegister, 'serverStretchedPassword'))
  test.assert(serverRegister.serverStretchedPassword.length === 32)
  test.assert(has(serverRegister, 'serverWrappedEncryptionKey'))
  test.assert(serverRegister.serverWrappedEncryptionKey.length === 32)
  test.assert(has(serverRegister, 'userID'))
  test.assert(serverRegister.userID.length === 32)
  test.assert(has(serverRegister, 'verificationHash'))
  test.assert(serverRegister.verificationHash.length === 32)

  // server login verification

  const serverLogin = protocol.server.login({
    authenticationToken: clientLogin.authenticationToken,
    authenticationSalt: serverRegister.authenticationSalt,
    verificationHash: serverRegister.verificationHash
  })

  test.assert(serverLogin === true)

  const badServerLogin = protocol.server.login({
    authenticationToken: clientLogin.authenticationToken,
    authenticationSalt: serverRegister.authenticationSalt,
    verificationHash: Buffer.alloc(32)
  })

  test.assert(badServerLogin === false)

  // server access token request server

  const keyAccessToken = crypto.randomBytes(32)

  const serverRequest = protocol.server.request({
    serverStretchedPassword: serverRegister.serverStretchedPassword,
    serverWrappedEncryptionKey: serverRegister.serverWrappedEncryptionKey,
    keyAccessToken
  })

  test.assert(has(serverRequest, 'tokenID'))
  test.assert(serverRequest.tokenID.length === 32)
  test.assert(has(serverRequest, 'ciphertext'))
  test.assert(serverRequest.ciphertext.length === 32)
  test.assert(has(serverRequest, 'mac'))
  test.assert(serverRequest.mac.length === 32)
  test.assert(has(serverRequest, 'requestAuthenticationKey'))
  test.assert(serverRequest.requestAuthenticationKey.length === 32)

  // access token client request

  const clientRequest = protocol.client.request({
    ciphertext: serverRequest.ciphertext,
    mac: serverRequest.mac,
    clientStretchedPassword: clientLogin.clientStretchedPassword,
    keyAccessToken
  })

  test.assert(has(clientRequest, 'encryptionKey'))
  test.assert(clientRequest.encryptionKey.length === 32)

  const badClientRequest = protocol.client.request({
    ciphertext: serverRequest.ciphertext,
    mac: Buffer.alloc(32),
    clientStretchedPassword: clientLogin.clientStretchedPassword,
    keyAccessToken
  })

  test.assert(badClientRequest === false)

  test.end()
})
