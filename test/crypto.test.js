const ajv = require('ajv')()
const crypto = require('../crypto')
const schemas = require('../schemas')
const tape = require('tape')

tape('encryption round trip', function (test) {
  const plaintext = 'plaintext message'
  const key = crypto.encryptionKey()
  const nonce = crypto.nonce()
  const encrypted = crypto.encryptString({
    plaintext, nonce, key
  })
  const decrypted = crypto.decryptString({
    ciphertext: encrypted, nonce, key
  })
  test.same(plaintext, decrypted, 'identical')
  test.end()
})

tape('bad decryption', function (test) {
  const random = crypto.random(64)
  const key = crypto.encryptionKey()
  const nonce = crypto.nonce()
  const decrypted = crypto.decryptString({
    ciphertext: random, nonce, key
  })
  test.assert(decrypted === false)
  test.end()
})

tape('binary encryption round trip', function (test) {
  const binary = crypto.random(32)
  const key = crypto.encryptionKey()
  const nonce = crypto.nonce()
  const encrypted = crypto.encryptBinary({
    plaintext: binary, nonce, key
  })
  const decrypted = crypto.decryptBinary({
    ciphertext: encrypted, nonce, key
  })
  test.same(binary, decrypted, 'identical')
  test.end()
})

tape('binary bad decryption', function (test) {
  const random = crypto.random(32)
  const key = crypto.encryptionKey()
  const nonce = crypto.nonce()
  const decrypted = crypto.decryptBinary({
    ciphertext: random, nonce, key
  })
  test.assert(decrypted === false)
  test.end()
})

tape('signature', function (test) {
  const keyPair = crypto.keyPair()
  const object = { entry: 'plaintext message' }
  const signature = crypto.signJSON({
    message: object,
    secretKey: keyPair.secretKey
  })
  test.assert(
    crypto.verifyJSON({
      message: object,
      signature,
      publicKey: keyPair.publicKey
    })
  )
  test.end()
})

tape('signature with body key', function (test) {
  const keyPair = crypto.keyPair()
  const object = { text: 'plaintext message' }
  const signature = crypto.signJSON({
    message: object,
    secretKey: keyPair.secretKey
  })
  test.assert(
    crypto.verifyJSON({
      message: object,
      signature,
      publicKey: keyPair.publicKey
    })
  )
  test.end()
})

tape('signature with keys from seed', function (test) {
  const plaintext = 'plaintext message'
  const seed = crypto.keyPairSeed()
  const keyPair = crypto.keyPairFromSeed(seed)
  const object = { entry: plaintext }
  const signature = crypto.signJSON({
    message: object, secretKey: keyPair.secretKey
  })
  test.assert(
    crypto.verifyJSON({
      message: object, signature, publicKey: keyPair.publicKey
    })
  )
  test.end()
})

tape('hash', function (test) {
  const input = 'this is some input'
  const digest = crypto.hash(input)
  test.assert(typeof digest === 'string')
  test.end()
})

tape('hashJSON', function (test) {
  const input = { text: 'this is some input' }
  const digest = crypto.hashJSON(input)
  test.assert(typeof digest === 'string')
  test.end()
})

tape('random', function (test) {
  const random = crypto.random(32)
  test.assert(typeof random === 'string')
  test.end()
})

tape('read key', function (test) {
  const key = crypto.encryptionKey()
  test.assert(typeof key === 'string')
  test.end()
})

tape('discovery key', function (test) {
  const distributionKey = crypto.distributionKey()
  test.assert(typeof distributionKey === 'string')
  const projectDiscoverKey = crypto.discoveryKey(distributionKey)
  test.assert(typeof projectDiscoverKey === 'string')
  test.end()
})

tape('verify envelope', function (test) {
  const distributionKey = crypto.distributionKey()
  const discoveryKey = crypto.discoveryKey(distributionKey)
  const index = 1
  const prior = crypto.hash(crypto.random(64))
  const entry = {
    discoveryKey,
    index,
    prior,
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    timestamp: new Date().toISOString()
  }
  const logKeyPair = crypto.keyPair()
  const logPublicKey = logKeyPair.publicKey
  const projectKeyPair = crypto.keyPair()
  const projectPublicKey = projectKeyPair.publicKey
  const encryptionKey = crypto.encryptionKey()
  const nonce = crypto.nonce()
  const ciphertext = crypto.encryptJSON({
    plaintext: entry,
    nonce,
    key: encryptionKey
  })
  const envelope = {
    discoveryKey,
    logPublicKey,
    index,
    prior,
    logSignature: crypto.signBinary({
      message: ciphertext, secretKey: logKeyPair.secretKey
    }),
    projectSignature: crypto.signBinary({
      message: ciphertext, secretKey: projectKeyPair.secretKey
    }),
    entry: { ciphertext, nonce }
  }
  ajv.validate(schemas.envelope, envelope)
  test.same(ajv.errors, null, 'no schema errors')
  const errors = crypto.verifyEnvelope({
    envelope, projectPublicKey, encryptionKey
  })
  test.same(errors, [], 'no signature validation errors')
  test.end()
})

tape('envelope generate and verify', function (test) {
  const distributionKey = crypto.distributionKey()
  const discoveryKey = crypto.discoveryKey(distributionKey)
  const logKeyPair = crypto.keyPair()
  const projectKeyPair = crypto.keyPair()
  const projectPublicKey = projectKeyPair.publicKey
  const encryptionKey = crypto.encryptionKey()
  const index = 1
  const prior = crypto.hash(crypto.random(64))
  const entry = {
    discoveryKey,
    index,
    prior,
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    timestamp: new Date().toISOString()
  }
  ajv.validate(schemas.intro, entry)
  test.same(ajv.errors, null, 'no intro schema errors')
  ajv.validate(schemas.entry, entry)
  test.same(ajv.errors, null, 'no entry schema errors')
  let envelope
  test.doesNotThrow(function () {
    envelope = crypto.envelope({
      logKeyPair,
      projectKeyPair,
      encryptionKey,
      entry
    })
  }, '.envelope() does not throw')
  ajv.validate(schemas.envelope, envelope)
  test.same(ajv.errors, null, 'no schema validation errors')
  let errors
  test.doesNotThrow(function () {
    errors = crypto.verifyEnvelope({
      envelope, projectPublicKey, encryptionKey
    })
  }, '.verifyEnvelope() does not throw')
  test.same(errors, [], '.verifyEnvelope() returns no errors')
  test.end()
})

tape('invitation round trip', function (test) {
  const distributionKey = crypto.distributionKey()
  const keyPair = crypto.keyPair()
  const publicKey = keyPair.publicKey
  const secretKey = keyPair.secretKey
  const encryptionKey = crypto.encryptionKey()
  const title = 'Test Title'
  let invitation
  test.doesNotThrow(function () {
    invitation = crypto.encryptInvitation({
      distributionKey,
      publicKey,
      encryptionKey,
      secretKey,
      title
    })
  }, '.invitation() does not throw')
  const opened = crypto.decryptInvitation({
    invitation, encryptionKey
  })
  test.same(opened.secretKey, secretKey, 'secretKey')
  test.same(opened.encryptionKey, encryptionKey, 'encryptionKey')
  test.same(opened.title, title, 'title')
  test.end()
})

tape('encoding round trip', function (test) {
  const original = crypto.random(32)
  const hex = crypto.base64ToHex(original)
  test.assert(/^[a-f0-9]+$/.test(hex))
  const base64 = crypto.hexToBase64(hex)
  test.same(original, base64)
  test.end()
})
