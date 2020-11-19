// This module exports cryptographic functions and constants.

const assert = require('assert')
const has = require('has')
const sodium = require('sodium-universal')
const stringify = require('./stringify')

const BINARY_ENCODING = exports.binaryEncoding = 'base64'

// Random Data

function random (bytes) {
  assert(Number.isInteger(bytes))
  assert(bytes > 0)
  const buffer = Buffer.alloc(bytes)
  sodium.randombytes_buf(buffer)
  return buffer.toString(BINARY_ENCODING)
}

exports.random = random

// Hashing

const DIGEST_BYTES = exports.digestBytes = sodium.crypto_generichash_BYTES

function hash (input) {
  assert(typeof input === 'string')
  const digestBuffer = Buffer.alloc(DIGEST_BYTES)
  sodium.crypto_generichash(digestBuffer, Buffer.from(input))
  return digestBuffer.toString(BINARY_ENCODING)
}

exports.hash = hash

function hashJSON (input) {
  assert(input !== undefined)
  const digestBuffer = Buffer.alloc(DIGEST_BYTES)
  const inputBuffer = Buffer.from(stringify(input), 'utf8')
  sodium.crypto_generichash(digestBuffer, inputBuffer)
  return digestBuffer.toString(BINARY_ENCODING)
}

exports.hashJSON = hashJSON

// Stream Encryption

const STREAM_KEY_BYTES =
exports.distributionKeyBytes =
sodium.crypto_stream_KEYBYTES

exports.distributionKey = () => random(STREAM_KEY_BYTES)

exports.discoveryKey = distributionKey => {
  assert(typeof distributionKey === 'string')
  return hash(distributionKey)
}

exports.discoveryKeyLength = DIGEST_BYTES

// Box Encryption

const SECRETBOX_KEY_BYTES =
exports.encryptionKeyBytes =
sodium.crypto_secretbox_KEYBYTES

exports.encryptionKey = () => random(SECRETBOX_KEY_BYTES)

const SECRETBOX_NONCE_BYTES =
exports.nonceBytes =
sodium.crypto_secretbox_NONCEBYTES

exports.nonce = () => random(SECRETBOX_NONCE_BYTES)

const SECRETBOX_MAC_BYTES =
exports.encryptionMACBytes =
sodium.crypto_secretbox_MACBYTES

const inputTypes = {
  JSON: 'json',
  String: 'utf8',
  Binary: 'base64'
}

Object.keys(inputTypes).forEach(suffix => {
  const encoding = inputTypes[suffix]
  exports['encrypt' + suffix] = ({ plaintext, nonce, key }) => {
    return encrypt({ plaintext, encoding, nonce, key })
  }
  exports['decrypt' + suffix] = ({ ciphertext, nonce, key }) => {
    return decrypt({ ciphertext, encoding, nonce, key })
  }
})

function encrypt ({ plaintext, encoding, nonce, key }) {
  const plaintextBuffer = decode(plaintext, encoding)
  const ciphertextBuffer = Buffer.alloc(
    plaintextBuffer.length + SECRETBOX_MAC_BYTES
  )
  sodium.crypto_secretbox_easy(
    ciphertextBuffer,
    plaintextBuffer,
    Buffer.from(nonce, BINARY_ENCODING),
    Buffer.from(key, BINARY_ENCODING)
  )
  return ciphertextBuffer.toString(BINARY_ENCODING)
}

function decrypt ({ ciphertext, encoding, nonce, key }) {
  const ciphertextBuffer = decode(ciphertext, BINARY_ENCODING)
  const plaintextBuffer = Buffer.alloc(
    ciphertextBuffer.length - SECRETBOX_MAC_BYTES
  )
  const result = sodium.crypto_secretbox_open_easy(
    plaintextBuffer,
    ciphertextBuffer,
    Buffer.from(nonce, BINARY_ENCODING),
    Buffer.from(key, BINARY_ENCODING)
  )
  if (!result) return false
  return encode(plaintextBuffer, encoding)
}

// Signature

const SIGN_SEED_BYTES =
exports.keyPairSeedBytes =
sodium.crypto_sign_SEEDBYTES

exports.keyPairSeed = () => random(SIGN_SEED_BYTES)

const SIGN_PUBLIC_KEY_BYTES =
exports.publicKeyBytes =
sodium.crypto_sign_PUBLICKEYBYTES

const SIGN_SECRET_KEY_BYTES =
exports.secretKeyBytes =
sodium.crypto_sign_SECRETKEYBYTES

exports.keyPairFromSeed = seed => {
  assert(typeof seed === 'string')
  const publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  const secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_seed_keypair(
    publicKeyBuffer,
    secretKeyBuffer,
    Buffer.from(seed, BINARY_ENCODING)
  )
  return {
    secretKey: secretKeyBuffer.toString(BINARY_ENCODING),
    publicKey: publicKeyBuffer.toString(BINARY_ENCODING)
  }
}

exports.keyPair = () => {
  const publicKeyBuffer = Buffer.alloc(SIGN_PUBLIC_KEY_BYTES)
  const secretKeyBuffer = Buffer.alloc(SIGN_SECRET_KEY_BYTES)
  sodium.crypto_sign_keypair(publicKeyBuffer, secretKeyBuffer)
  return {
    publicKey: publicKeyBuffer.toString(BINARY_ENCODING),
    secretKey: secretKeyBuffer.toString(BINARY_ENCODING)
  }
}

const SIGNATURE_BYTES =
exports.signatureBytes =
sodium.crypto_sign_BYTES

Object.keys(inputTypes).forEach(suffix => {
  const encoding = inputTypes[suffix]
  exports['sign' + suffix] = ({ message, secretKey }) => {
    return sign({ message, encoding, secretKey })
  }
  exports['verify' + suffix] = ({ message, signature, publicKey }) => {
    return verify({ message, encoding, signature, publicKey })
  }
})

function sign ({ message, encoding, secretKey }) {
  assert(typeof secretKey === 'string')
  const signatureBuffer = Buffer.alloc(SIGNATURE_BYTES)
  sodium.crypto_sign_detached(
    signatureBuffer,
    decode(message, encoding),
    Buffer.from(secretKey, BINARY_ENCODING)
  )
  return signatureBuffer.toString(BINARY_ENCODING)
}

function verify ({ message, encoding, signature, publicKey }) {
  assert(typeof signature === 'string')
  assert(typeof publicKey === 'string')
  return sodium.crypto_sign_verify_detached(
    Buffer.from(signature, BINARY_ENCODING),
    decode(message, encoding),
    Buffer.from(publicKey, BINARY_ENCODING)
  )
}

function encode (buffer, encoding) {
  assert(Buffer.isBuffer(buffer))
  if (encoding === 'base64' || encoding === 'utf8') {
    return buffer.toString(encoding)
  }
  if (encoding === 'json') {
    return JSON.parse(buffer)
  }
  throw new Error('unsupported encoding: ' + encoding)
}

function decode (message, encoding) {
  assert(message !== undefined)
  if (encoding === 'base64' || encoding === 'utf8') {
    return Buffer.from(message, encoding)
  }
  if (encoding === 'json') {
    return Buffer.from(stringify(message), 'utf8')
  }
  throw new Error('unsupported encoding: ' + encoding)
}

// Envelopes

exports.envelope = ({
  entry,
  publicKey,
  logKeyPair,
  projectKeyPair,
  encryptionKey
}) => {
  assert(typeof entry === 'object')
  assert(typeof logKeyPair === 'object')
  assert(typeof logKeyPair.publicKey === 'string')
  assert(typeof logKeyPair.secretKey === 'string')
  assert(typeof projectKeyPair === 'object')
  assert(typeof projectKeyPair.publicKey === 'string')
  assert(typeof projectKeyPair.secretKey === 'string')
  const index = entry.index
  assert(Number.isSafeInteger(index))
  assert(index >= 0)
  if (index > 0) assert(typeof entry.prior === 'string')
  const nonce = exports.nonce()
  const ciphertext = exports.encryptJSON({
    plaintext: entry,
    nonce,
    key: encryptionKey
  })
  const envelope = {
    discoveryKey: entry.discoveryKey,
    index: entry.index,
    prior: entry.prior,
    logPublicKey: logKeyPair.publicKey,
    logSignature: exports.signBinary({
      message: ciphertext,
      secretKey: logKeyPair.secretKey
    }),
    projectSignature: exports.signBinary({
      message: ciphertext,
      secretKey: projectKeyPair.secretKey
    }),
    entry: { ciphertext, nonce }
  }
  return envelope
}

exports.verifyEnvelope = ({
  envelope,
  projectPublicKey,
  encryptionKey
}) => {
  assert(typeof envelope === 'object')
  assert(typeof projectPublicKey === 'string')
  assert(typeof encryptionKey === 'string')

  const errors = []

  function report (message, flag) {
    const error = new Error(message)
    error[flag] = true
    errors.push(error)
  }

  // Verify Signatures
  const ciphertext = envelope.entry.ciphertext
  const validLogSiganture = exports.verifyBinary({
    message: ciphertext,
    signature: envelope.logSignature,
    publicKey: envelope.logPublicKey
  })
  if (!validLogSiganture) {
    report('invalid log signature', 'logSignature')
  }
  const validProjectSignature = exports.verifyBinary({
    message: ciphertext,
    signature: envelope.projectSignature,
    publicKey: projectPublicKey
  })
  if (!validProjectSignature) {
    report('invalid project signature', 'projectSignature')
  }

  // Verify Entry
  if (encryptionKey) {
    const entry = exports.decryptJSON({
      ciphertext: envelope.entry.ciphertext,
      nonce: envelope.entry.nonce,
      key: encryptionKey
    })
    if (!entry) {
      report('could not decrypt entry', 'encryption')
    } else {
      if (entry.discoveryKey !== envelope.discoveryKey) {
        report('discoveryKey mismatch', 'discoveryKey')
      }
      if (entry.index !== envelope.index) {
        report('index mismatch', 'index')
      }
      if (entry.index > 0 && !envelope.prior) {
        report('envelope missing prior digest', 'envelopePrior')
      }
      if (entry.index > 0 && !entry.prior) {
        report('entry missing prior digest', 'entryPrior')
      }
    }
  }

  return errors
}

// Invitations

const invitationEncrypted = ['encryptionKey', 'secretKey', 'title']

exports.encryptInvitation = options => {
  const distributionKey = options.distributionKey
  assert(typeof distributionKey === 'string')
  const publicKey = options.publicKey
  assert(typeof publicKey === 'string')
  const encryptionKey = options.encryptionKey
  assert(typeof encryptionKey === 'string')

  const returned = { distributionKey, publicKey }
  invitationEncrypted.forEach(encryptProperty)
  return returned

  function encryptProperty (key) {
    if (!has(options, key)) return
    const encryptFunction = key === 'title'
      ? exports.encryptString
      : exports.encryptBinary
    const nonce = exports.nonce()
    returned[key] = {
      ciphertext: encryptFunction({
        plaintext: options[key],
        nonce,
        key: encryptionKey
      }),
      nonce
    }
  }
}

exports.decryptInvitation = options => {
  const invitation = options.invitation
  assert(typeof invitation === 'object')
  const encryptionKey = options.encryptionKey
  assert(typeof encryptionKey === 'string')

  const returned = {
    distributionKey: invitation.distributionKey,
    publicKey: invitation.publicKey
  }
  invitationEncrypted.forEach(decryptProperty)
  return returned

  function decryptProperty (key) {
    if (!has(invitation, key)) return
    const decryptMethod = key === 'title'
      ? exports.decryptString
      : exports.decryptBinary
    returned[key] = decryptMethod({
      ciphertext: invitation[key].ciphertext,
      nonce: invitation[key].nonce,
      key: encryptionKey
    })
  }
}

// Encoding

exports.base64ToHex = base64 => {
  return Buffer.from(base64, 'base64').toString('hex')
}

exports.hexToBase64 = base64 => {
  return Buffer.from(base64, 'hex').toString('base64')
}
