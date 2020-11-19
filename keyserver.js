// This module exports a protocol implementation for deriving and
// serving encryption keys.

const assert = require('assert')
const sodium = require('sodium-universal')

// Configure a protocol implementation with sodium primitives.
module.exports = protocol({
  clientStretch: ({ password, salt }) => {
    const returned = Buffer.alloc(32)
    sodium.crypto_pwhash(
      returned, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    )
    return returned
  },

  serverStretchSaltLength: sodium.crypto_pwhash_SALTBYTES,

  serverStretch: ({ password, salt }) => {
    const returned = Buffer.alloc(32)
    sodium.crypto_pwhash(
      returned, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    )
    return returned
  },

  authenticationToken: {
    subkey: 1,
    context: Buffer.from('authTokn')
  },

  verificationHash: {
    subkey: 2,
    context: Buffer.from('verifHsh')
  },

  serverWrappingKey: {
    subkey: 3,
    context: Buffer.from('serverKy')
  },

  clientWrappingKey: {
    subkey: 4,
    context: Buffer.from('clientKy')
  },

  requestAuthenticationKey: {
    subkey: 5,
    context: Buffer.from('reqAthKy')
  },

  responseAuthenticationKey: {
    subkey: 6,
    context: Buffer.from('resAthKy')
  },

  responseEncryptionKey: {
    subkey: 7,
    context: Buffer.from('resEncKy')
  },

  keyRequestToken: {
    subkey: 8,
    context: Buffer.from('kyReqTkn')
  },

  tokenID: {
    subkey: 9,
    context: Buffer.from('token-ID')
  },

  deriveKey: ({ key, subkey, context, length = 32 }) => {
    const returned = Buffer.alloc(length)
    assert(returned.length >= sodium.crypto_kdf_BYTES_MIN)
    assert(returned.length <= sodium.crypto_kdf_BYTES_MAX)
    assert(context.length === sodium.crypto_kdf_CONTEXTBYTES)
    assert(key.length === sodium.crypto_kdf_KEYBYTES)
    sodium.crypto_kdf_derive_from_key(
      returned, subkey, context, key
    )
    return returned
  },

  authenticate: ({ key, input }) => {
    const returned = Buffer.alloc(sodium.crypto_auth_BYTES)
    sodium.crypto_auth(returned, input, key)
    return returned
  },

  random,

  generateUserID: () => random(32),

  generateToken: () => random(32)
})

function protocol ({
  clientStretch,
  serverStretch,
  serverStretchSaltLength,
  deriveKey,
  authenticate,
  random,
  generateUserID,
  verificationHash,
  authenticationToken: authenticationTokenParameters,
  clientWrappingKey: clientWrappingKeyParameters,
  serverWrappingKey: serverWrappingKeyParameters,
  verificationHash: verificationHashParameters,
  responseAuthenticationKey: responseAuthenticationKeyParameters,
  responseEncryptionKey: responseEncryptionKeyParameters,
  requestAuthenticationKey: requestAuthenticationKeyParameters,
  keyRequestToken: keyRequestTokenParameters,
  tokenID: tokenIDParameters
}) {
  // Cryptographic Primitives
  assert(typeof clientStretch === 'function')
  assert(typeof serverStretch === 'function')
  assert(Number.isInteger(serverStretchSaltLength))
  assert(serverStretchSaltLength > 0)
  assert(typeof deriveKey === 'function')
  assert(typeof authenticate === 'function')
  assert(typeof random === 'function')
  assert(typeof generateUserID === 'function')

  // Key Derivation Parameters
  assert(typeof verificationHashParameters === 'object')
  assert(typeof authenticationTokenParameters === 'object')
  assert(typeof clientWrappingKeyParameters === 'object')
  assert(typeof serverWrappingKeyParameters === 'object')
  assert(typeof responseAuthenticationKeyParameters === 'object')
  assert(typeof responseEncryptionKeyParameters === 'object')
  assert(typeof requestAuthenticationKeyParameters === 'object')
  assert(typeof keyRequestTokenParameters === 'object')
  assert(typeof tokenIDParameters === 'object')

  // API
  return {
    client: {
      login: clientLogin,
      request: clientRequest
    },
    server: {
      register: serverRegister,
      login: serverLogin,
      request: serverRequest
    }
  }

  function clientLogin ({ password, email }) {
    assert(typeof password === 'string')
    assert(password.length > 0)
    const passwordBuffer = Buffer.from(password, 'utf8')

    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)
    const emailBuffer = Buffer.from(email, 'utf8')

    const clientStretchedPassword = clientStretch({
      password: passwordBuffer,
      salt: emailBuffer
    })
    const authenticationToken = deriveKeyHelper(
      clientStretchedPassword, authenticationTokenParameters
    )

    return {
      authenticationToken,
      clientStretchedPassword
    }
  }

  function serverRegister ({
    clientStretchedPassword,
    authenticationToken
  }) {
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(clientStretchedPassword.byteLength > 0)

    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    const authenticationSalt = random(serverStretchSaltLength)
    const serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })
    const verificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )
    const serverWrappedEncryptionKey = random(32)
    const userID = generateUserID()

    return {
      authenticationSalt,
      userID,
      serverWrappedEncryptionKey,
      verificationHash,
      serverStretchedPassword
    }
  }

  function serverLogin ({
    authenticationToken,
    authenticationSalt,
    verificationHash
  }) {
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    assert(Buffer.isBuffer(authenticationSalt))
    assert(authenticationSalt.byteLength > 0)

    assert(Buffer.isBuffer(verificationHash))
    assert(verificationHash.byteLength > 0)

    const serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    const computedVerificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )

    return verificationHash.equals(computedVerificationHash)
  }

  function serverRequest ({
    serverStretchedPassword,
    serverWrappedEncryptionKey,
    keyAccessToken
  }) {
    assert(Buffer.isBuffer(serverStretchedPassword))
    assert(serverStretchedPassword.byteLength > 0)

    assert(Buffer.isBuffer(serverWrappedEncryptionKey))
    assert(serverWrappedEncryptionKey.byteLength > 0)

    assert(Buffer.isBuffer(keyAccessToken))
    assert(keyAccessToken.byteLength > 0)

    const parameters = { key: serverStretchedPassword }
    Object.assign(parameters, serverWrappingKeyParameters)
    const serverWrappingKey = deriveKeyHelper(
      serverStretchedPassword, serverWrappingKeyParameters
    )
    const clientWrappedEncryptionKey = xor(serverWrappingKey, serverWrappedEncryptionKey)

    const tokenID = deriveKeyHelper(
      keyAccessToken, tokenIDParameters
    )
    const requestAuthenticationKey = deriveKeyHelper(
      keyAccessToken, requestAuthenticationKeyParameters
    )
    const keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    const responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )
    const responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )

    const ciphertext = xor(clientWrappedEncryptionKey, responseEncryptionKey)
    const mac = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    return {
      ciphertext,
      mac,
      requestAuthenticationKey,
      tokenID
    }
  }

  function clientRequest ({
    ciphertext,
    mac,
    clientStretchedPassword,
    keyAccessToken
  }) {
    assert(Buffer.isBuffer(ciphertext))
    assert(Buffer.isBuffer(mac))
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(Buffer.isBuffer(keyAccessToken))

    const keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    const responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )
    const responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )

    const computedMAC = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    if (!mac.equals(computedMAC)) return false

    const clientWrappedEncryptionKey = xor(ciphertext, responseEncryptionKey)

    const clientWrappingKey = deriveKeyHelper(
      clientStretchedPassword, clientWrappingKeyParameters
    )

    const encryptionKey = xor(clientWrappedEncryptionKey, clientWrappingKey)

    return { encryptionKey }
  }

  function deriveKeyHelper (key, parameters) {
    assert(Buffer.isBuffer(key))
    assert(typeof parameters === 'object')
    return deriveKey(Object.assign({ key }, parameters))
  }
}

function xor (a, b) {
  assert(a.length === b.length)
  const returned = Buffer.alloc(a.length)
  for (let offset = 0; offset < a.length; offset++) {
    returned[offset] = a[offset] ^ b[offset]
  }
  return returned
}

function random (size) {
  const returned = Buffer.alloc(size)
  sodium.randombytes_buf(returned)
  return returned
}
