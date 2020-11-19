// This file exports JSON Schemas and validation functions.

const assert = require('assert')
const crypto = require('./crypto')

// Helper Functions

const base64Pattern = (() => {
  const chars = '[A-Za-z0-9+/]'
  return `^(${chars}{4})*(${chars}{2}==|${chars}{3}=)?$`
})()

function base64String (bytes) {
  const schema = { type: 'string', pattern: base64Pattern }
  if (bytes) {
    assert(Number.isSafeInteger(bytes))
    assert(bytes > 0)
    const length = Buffer.alloc(bytes).toString('base64').length
    schema.minLength = length
    schema.maxLength = length
  } else {
    schema.minLength = 4
  }
  return schema
}

// Helper Subschemas

const index = { type: 'integer', minimum: 0 }
const name = { type: 'string', minLength: 1, maxLength: 256 }
const timestamp = { type: 'string', format: 'date-time' }
const text = { stype: 'string', minLength: 1 }

const digest = base64String(crypto.digestBytes)
const discoveryKey = base64String(crypto.digestBytes)
const distributionKey = base64String(crypto.distributionKeyBytes)
const nonce = base64String(crypto.nonceBytes)
const publicKey = base64String(crypto.publicKeyBytes)
const signature = base64String(crypto.signatureByes)

const encrypted = {
  type: 'object',
  properties: { nonce, ciphertext: base64String() },
  required: ['nonce', 'ciphertext'],
  additionalProperties: false
}

// Log Entries

// Intros to associate a personal and device name with subsequent
// log entries.
//
// Intros serve the same role as [user] data in ~/.gitconfig.
const intro = exports.intro = {
  type: 'object',
  properties: {
    type: { const: 'intro' },
    name, // e.g. "Kyle E. Mitchell"
    device: name, // e.g. "laptop"
    timestamp
  },
  required: ['type', 'name', 'device', 'timestamp'],
  additionalProperties: false
}

// Drafts contain the content of a version of a document.
//
// Drafts work like commits in Git.
const draft = exports.draft = {
  type: 'object',
  properties: {
    type: { const: 'draft' },
    parents: {
      type: 'array',
      items: digest,
      maxItems: 2,
      uniqueItems: true
    },
    content: { type: 'object' },
    timestamp
  },
  required: ['type', 'parents', 'content', 'timestamp'],
  additionalProperties: false
}

// Marks associate a name with a draft.
//
// They can be moved from draft to draft over time.
//
// Marks work like branches and tags in Git.
const mark = exports.mark = {
  type: 'object',
  properties: {
    type: { const: 'mark' },
    identifier: base64String(4),
    name,
    timestamp,
    draft: digest
  },
  required: ['type', 'identifier', 'name', 'timestamp', 'draft'],
  additionalProperties: false
}

// Notes associate text with ranges of text within drafts.
//
// Notes work like comments in word processors.
const note = exports.note = {
  type: 'object',
  properties: {
    type: { const: 'note' },
    draft: digest,
    range: {
      type: 'object',
      properties: {
        start: { type: 'integer', minimum: 0 },
        end: { type: 'integer', minimum: 1 }
      },
      required: ['start', 'end'],
      additionalProperties: false
    },
    text,
    timestamp
  },
  required: ['type', 'draft', 'range', 'text', 'timestamp'],
  additionalProperties: false
}

// Replies associate text with notes.
const reply = exports.reply = {
  type: 'object',
  properties: {
    type: { const: 'reply' },
    draft: digest,
    parent: digest,
    text,
    timestamp
  },
  required: ['type', 'draft', 'parent', 'text', 'timestamp'],
  additionalProperties: false
}

// Corrections replace the texts of notes and replies.
//
// When users make typos or mistakes in notes or replies,
// they use corrections to fix them.
const correction = exports.correction = {
  type: 'object',
  properties: {
    type: { const: 'correction' },
    note: digest,
    text,
    timestamp
  },
  required: ['type', 'note', 'text', 'timestamp'],
  additionalProperties: false
}

const entryTypes = { intro, draft, mark, note, reply, correction }

// Add log-entry properties to each entry type schema.
Object.keys(entryTypes).forEach(key => {
  const schema = entryTypes[key]
  Object.assign(schema.properties, {
    discoveryKey,
    index,
    // The first entry in a log does not include the digest
    // of a prior entry.
    prior: digest // optional
  })
  schema.required.push('index', 'discoveryKey')
})

exports.entry = {
  type: 'object',
  oneOf: Object.values(entryTypes)
}

// Transport

// Envelopes wrap encrypted entries with signatures
// and indexing information.
exports.envelope = {
  type: 'object',
  properties: {
    discoveryKey,
    logPublicKey: publicKey,
    logSignature: signature,
    projectSignature: signature,
    index,
    prior: digest, // optional
    // The first entry in a log does not include the digest
    // of a prior entry.
    entry: encrypted
  },
  required: [
    'discoveryKey',
    'logPublicKey',
    'logSignature',
    'projectSignature',
    'index',
    'entry'
  ],
  additionalProperties: false
}

// Invitations communicate the keys needed to join a project.
//
// Users send invitations to the server, which forwards them
// to the user's other devices.
exports.invitation = {
  type: 'object',
  properties: {
    distributionKey,
    publicKey,
    secretKey: encrypted, // optional
    readKey: encrypted, // optional
    title: encrypted // optional
  },
  required: ['distributionKey', 'publicKey'],
  additionalProperties: false
}

// Export Validation Functions
const ajv = require('ajv')()
exports.validate = {}
Object.keys(exports).forEach(key => {
  const compiled = ajv.compile(exports[key])
  exports.validate[key] = data => {
    const valid = compiled(data)
    return { valid, errors: valid ? [] : compiled.errors }
  }
})
