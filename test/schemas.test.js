const AJV = require('ajv')
const crypto = require('../crypto')
const schemas = require('../schemas')
const tape = require('tape')

Object.keys(schemas).forEach(id => {
  tape(id, test => {
    const ajv = new AJV()
    ajv.validateSchema(schemas[id])
    test.deepEqual(ajv.errors, null, 'valid schema')
    test.end()
  })
})

tape('intro', test => {
  const intro = {
    discoveryKey: crypto.discoveryKey(crypto.distributionKey()),
    type: 'intro',
    name: 'Kyle E. Mitchell',
    device: 'laptop',
    timestamp: new Date().toISOString(),
    index: 0
  }
  test.same(
    schemas.validate.intro(intro),
    { valid: true, errors: [] }
  )
  test.end()
})
