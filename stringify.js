// This module exports a JSON stringify function.
//
// To make sure equivalent JSON data always stringifies to
// the same, identical string, we use an implementation that
// outputs the keys of every object in sorted order. This gives
// us "content addressability", the ability to refer to a data
// record by the cryptographic digest of its canonical string
// representation.

module.exports = require('fast-json-stable-stringify')
