'use strict'

const TokenError = require('./error')
const createDecoder = require('./decoder')
const createVerifier = require('./verifier')
const createSigner = require('./signer')
const { supportsWorkers, startWorkers, stopWorkers } = require('./workers')

module.exports = {
  TokenError,
  createDecoder,
  createVerifier,
  createSigner,
  supportsWorkers,
  startWorkers,
  stopWorkers
}
