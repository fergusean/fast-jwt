'use strict'

const Benchmark = require('benchmark')
const { sign: jsonwebtokenSignSync, verify: jsonwebtokenVerifySync } = require('jsonwebtoken')
const { readFileSync } = require('fs')
const { cpus } = require('os')
const { resolve } = require('path')
const { promisify } = require('util')
const { log, saveLogs } = require('./utils')
const { createSigner, createVerifier, startWorkers, stopWorkers } = require('../src')

const jsonwebtokenSign = promisify(jsonwebtokenSignSync)
const jsonwebtokenVerify = promisify(jsonwebtokenVerifySync)

async function compareSigning(payload, algorithm, privateKey, publicKey) {
  const asyncPrivateKey = async () => privateKey
  const asyncPublicKey = async () => publicKey
  const callbackPublicKey = (header, callback) => callback(null, publicKey)

  const fastjwtSign = createSigner({ algorithm, secret: asyncPrivateKey })
  const fastjwtSignWorkers = createSigner({ algorithm, secret: asyncPrivateKey, useWorkers: true })
  const fastjwtVerify = createVerifier({ secret: asyncPublicKey })
  const fastjwtVerifyWorkers = createVerifier({ secret: asyncPublicKey, useWorkers: true })

  const fastjwtGenerated = await fastjwtSign(payload)
  const fastjwtWorkersGenerated = await fastjwtSignWorkers(payload)
  const jsonwebtokenGenerated = await jsonwebtokenSign(payload, privateKey, { algorithm })

  if ((process.env.NODE_DEBUG || '').includes('fast-jwt')) {
    log('-------')
    log(`Generated ${algorithm} tokens (equal=${jsonwebtokenGenerated === fastjwtGenerated}):`)
    log(`        fastjwt: ${fastjwtGenerated}`)
    log(`fastjwt+workers: ${fastjwtWorkersGenerated}`)
    log(`   jsonwebtoken: ${jsonwebtokenGenerated}`)
    log('Generated tokens verification:')
    log(`        fastjwt: ${JSON.stringify(await fastjwtVerify(fastjwtGenerated))}`)
    log(`fastjwt+workers: ${JSON.stringify(await fastjwtVerifyWorkers(fastjwtWorkersGenerated))}`)
    log(`   jsonwebtoken: ${JSON.stringify(await jsonwebtokenVerify(jsonwebtokenGenerated, callbackPublicKey))}`)
    log('-------')
  }

  let promiseResolve, promiseReject

  const promise = new Promise((resolve, reject) => {
    promiseResolve = resolve
    promiseReject = reject
  })

  const jobsNum = cpus().length * 20
  const suite = new Benchmark.Suite()

  suite
    .add(`${algorithm} - sign - fast-jwt (async)`, {
      defer: true,
      fn(deferred) {
        Promise.all(Array.from(Array(jobsNum)).map(() => fastjwtSign(payload))).then(() => deferred.resolve())
      }
    })
    .add(`${algorithm} - sign - fast-jwt (workers)`, {
      defer: true,
      fn(deferred) {
        Promise.all(Array.from(Array(jobsNum)).map(() => fastjwtSignWorkers(payload))).then(() => deferred.resolve())
      }
    })
    .add(`${algorithm} - sign - jsonwebtoken (async)`, {
      defer: true,
      fn(deferred) {
        Promise.all(
          Array.from(Array(jobsNum)).map(() => jsonwebtokenSign(payload, privateKey, { algorithm }))
        ).then(() => deferred.resolve())
      }
    })
    .on('cycle', function(event) {
      log(`Executed: ${event.target}`)
    })
    .on('complete', async function() {
      const fastest = this.filter('fastest')
        .map(i => i.name.split(' - ').pop())
        .join(' OR ')
      log(`Fastest ${algorithm} sign implementation is: ${fastest}\n`)
      promiseResolve()
    })
    .on('error', promiseReject)
    .run({ async: true })

  return promise
}

const esPrivateKey = readFileSync(resolve(__dirname, './keys/es-private.key'))
const rsPrivateKey = readFileSync(resolve(__dirname, './keys/rs-private.key'))
const psPrivateKey = readFileSync(resolve(__dirname, './keys/ps-private.key'))
const esPublicKey = readFileSync(resolve(__dirname, './keys/es-public.key'))
const rsPublicKey = readFileSync(resolve(__dirname, './keys/rs-public.key'))
const psPublicKey = readFileSync(resolve(__dirname, './keys/ps-public.key'))

async function runSuites() {
  startWorkers()

  await compareSigning({ a: 1, b: 2, c: 3 }, 'HS512', 'secretsecretsecret', 'secretsecretsecret')
  await compareSigning({ a: 1, b: 2, c: 3 }, 'ES512', esPrivateKey, esPublicKey)
  await compareSigning({ a: 1, b: 2, c: 3 }, 'RS512', rsPrivateKey, rsPublicKey)
  await compareSigning({ a: 1, b: 2, c: 3 }, 'PS512', psPrivateKey, psPublicKey)

  await stopWorkers()
  await saveLogs('workers')
}

runSuites().catch(console.error)
