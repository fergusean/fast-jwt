'use strict'

const { test } = require('tap')
const { readFileSync } = require('fs')
const { cpus } = require('os')
const { resolve } = require('path')

const { createVerifier, createSigner, supportsWorkers, startWorkers, stopWorkers } = require('../src')
const { writeBuffer, readBuffer } = require('../src/workers')

const start = Math.floor(Date.now() / 1000)
const rsPrivateKey = readFileSync(resolve(__dirname, '../benchmarks/keys/rs-private.key'))
const rsPublicKey = readFileSync(resolve(__dirname, '../benchmarks/keys/rs-public.key'))
const psPrivateKey = readFileSync(resolve(__dirname, '../benchmarks/keys/ps-private.key'))
const psPublicKey = readFileSync(resolve(__dirname, '../benchmarks/keys/ps-public.key'))
const esPrivateKey = readFileSync(resolve(__dirname, '../benchmarks/keys/es-private.key'))
const esPublicKey = readFileSync(resolve(__dirname, '../benchmarks/keys/es-public.key'))

test('shared buffer management', t => {
  const buffer = Buffer.alloc(200)
  const sizes = []

  writeBuffer(buffer, sizes, ['0', '1', undefined, '123', null])
  t.strictDeepEqual(sizes, [1, 1, 0, 3, 0])

  const elements = readBuffer(buffer, sizes, 5).map(t => (t ? t.toString() : t))
  t.strictDeepEqual(elements, ['0', '1', undefined, '123', undefined])

  t.end()
})

test('worker threads based tokens round trip with buffer secrets', async t => {
  if (!supportsWorkers) {
    return
  }

  startWorkers()
  t.teardown(stopWorkers)

  let sign
  let verify
  let token
  let verified

  sign = createSigner({ algorithm: 'HS512', secret: 'secretsecretsecret', useWorkers: true })
  verify = createVerifier({ secret: 'secretsecretsecret', complete: true, useWorkers: true })
  token = await sign({ payload: 'PAYLOAD' })
  verified = await verify(token)

  t.equal(verified.payload.payload, 'PAYLOAD')
  t.true(verified.payload.iat >= start)
  t.true(verified.payload.iat < Date.now() / 1000)

  sign = createSigner({ algorithm: 'RS512', secret: rsPrivateKey.toString('utf-8'), useWorkers: true })
  verify = createVerifier({ secret: rsPublicKey.toString('utf-8'), useWorkers: true })
  token = await sign({ payload: 'PAYLOAD' })
  verified = await verify(token)

  t.equal(verified.payload, 'PAYLOAD')
  t.true(verified.iat >= start)
  t.true(verified.iat < Date.now() / 1000)

  sign = createSigner({ algorithm: 'PS512', secret: psPrivateKey, useWorkers: true })
  verify = createVerifier({ secret: psPublicKey, useWorkers: true })
  token = await sign({ payload: 'PAYLOAD' })
  verified = await verify(token)

  t.equal(verified.payload, 'PAYLOAD')
  t.true(verified.iat >= start)
  t.true(verified.iat < Date.now() / 1000)

  // TODO: This should also be tested - For now writeBuffer and readBuffer only support serializing strings
  // sign = createSigner({ algorithm: 'ES512', secret: { key: esPrivateKey, passphrase: '' }, useWorkers: true })
  // verify = createVerifier({ secret: esPublicKey, useWorkers: true })
  // token = await sign({ payload: 'PAYLOAD' })
  // verified = await verify(token)

  // t.equal(verified.payload, 'PAYLOAD')
  // t.true(verified.iat >= start)
  // t.true(verified.iat < Date.now() / 1000)

  // sign = createSigner({
  //   algorithm: 'ES512',
  //   secret: { key: esPrivateKey.toString('utf-8'), passphrase: Buffer.from('') },
  //   useWorkers: true
  // })
  // verify = createVerifier({ secret: esPublicKey, useWorkers: true })
  // token = await sign({ payload: 'PAYLOAD' })
  // verified = await verify(token)

  // t.equal(verified.payload, 'PAYLOAD')
  // t.true(verified.iat >= start)
  // t.true(verified.iat < Date.now() / 1000)

  await t.rejects(
    createSigner({
      algorithm: 'RS512',
      secret: '-----BEGIN RSA PRIVATE KEY-----NONE-----END RSA PRIVATE KEY-----',
      useWorkers: true
    })({ payload: 'PAYLOAD' }),
    {
      message: 'Cannot create the signature.'
    }
  )

  await t.rejects(
    createVerifier({ secret: '-----BEGIN PUBLIC KEY-----NONE-----END PUBLIC KEY-----', useWorkers: true })(
      'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiUEFZTE9BRCIsImlhdCI6MTU3OTI2MDYzMH0.lbQwm3hZK0Wj4y52i1KMP0NRZ8Ruu0znifQffoGXqQuMJkqXCXBsDnLlFRhNU3GbfCfjtX52vNRqerse4AWfjY3wV1Po6zPiuewXyWzWqu9QY0oQG-qT1P2c2Q_u_eOJmXFZwiHq8MOn4Vi1jwFxZ_TSNkNHFRJ3vKVCEuXECtehpeP83IMXlUrRaTy_Wl0NZ2DtbUz4QyfehrWOWdB1AjBwTuNbiaVLpX4GJCkCJSUM5iF-NZgrcKjj_DjRMiQRUKVHK64OtegZkM5AId1U9hbGdY7Tujd7Vdx-yazP5tdcCQYHp0woZBWQWNZw_4Fn-mqIis6PjHgJdamFeTYTHYxRB5DwjdLCDrjUsh3Wi3I59APxfmL1zACGcNSPmeAqW4caE73lWOMQec7H60FVoVt_BAylDle2osJXsKkMQj_rNFo_Lky7VAURwAS3-0_Rxm9DuYwg1ZH1IEK3INfJ5I2QVmLkfO_4T96uDGyUOGqZ4DvPcTUbLAVp_kgCBkLHtk178oKMmbg8yYYoJnaNkRRFo-Z6HZD-8-OBDbjnrrgf8GiJUkgqO1tDETGTnX7U-2eotPcVsiuruwRIRRfoYP9j_zIEMP9NoUoXrdcwQRVrTIg8RAweEMtcc1uMM5P13RHNVbFZkXjS35tuvlTyvJFzA4_uY6t-ZvDq_EdDrBI'
    ),
    { message: 'Cannot verify the signature.' }
  )

  await t.rejects(
    createVerifier({ secret: rsPublicKey, useWorkers: true })(
      'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiUEFZTE9BRCIsImlhdCI6MTU3OTI2MDYzMH0.aa'
    ),
    { message: 'The token signature is invalid.' }
  )
})

test('signing and verifying should work with useWorkers even if workers have not been started', async t => {
  const sign = createSigner({ algorithm: 'HS512', secret: 'secretsecretsecret', useWorkers: true })
  const verify = createVerifier({ secret: 'secretsecretsecret', complete: true, useWorkers: true })
  const token = await sign({ payload: 'PAYLOAD' })
  const verified = await verify(token)

  t.equal(verified.payload.payload, 'PAYLOAD')
  t.true(verified.payload.iat >= start)
  t.true(verified.payload.iat < Date.now() / 1000)
})

test('worker threads should work even if all workers are busy', async t => {
  if (!supportsWorkers) {
    return
  }

  const jobsNum = cpus().length * 20

  const sign = createSigner({ algorithm: 'HS512', secret: 'secretsecretsecret', useWorkers: true })
  const verify = createVerifier({ secret: 'secretsecretsecret', complete: true, useWorkers: true })

  startWorkers()
  startWorkers() // This is to prove workers cannot be started twice

  // Verify successful operations
  const signed = await Promise.all(Array.from(Array(jobsNum)).map(() => sign({ payload: 'PAYLOAD' })))
  const verified = await Promise.all(signed.map(verify))

  const payloadsSet = new Set()
  const iatsSet = new Set()

  for (const v of verified) {
    payloadsSet.add(v.payload.payload)
    iatsSet.add(v.payload.iat)
  }

  const iats = Array.from(iatsSet.values()).sort()
  const payloads = Array.from(payloadsSet.values()).sort()

  t.strictDeepEqual(payloads, ['PAYLOAD'])
  t.true(iats[0] >= start)
  t.true(iats[iats.length - 1] <= Date.now() / 1000)

  let signFailures = 0
  let verifyFailures = 0

  // Verify failures operations
  await Promise.all(
    Array.from(Array(jobsNum)).map(() => {
      return createSigner({
        algorithm: 'RS512',
        secret: '-----BEGIN RSA PRIVATE KEY-----NONE-----END RSA PRIVATE KEY-----',
        useWorkers: true
      })({ payload: 'PAYLOAD' }).catch(() => signFailures++)
    })
  )

  await Promise.all(
    Array.from(Array(jobsNum)).map(() => {
      return createVerifier({ secret: '-----BEGIN PUBLIC KEY-----NONE-----END PUBLIC KEY-----', useWorkers: true })(
        'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXlsb2FkIjoiUEFZTE9BRCIsImlhdCI6MTU3OTI2MDYzMH0.lbQwm3hZK0Wj4y52i1KMP0NRZ8Ruu0znifQffoGXqQuMJkqXCXBsDnLlFRhNU3GbfCfjtX52vNRqerse4AWfjY3wV1Po6zPiuewXyWzWqu9QY0oQG-qT1P2c2Q_u_eOJmXFZwiHq8MOn4Vi1jwFxZ_TSNkNHFRJ3vKVCEuXECtehpeP83IMXlUrRaTy_Wl0NZ2DtbUz4QyfehrWOWdB1AjBwTuNbiaVLpX4GJCkCJSUM5iF-NZgrcKjj_DjRMiQRUKVHK64OtegZkM5AId1U9hbGdY7Tujd7Vdx-yazP5tdcCQYHp0woZBWQWNZw_4Fn-mqIis6PjHgJdamFeTYTHYxRB5DwjdLCDrjUsh3Wi3I59APxfmL1zACGcNSPmeAqW4caE73lWOMQec7H60FVoVt_BAylDle2osJXsKkMQj_rNFo_Lky7VAURwAS3-0_Rxm9DuYwg1ZH1IEK3INfJ5I2QVmLkfO_4T96uDGyUOGqZ4DvPcTUbLAVp_kgCBkLHtk178oKMmbg8yYYoJnaNkRRFo-Z6HZD-8-OBDbjnrrgf8GiJUkgqO1tDETGTnX7U-2eotPcVsiuruwRIRRfoYP9j_zIEMP9NoUoXrdcwQRVrTIg8RAweEMtcc1uMM5P13RHNVbFZkXjS35tuvlTyvJFzA4_uY6t-ZvDq_EdDrBI'
      ).catch(() => verifyFailures++)
    })
  )

  t.is(signFailures, jobsNum)
  t.is(verifyFailures, jobsNum)

  t.teardown(() => {
    // This is to prove workers cannot be stopped twice
    return new Promise((resolve, reject) => {
      stopWorkers(resolve)
    }).then(stopWorkers)
  })
})
