/* globals SharedArrayBuffer, Atomics */

'use strict'

const { cpus } = require('os')

const { createSignature, verifySignature } = require('./crypto')
const TokenError = require('./error')

let Worker = null
let workers = []

const cores = cpus().length
const availableWorkers = Array.from(Array(cores)).map((_, i) => i)
const requestsSharedBuffers = Array(cores)
const repliesSharedBuffers = Array(cores)
const requestsSizesArray = Array(cores)
const repliesSizesArray = Array(cores)

function writeBuffer(buffer, sizesArray, elements) {
  let i = 0
  let offset = 0
  for (const element of elements) {
    if (typeof element !== 'string' && !(element instanceof Buffer)) {
      sizesArray[i] = 0
      i++
      continue
    }

    const size = Buffer.from(element).copy(buffer, offset)
    sizesArray[i] = size
    i++
    offset += size
  }
}

function readBuffer(buffer, sizesArray, elementsCount) {
  const elements = []
  let start = 0
  let end = 0

  // Read the arguments
  for (let i = 0; i < elementsCount; i++) {
    end += sizesArray[i]
    elements.push(start !== end ? buffer.slice(start, end) : undefined)
    start += sizesArray[i]
  }

  return elements
}

function deserializeWorkerError(code, message, stack, originalCode, originalMessage, originalStack) {
  const originalError = new Error(originalMessage)
  originalError.code = originalCode
  originalError.stack = originalStack

  const error = new TokenError(code, message, { originalError })
  error.stack = stack

  return error
}

function startWorkers(size = 4096) {
  if (workers.length) {
    return
  }

  // For each worker, create a request and reply sharedArrayBuffer, used to share the data
  for (let i = 0; i < cores; i++) {
    const startSharedBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT)
    const requestSizesSharedBuffer = new SharedArrayBuffer(10 * Int32Array.BYTES_PER_ELEMENT)
    const replySizesSharedBuffer = new SharedArrayBuffer(10 * Int32Array.BYTES_PER_ELEMENT)
    const startArray = new Int32Array(startSharedBuffer)

    requestsSharedBuffers[i] = new SharedArrayBuffer(size)
    repliesSharedBuffers[i] = new SharedArrayBuffer(size)
    requestsSizesArray[i] = new Int32Array(requestSizesSharedBuffer)
    repliesSizesArray[i] = new Int32Array(replySizesSharedBuffer)

    const worker = new Worker(__filename, {
      workerData: {
        index: i,
        startSharedBuffer,
        requestSharedBuffer: requestsSharedBuffers[i],
        replySharedBuffer: repliesSharedBuffers[i],
        requestSizesSharedBuffer,
        replySizesSharedBuffer
      }
    })

    // Wait for the worker to start
    Atomics.wait(startArray, 0, 0)

    // TODO: Track workers status
    worker.on('error', console.error)
    workers.push(worker)
  }
}

function stopWorkers(callback) {
  if (!workers.length) {
    return
  }

  const promise = Promise.all(workers.map(w => w.terminate()))
  workers = []

  if (typeof callback === 'function') {
    promise.then(() => callback(), callback)
    return
  }

  return promise
}

function getAvailableWorker(callback, attempts = 3) {
  if (!workers.length) {
    return callback(null)
  }

  const worker = availableWorkers.shift()

  if (!worker && attempts > 0 && workers.length) {
    setTimeout(() => getAvailableWorker(callback, attempts - 1), Math.floor(Math.random() * 10))
    return
  }

  callback(worker)
}

/* istanbul ignore next */
function handleWorker(parentPort, data) {
  const {
    startSharedBuffer,
    requestSharedBuffer,
    requestSizesSharedBuffer,
    replySharedBuffer,
    replySizesSharedBuffer
  } = data
  const requestBuffer = Buffer.from(requestSharedBuffer)
  const replyBuffer = Buffer.from(replySharedBuffer)
  const requestSizes = new Int32Array(requestSizesSharedBuffer)
  const replySizes = new Int32Array(replySizesSharedBuffer)

  parentPort.on('message', request => {
    try {
      const [operation, algorithm, secret, headerOrInput, payloadOrSignature] = readBuffer(
        requestBuffer,
        requestSizes,
        5
      )
      let rv = null

      if (operation.toString('utf-8') === 'sign') {
        rv = createSignature(algorithm.toString('utf-8'), secret, headerOrInput, payloadOrSignature)
      } else {
        rv = verifySignature(algorithm.toString('utf-8'), secret, headerOrInput, payloadOrSignature.toString('utf-8'))
      }

      // Once done, send the reply back
      writeBuffer(replyBuffer, replySizes, [rv.toString()])

      parentPort.postMessage(0)
    } catch (e) {
      const error = TokenError.wrap(e, TokenError.codes.workerError, 'Cannot perform operation using worker.')

      writeBuffer(replyBuffer, replySizes, [
        error.code,
        error.message,
        error.stack,
        error.originalError.code || '',
        error.originalError.message,
        error.originalError.stack
      ])

      parentPort.postMessage(-1)
    }
  })

  const startArray = new Int32Array(startSharedBuffer)
  Atomics.store(startArray, 0, 1)
  Atomics.notify(startArray, 0)
}

function createSignatureWithWorker(algorithm, secret, header, payload, callback) {
  getAvailableWorker(workerIndex => {
    console.log(workerIndex)
    // Could not get a worker within the reasonable timeout, perform the operation synchronously
    if (!workerIndex) {
      try {
        callback(null, createSignature(algorithm, secret, header, payload))
      } catch (e) {
        callback(e)
      }

      return
    }

    const worker = workers[workerIndex]

    // Store the message in the buffer
    const requestBuffer = Buffer.from(requestsSharedBuffers[workerIndex])
    const replyBuffer = Buffer.from(repliesSharedBuffers[workerIndex])

    writeBuffer(requestBuffer, requestsSizesArray[workerIndex], ['sign', algorithm, secret, header, payload])

    // Prepare to receive the response
    worker.removeAllListeners('message')
    worker.on('message', response => {
      const data = readBuffer(replyBuffer, repliesSizesArray[workerIndex], response === 0 ? 1 : 6)

      // Make the worker available again
      availableWorkers.push(workerIndex)

      // In case of errors
      if (response < 0) {
        callback(deserializeWorkerError(...data.map(d => (d ? d.toString('utf-8') : null))))
        return
      }

      callback(null, Buffer.from(data[0]).toString('utf-8'))
    })

    // Send the request - Note that the content is not important
    worker.postMessage(0)
  })
}

function verifySignatureWithWorker(algorithm, secret, input, signature, callback) {
  getAvailableWorker(workerIndex => {
    // Could not get a worker within the reasonable timeout, perform the operation synchronously
    if (!workerIndex) {
      try {
        callback(null, verifySignature(algorithm, secret, input, signature))
      } catch (e) {
        callback(e)
      }

      return
    }

    const worker = workers[workerIndex]

    // Store the message in the buffer
    const requestBuffer = Buffer.from(requestsSharedBuffers[workerIndex])
    const replyBuffer = Buffer.from(repliesSharedBuffers[workerIndex])

    writeBuffer(requestBuffer, requestsSizesArray[workerIndex], ['verify', algorithm, secret, input, signature])

    // Prepare to receive the response
    worker.removeAllListeners('message')
    worker.on('message', response => {
      const data = readBuffer(replyBuffer, repliesSizesArray[workerIndex], response === 0 ? 1 : 6)

      // Make the worker available again
      availableWorkers[workerIndex] = 0

      // In case of errors
      if (response < 0) {
        callback(deserializeWorkerError(...data.map(d => (d ? d.toString('utf-8') : null))))
        return
      }

      callback(null, data[0].toString('utf-8') === 'true')
    })

    // Send the request - Note that the content is not important
    worker.postMessage(0)
  })
}

module.exports = { supportsWorkers: false, writeBuffer, readBuffer }

try {
  const { Worker: WorkerClass, isMainThread, workerData, parentPort } = require('worker_threads')

  /* istanbul ignore else */
  if (isMainThread) {
    Worker = WorkerClass

    Object.assign(module.exports, {
      supportsWorkers: true,
      startWorkers,
      stopWorkers,
      createSignatureWithWorker,
      verifySignatureWithWorker
    })
  } else {
    // Start processing jobs
    try {
      handleWorker(parentPort, workerData)
    } catch (e) {
      // TODO: Handle errors
    }
  }
} catch (e) {
  // No-op
}
