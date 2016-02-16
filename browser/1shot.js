'use strict'
var createHash = require('create-hash/browser')

var ZEROS = new Buffer(128)
ZEROS.fill(0)

module.exports = function hmac1shot (alg, key, data) {
  alg = alg.toLowerCase()
  var blocksize = (alg === 'sha512' || alg === 'sha384') ? 128 : 64

  if (key.length > blocksize) {
    key = createHash(alg).update(key).digest()
  } else if (key.length < blocksize) {
    key = Buffer.concat([ key, ZEROS ], blocksize)
  }

  var ipad = new Buffer(blocksize)
  var opad = new Buffer(blocksize)

  for (var i = 0; i < blocksize; i++) {
    ipad[i] = key[i] ^ 0x36
    opad[i] = key[i] ^ 0x5C
  }

  data = createHash(alg).update(Buffer.concat([ ipad, data ])).digest()
  return createHash(alg).update(Buffer.concat([ opad, data ])).digest()
}
