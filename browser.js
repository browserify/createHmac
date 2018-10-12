'use strict'
var inherits = require('inherits')
var Base = require('cipher-base')
var Buffer = require('safe-buffer').Buffer
var createHash = require('create-hash')

var ZEROS = Buffer.alloc(128)

function Hmac (alg, key) {
  Base.call(this, 'digest')
  if (typeof key === 'string') {
    key = Buffer.from(key)
  }

  var blocksize = (alg === 'sha512' || alg === 'sha384') ? 128 : 64

  if (key.length > blocksize) {
    var hash = createHash(alg)
    key = hash.update(key).digest()
  }
  if (key.length < blocksize) {
    key = Buffer.concat([key, ZEROS], blocksize)
  }

  var ipad = Buffer.allocUnsafe(blocksize)
  var opad = Buffer.allocUnsafe(blocksize)

  for (var i = 0; i < blocksize; i++) {
    ipad[i] = key[i] ^ 0x36
    opad[i] = key[i] ^ 0x5C
  }

  this._ihash = createHash(alg)
  this._ohash = createHash(alg)
  this._ihash.update(ipad)
  this._ohash.update(opad)
}

inherits(Hmac, Base)

Hmac.prototype._update = function (data) {
  this._ihash.update(data)
}

Hmac.prototype._final = function () {
  return this._ohash.update(this._ihash.digest()).digest()
}

module.exports = function createHmac (alg, key) {
  return new Hmac(alg, key)
}
