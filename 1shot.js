'use strict'
var createHmac = require('crypto').createHmac

module.exports = function hmac1shot (alg, key, data) {
  return createHmac(alg, key).update(data).digest()
}
