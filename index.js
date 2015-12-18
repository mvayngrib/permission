'use strict';

var utils = require('@tradle/utils');
var assert = require('assert');
var ENCODING = 'base64'

function Permission(key, symmetricKey) {
  var symmetricKeyStr;

  if (typeof symmetricKey === 'undefined' || symmetricKey === null)
    symmetricKeyStr = null;
  else if (typeof symmetricKey !== 'string')
    symmetricKeyStr = symmetricKey.toString('base64');
  else
    symmetricKeyStr = symmetricKey;

  this._body = {
    key: key.toString('hex'),
    decryptionKey: symmetricKeyStr
  }

  this._cleartext = new Buffer(JSON.stringify(this._body));
}

Permission.prototype.encrypt = function(encryptionKey) {
  this._encryptionKey = encryptionKey;
  this._encryptBody = true;
  this._encryptKey = true;
}

Permission.prototype.encryptKey = function(encryptionKey) {
  this._encryptionKey = encryptionKey;
  this._encryptKey = true;
}

Permission.prototype.build = function(cb) {
  var self = this;

  if (this._encryptBody) {
    utils.encryptAsync({
      data: this._cleartext,
      key: this._encryptionKey
    }, function (err, cipherbuf) {
      if (err) return cb(err)

      self._cipherbuf = cipherbuf
      utils.getStorageKeyFor(self._cipherbuf, finish)
    })
  } else {
    utils.getStorageKeyFor(this._cleartext, finish)
  }

  function finish(err, key) {
    if (err) return cb(err)

    self._key = key;
    if (self._encryptKey) {
      utils.encryptAsync({
        data: self._key,
        key: self._encryptionKey
      }, function (err, encryptedKey) {
        if (err) return cb(err)

        self._encryptedKey = encryptedKey
        cb()
      });
    } else {
      cb()
    }
  }
}

Permission.prototype.key = function() {
  return this._key;
}

Permission.prototype.encryptedKey = function() {
  return this._encryptedKey;
}

Permission.prototype.data = function() {
  return this._cipherbuf || this._cleartext;
}

Permission.prototype.body = function() {
  var copy = {};
  for (var p in this._body) {
    copy[p] = this._body[p];
  }

  return copy;
}

Permission.prototype.fileKeyString = function() {
  return this._body.key.toString('hex')
}

Permission.prototype.fileKeyBuf = function() {
  return new Buffer(this._body.key, 'hex');
}

Permission.prototype.decryptionKeyString = function() {
  return this._body.decryptionKey;
}

Permission.prototype.decryptionKeyBuf = function() {
  var dKey = this._body.decryptionKey;
  if (dKey === null) return dKey;

  return new Buffer(dKey, ENCODING)
}

// Permission.decryptKey = function(myPrivKey, theirPubKey, encryptedKey) {
//   var permissionEncryptionKey = utils.sharedEncryptionKey(myPrivKey, theirPubKey);
//   return utils.decrypt(encryptedKey, permissionEncryptionKey);
// }

Permission.recover = function(data, encryptionKey, cb) {
  if (typeof data === 'string') data = new Buffer(data);

  // var permissionEncryptionKey = utils.sharedEncryptionKey(myPrivKey, theirPubKey);
  if (encryptionKey) {
    utils.decryptAsync({
      data: data,
      key: encryptionKey
    }, function (err, decrypted) {
      data = decrypted
      finish()
    });
  } else {
    finish()
  }

  function finish () {
    var json = data.toString();
    var body;
    try {
      body = JSON.parse(json);
    } catch (err) {
      cb(new Error('Permission body is not valid json'))
    }

    assert('key' in body && 'decryptionKey' in body, 'Invalid permission contents');
    cb(null, new Permission(body.key, body.decryptionKey))
  }
}

module.exports = Permission;
