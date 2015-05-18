
var crypto = require('crypto')
var test = require('tape')
var ECKey = require('bitcoinjs-lib').ECKey
var utils = require('tradle-utils')
var bufferEqual = require('buffer-equal')
var Permission = require('../')

test('permission file', function(t) {
  t.plan(2)

  var key1 = ECKey.makeRandom()
  var key2 = ECKey.makeRandom()

  var fileHash = crypto.randomBytes(40)
  var fileKey = crypto.randomBytes(32)

  var permission = new Permission(fileHash, fileKey)
  var encryptionKey = utils.sharedEncryptionKey(key1.d, key2.pub)
  var decryptionKey
  var decryptedPermission
  permission.encrypt(encryptionKey)

  permission.build(function(err) {
    if (err) throw err

    var encryptedPermission = permission.data()
    decryptionKey = utils.sharedEncryptionKey(key2.d, key1.pub)
    decryptedPermission = Permission.recover(encryptedPermission, decryptionKey)

    decryptedPermission.build(function(err) {
      if (err) throw err

      t.ok(bufferEqual(encryptionKey, decryptionKey))
      t.deepEqual(decryptedPermission.body(), permission.body())
    })
  })
})
