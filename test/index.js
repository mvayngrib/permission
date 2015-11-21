
var crypto = require('crypto')
var test = require('tape')
var ECKey = require('@tradle/bitcoinjs-lib').ECKey
var utils = require('@tradle/utils')
var bufferEqual = require('buffer-equal')
var TxData = require('@tradle/tx-data').TxData
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

test('permission file + transaction construction, reconstruction', function(t) {
  t.plan(6);

  var prefix = 'blah';
  var key1 = ECKey.makeRandom();
  var key2 = ECKey.makeRandom();

  var fileHash = crypto.randomBytes(40);
  var fileKey = crypto.randomBytes(32);

  var permission = new Permission(fileHash, fileKey);
  var parsedPermission
  var encryptionKey = utils.sharedEncryptionKey(key1.d, key2.pub);
  permission.encrypt(encryptionKey);

  permission.build(function(err) {
    if (err) throw err

    var typeCode = TxData.types.permission;
    var encryptedPermissionKey = permission.encryptedKey();

    var tData = new TxData(prefix, typeCode, encryptedPermissionKey);
    var serialized = tData.serialize();
    var deserialized = TxData.deserialize(serialized, prefix);

    // #1
    t.equal(typeCode, deserialized.type());

    var parsedPermissionKey = deserialized.data();

    // #2
    t.ok(bufferEqual(parsedPermissionKey, encryptedPermissionKey));
    // #3

    var decryptionKey = utils.sharedEncryptionKey(key2.d, key1.pub);
    t.ok(bufferEqual(permission.key(), utils.decrypt(encryptedPermissionKey, decryptionKey)));

    var permissionData = permission.data();
    parsedPermission = Permission.recover(permissionData, decryptionKey);

    parsedPermission.build(function(err) {
      if (err) throw err

      // #4
      t.deepEqual(parsedPermission.body(), permission.body());
      // #5
      t.ok(bufferEqual(fileHash, parsedPermission.fileKeyBuf()));
      // #6
      t.ok(bufferEqual(fileKey, parsedPermission.decryptionKeyBuf()));
    })
  })
})
