
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
    Permission.recover(encryptedPermission, decryptionKey, function (err, decryptedPermission) {
      if (err) throw err

      decryptedPermission.build(function(err) {
        if (err) throw err

        t.ok(bufferEqual(encryptionKey, decryptionKey))
        t.deepEqual(decryptedPermission.body(), permission.body())
      })
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

    var decryptionKey = utils.sharedEncryptionKey(key2.d, key1.pub);

    // #3
    utils.decryptAsync({
      data: encryptedPermissionKey,
      key: decryptionKey
    }, function (err, permissionKey) {
      t.ok(bufferEqual(permission.key(), permissionKey));
    })

    var permissionData = permission.data();
    Permission.recover(permissionData, decryptionKey, function (err, parsedPermission) {
      if (err) throw err

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
})
