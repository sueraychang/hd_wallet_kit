// ignore_for_file: constant_identifier_names
import 'dart:typed_data';

import 'package:hd_wallet_kit/src/hdkey.dart';
import 'package:hd_wallet_kit/src/hdkeychain.dart';
import 'package:hd_wallet_kit/src/hdpublickey.dart';
import 'package:meta/meta.dart';

enum Purpose {
  BIP44(44),
  BIP49(49),
  BIP84(84);

  final int value;
  const Purpose(this.value);
}

class HDWallet {
  late final HDKeychain _hdKeychain;
  late final int _coinType;
  late final Purpose _purpose;

  HDWallet.fromSeed(Uint8List seed, int coinType, Purpose purpose) {
    _hdKeychain = HDKeychain.fromSeed(seed);
    _coinType = coinType;
    _purpose = purpose;
  }

  @visibleForTesting
  HDWallet.fromKey(HDKey masterKey, int coinType, Purpose purpose) {
    _hdKeychain = HDKeychain(masterKey);
    _coinType = coinType;
    _purpose = purpose;
  }

  HDPublicKey getPublicKey(int account, int change, int index) {
    return HDPublicKey(getPrivateKey(account, change, index));
  }

  HDKey getPrivateKey(int account, int change, int index) {
    return getPrivateKeyByPath(
        "m/${_purpose.value}'/$_coinType'/$account'/$change/$index");
  }

  HDKey getPrivateKeyByPath(String path) {
    return _hdKeychain.getKeyByPath(path);
  }
}
