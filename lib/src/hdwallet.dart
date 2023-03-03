// ignore_for_file: constant_identifier_names
import 'dart:typed_data';

import 'package:hd_wallet_kit/src/hdkey.dart';
import 'package:hd_wallet_kit/src/hdkeychain.dart';
import 'package:hd_wallet_kit/src/hdpublickey.dart';

enum Purpose {
  BIP44(44),
  BIP49(49),
  BIP84(84);

  final int value;
  const Purpose(this.value);
}

class HDWallet {
  late final HDKeychain _hdKeychain;

  /// Create HDWallet using Uint8List seed.
  HDWallet.fromSeed({required Uint8List seed}) {
    _hdKeychain = HDKeychain.fromSeed(seed);
  }

  /// Create HDWallet using HDkey.
  HDWallet.fromKey(HDKey masterKey) {
    _hdKeychain = HDKeychain(masterKey);
  }

  /// Get the public key of the HDWallet.
  HDPublicKey getPublicKey({
    required Purpose purpose,
    required int coinType,
    required int account,
    required int change,
    required int index,
  }) {
    return HDPublicKey(deriveKey(
      purpose: purpose,
      coinType: coinType,
      account: account,
      change: change,
      index: index,
    ));
  }

  /// Child key derivation using m / purpose' / coin_type' / account' / change / index .
  HDKey deriveKey({
    required Purpose purpose,
    required int coinType,
    required int account,
    required int change,
    required int index,
  }) {
    return deriveKeyByPath(
        path: "m/${purpose.value}'/$coinType'/$account'/$change/$index");
  }

  /// Child key derivation using path.
  HDKey deriveKeyByPath({required String path}) {
    return _hdKeychain.getKeyByPath(path);
  }
}
