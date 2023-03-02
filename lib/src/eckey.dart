// ignore_for_file: non_constant_identifier_names, constant_identifier_names

import 'dart:typed_data';

import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
import 'package:hd_wallet_kit/utils.dart';
import 'package:pointycastle/pointycastle.dart';

// ignore: implementation_imports
import 'package:pointycastle/src/utils.dart' as utils;

class ECKey {
  static final ECDomainParameters ecParams = ECDomainParameters('secp256k1');
  static final BigInt HALF_CURVE_ORDER = ecParams.n >> 1;
  static const String BITCOIN_SIGNED_MESSAGE_HEADER =
      "Bitcoin Signed Message:\n";

  // String _label = '';

  late final Uint8List _pubKey;
  Uint8List get pubKey => _pubKey;

  Uint8List? _pubKeyHash;
  Uint8List get pubKeyHash => _pubKeyHash ??= sha256Hash160(_pubKey);

  BigInt? _privKey;
  BigInt? get privKey => _privKey;
  Uint8List? get privKeyBytes =>
      _privKey != null ? utils.encodeBigIntAsUnsigned(_privKey!) : null;
  bool get hasPrivKey => _privKey != null;

  late final int _creationTime;
  int get creationTime => _creationTime;

  late final bool _isCompressed;
  bool get isCompressed => _isCompressed;

  late final bool _isChange;
  bool get isChange => _isChange;
  set setChange(bool isChange) => _isChange = isChange;

  // ECKey() {}

  ECKey.withPubKey(Uint8List pubKey) : this.withKeyPair(pubKey, null, false);

  ECKey.withPrivKey(BigInt privKey, bool compressed)
      : this.withKeyPair(null, privKey, compressed);

  ECKey.withKeyPair(Uint8List? pubKey, BigInt? privKey, bool compressed) {
    _privKey = privKey;
    if (pubKey != null) {
      _pubKey = Uint8List.fromList(pubKey);
      _isCompressed = _pubKey.length == 33;
    } else if (privKey != null) {
      _pubKey = pubKeyFromPrivKey(privKey, compressed);
      _isCompressed = compressed;
    } else {
      throw IllegalArgumentException(
          'You must provide at least a private key or a public key');
    }
    _creationTime = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  }

  static ECPoint? pubKeyPointFromPrivKey(BigInt privKey) {
    BigInt adjKey;
    if (privKey.bitLength > ecParams.n.bitLength) {
      adjKey = privKey.remainder(ecParams.n);
    } else {
      adjKey = privKey;
    }
    return ecParams.G * adjKey;
  }

  static Uint8List pubKeyFromPrivKey(BigInt privKey, bool compressed) {
    return pubKeyPointFromPrivKey(privKey)!.getEncoded(compressed);
  }
}
