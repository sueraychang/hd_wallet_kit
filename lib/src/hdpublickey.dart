import 'dart:typed_data';

import 'package:hd_wallet_kit/src/hdkey.dart';

class HDPublicKey {
  late final Uint8List publicKey;
  late final Uint8List publicKeyHash;

  HDPublicKey(HDKey key) {
    publicKey = key.pubKey;
    publicKeyHash = key.pubKeyHash;
  }
}
