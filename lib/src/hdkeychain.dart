import 'dart:typed_data';

import 'package:hd_wallet_kit/src/hdkey.dart';
import 'package:hd_wallet_kit/src/hdkeyderivation.dart';

class HDKeychain {
  late final HDKey _hdKey;

  HDKeychain(HDKey hdKey) {
    _hdKey = hdKey;
  }

  HDKeychain.fromSeed(Uint8List seed) {
    _hdKey = HDKeyDerivation.createRootKey(seed);
  }

  /// Parses the BIP32 path and derives the chain of keychains accordingly.
  /// Path syntax: (m?/)?([0-9]+'?(/[0-9]+'?)*)?
  /// The following paths are valid:
  ///
  /// "" (root key)
  /// "m" (root key)
  /// "/" (root key)
  /// "m/0'" (hardened child #0 of the root key)
  /// "/0'" (hardened child #0 of the root key)
  /// "0'" (hardened child #0 of the root key)
  /// "m/44'/1'/2'" (BIP44 testnet account #2)
  /// "/44'/1'/2'" (BIP44 testnet account #2)
  /// "44'/1'/2'" (BIP44 testnet account #2)
  ///
  /// The following paths are invalid:
  ///
  /// "m / 0 / 1" (contains spaces)
  /// "m/b/c" (alphabetical characters instead of numerical indexes)
  /// "m/1.2^3" (contains illegal characters)
  HDKey getKeyByPath(String path) {
    HDKey key = _hdKey;

    String derivePath = path;
    if (derivePath == "m" || derivePath == "/" || derivePath == "") {
      return key;
    }
    if (derivePath.contains("m/")) {
      derivePath = derivePath.substring(2);
    }

    derivePath.split('/').forEach((element) {
      bool hardened = false;
      String indexText = element;
      if (element.contains("'")) {
        hardened = true;
        indexText = indexText.substring(0, indexText.length - 1);
      }
      final index = int.parse(indexText);
      key = HDKeyDerivation.deriveChildKey(key, index, hardened);
    });

    return key;
  }
}
