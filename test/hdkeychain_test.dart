import 'package:flutter_test/flutter_test.dart';
import 'package:hd_wallet_kit/src/hdkeychain.dart';
import 'package:hd_wallet_kit/utils.dart';

void main() {
  final seed = hexStringToUint8List(
      '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4');
  final hdKeyManager = HDKeychain.fromSeed(seed);

  group('hdkeychain', () {
    test('getKeyByPath BIP32', () {
      const path32 = 'm/0';
      final hdKey = hdKeyManager.getKeyByPath(path32);

      expect(hdKey.toString(), path32);
    });

    test('getKeyByPath BIP44', () {
      const path44 = "m/44'/0'/0'/0";
      final hdKey = hdKeyManager.getKeyByPath(path44);

      expect(hdKey.toString(), path44);
    });

    // test('getPublicExtendedKey BIP44', () {
    //   const path44 = "m/44'/0'/0'/0";
    //   final hdKey = hdKeyManager.getKeyByPath(path44);
    //   final base58 = hdKey.serializePublic(HDExtendedKeyVersion.xpub.value);
    //   const expected =
    //       "xpub6ELHKXNimKbxMCytPh7EdC2QXx46T9qLDJWGnTraz1H9kMMFdcduoU69wh9cxP12wDxqAAfbaESWGYt5rREsX1J8iR2TEunvzvddduAPYcY";

    //   expect(base58, expected);
    // });
  });
}
