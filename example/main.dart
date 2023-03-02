// ignore_for_file: avoid_print

import 'package:hd_wallet_kit/hd_wallet_kit.dart';
import 'package:hd_wallet_kit/utils.dart';

main() {
  final mnemonic = Mnemonic.generate();
  print('Generated mnemonic: ${mnemonic.join(' ')}');

  final seed = Mnemonic.toSeed(mnemonic);
  print('Mnemonic to seed: ${uint8ListToHexString(seed)}');

  final hdWallet = HDWallet.fromSeed(seed: seed);
  final rootKey = hdWallet.deriveKeyByPath(path: 'm');

  print(
      'bip32 extended privKey: ${rootKey.serializePrivate(HDExtendedKeyVersion.xprv)}');

  print(
      'bip32 extended pubKey: ${rootKey.serializePublic(HDExtendedKeyVersion.xpub)}');

  final bip44Key = hdWallet.deriveKeyByPath(path: "m/44'/0'/0'");

  print(
      'bip44 account0 extended privKey: ${bip44Key.serializePrivate(HDExtendedKeyVersion.xprv)}');

  print(
      'bip44 account0 extended pubKey: ${bip44Key.serializePublic(HDExtendedKeyVersion.xpub)}');

  final address0Key = hdWallet.deriveKey(
      purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 0);

  print('address0: ${address0Key.encodeAddress()}');

  final address1Key = hdWallet.deriveKey(
      purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 1);

  print('address1: ${address1Key.encodeAddress()}');
}
