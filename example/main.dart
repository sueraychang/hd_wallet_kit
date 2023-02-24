import 'package:base58check/base58check.dart';
import 'package:hd_wallet_kit/hd_wallet_kit.dart';
import 'package:hd_wallet_kit/src/hdextendedkeyversion.dart';
import 'package:hd_wallet_kit/utils.dart';

main() {
  final mnemonic = Mnemonic.generate();
  print('Generated mnemonic: ${mnemonic.join(' ')}');

  final seed = Mnemonic.toSeed(mnemonic);
  print('Mnemonic to seed: ${uint8ListToHexString(seed)}');

  final hdWallet = HDWallet.fromSeed(seed: seed);
  final rootKey = hdWallet.getPrivateKeyByPath(path: 'm');

  print(
      'bip32 extended privKey: ${rootKey.serializePrivate(HDExtendedKeyVersion.xprv.value)}');

  print(
      'bip32 extended pubKey: ${rootKey.serializePublic(HDExtendedKeyVersion.xpub.value)}');

  final bip44Key = hdWallet.getPrivateKeyByPath(path: "m/44'/0'/0'");

  print(
      'bip44 account0 extended privKey: ${bip44Key.serializePrivate(HDExtendedKeyVersion.xprv.value)}');

  print(
      'bip44 account0 extended pubKey: ${bip44Key.serializePublic(HDExtendedKeyVersion.xpub.value)}');

  final address0Key = hdWallet.getPrivateKey(
      purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 0);

  print(
      'address0: ${base58checkCodec.encode(Base58CheckPayload(0, address0Key.pubKeyHash))}');

  final address1Key = hdWallet.getPrivateKey(
      purpose: Purpose.BIP44, coinType: 0, account: 0, change: 0, index: 1);

  print(
      'address1: ${base58checkCodec.encode(Base58CheckPayload(0, address1Key.pubKeyHash))}');
}
