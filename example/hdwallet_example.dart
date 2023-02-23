import 'package:base58check/base58check.dart';
import 'package:hd_wallet_kit/hd_wallet_kit.dart';
import 'package:hd_wallet_kit/src/hdextendedkeyversion.dart';
import 'package:hd_wallet_kit/utils.dart';

main() {
  final mnemonic =
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
          .split(' ');
  final seed = Mnemonic.toSeed(mnemonic);

  final hdWallet = HDWallet.fromSeed(seed, 0, Purpose.BIP44);
  final rootKey = hdWallet.getPrivateKeyByPath('m');

  print('bip32 extended privKey: ${rootKey.serializePrivate(HDExtendedKeyVersion.xprv.value)}');

  print('bip32 extended pubKey: ${rootKey.serializePublic(HDExtendedKeyVersion.xpub.value)}');

  final bip44Key = hdWallet.getPrivateKeyByPath("m/44'/0'/0'");
  
  print('bip44 account extended privKey: ${bip44Key.serializePrivate(HDExtendedKeyVersion.xprv.value)}');

  print('bip44 account extended pubKey: ${bip44Key.serializePublic(HDExtendedKeyVersion.xpub.value)}');
  
  final address0Key = hdWallet.getPrivateKeyByPath("m/44'/0'/0'/0/0");

  print('address0: ${base58checkCodec.encode(Base58CheckPayload(0, address0Key.pubKeyHash))}');

  final address1Key = hdWallet.getPrivateKeyByPath("m/44'/0'/0'/0/1");

  print('address1: ${base58checkCodec.encode(Base58CheckPayload(0, address1Key.pubKeyHash))}');
  
}
