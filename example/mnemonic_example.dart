import 'package:hd_wallet_kit/hd_wallet_kit.dart';
import 'package:hd_wallet_kit/utils.dart';

main() {
  final mnemonic = Mnemonic.generate();
  print('Generated mnemonic: ${mnemonic.join(' ')}');

  final seed = Mnemonic.toSeed(mnemonic);
  print('Mnemonic to seed: ${uint8ListToHexString(seed)}');
}
