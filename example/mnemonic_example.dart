import 'package:hd_wallet_kit/hd_wallet_kit.dart';
import 'package:hd_wallet_kit/utils.dart';

main() {
  final mnemonic = Mnemonic.generate();
  print('Generated mnemonic: ${mnemonic.join(' ')}');

  final entropy = hexStringToUint8List('00000000000000000000000000000000');
  final mnemonicFromEntropy = Mnemonic.toMnemonic(entropy, WordList.english);
  print('Mnemonic from entropy: ${mnemonicFromEntropy.join(' ')}');

  final seed = Mnemonic.toSeed(mnemonicFromEntropy);
  print('Mnemonic to seed: ${uint8ListToHexString(seed)}');

  final entropyFromMnemonic =
      Mnemonic.toEntropy(mnemonicFromEntropy, WordList.english);
  print('Entropy from mnemonic: ${uint8ListToHexString(entropyFromMnemonic)}');
}
