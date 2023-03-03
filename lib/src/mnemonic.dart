import 'dart:convert';
import 'dart:core';
import 'dart:math';
import 'dart:typed_data';

import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
import 'package:hd_wallet_kit/src/wordlist.dart';
import 'package:hd_wallet_kit/utils.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';

enum EntropyStrength {
  minimum(128),
  low(160),
  medium(192),
  high(224),
  veryHigh(256);

  final int entropyLength;
  const EntropyStrength(this.entropyLength);

  int get checksumLength => entropyLength ~/ 32;
  int get totalLength => entropyLength + checksumLength;
  int get wordCount => checksumLength * 3;

  static EntropyStrength _fromWordCount(int wordCount) {
    switch (wordCount) {
      case 12:
        return EntropyStrength.minimum;
      case 15:
        return EntropyStrength.low;
      case 18:
        return EntropyStrength.medium;
      case 21:
        return EntropyStrength.high;
      case 24:
        return EntropyStrength.veryHigh;
      default:
        throw InvalidMnemonicCountException(message: 'count: $wordCount');
    }
  }
}

class Mnemonic {
  /// Generate mnemonic keys
  static List<String> generate([
    EntropyStrength strength = EntropyStrength.minimum,
    WordList wordList = WordList.english,
  ]) {
    final entropy = Uint8List(strength.entropyLength ~/ 8);
    final random = Random.secure();
    for (var i = 0; i < entropy.length; i++) {
      entropy[i] = random.nextInt(256);
    }
    return toMnemonic(entropy, wordList);
  }

  /// Convert entropy data to mnemonic word list.
  static List<String> toMnemonic(Uint8List entropy, WordList wordList) {
    if (entropy.isEmpty) {
      throw EmptyEntropyException(message: 'Entropy is empty.');
    }

    final entropyBits = uint8ListToBinaryString(entropy);
    final sha256Entropy = sha256Digest(entropy);
    final checksumBits = uint8ListToBinaryString(sha256Entropy)
        .substring(0, entropyBits.length ~/ 32);

    final totalBits = entropyBits + checksumBits;

    return _splitByLength(totalBits, 11)
        .map((e) => wordList.wordList[binaryStringToInt(e)])
        .toList();
  }

  /// Convert mnemonic keys to seed
  static Uint8List toSeed(List<String> mnemonicKeys, [String passphrase = '']) {
    validate(mnemonicKeys);

    final String mnemonicString = mnemonicKeys.join(' ');
    final salt = Uint8List.fromList(utf8.encode('mnemonic$passphrase'));

    final derivator = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128));
    derivator.init(Pbkdf2Parameters(salt, 2048, 64));
    return derivator.process(Uint8List.fromList(mnemonicString.codeUnits));
  }

  /// Validate mnemonic keys. Since validation
  /// requires deriving the original entropy, this function is the same as calling [toEntropy]
  static void validate(List<String> mnemonicKeys) {
    WordList approprateWordList = WordList.english;
    for (var wordList in WordList.values) {
      if (wordList.validWords(mnemonicKeys)) {
        approprateWordList = wordList;
        break;
      }
    }

    toEntropy(mnemonicKeys, approprateWordList);
  }

  /// Get the original entropy that was used to create this MnemonicCode. This call will fail
  /// if the words have an invalid length or checksum.
  ///
  /// @throws [InvalidMnemonicCountException] when the word count is zero or not a multiple of 3.
  /// @throws [ChecksumException] if the checksum does not match the expected value.
  ///
  ///
  static Uint8List toEntropy(List<String> mnemonicKeys, WordList wordlist) {
    final strength = EntropyStrength._fromWordCount(mnemonicKeys.length);
    final entropy = Uint8List(strength.entropyLength ~/ 8);

    String totalBits = '';
    for (var key in mnemonicKeys) {
      final index = wordlist.wordList.indexOf(key);
      if (index < 0) {
        throw InvalidMnemonicKeyException(message: 'Invalid word: $key');
      }
      totalBits += index.toRadixString(2).padLeft(11, '0');
    }

    for (int i = 0; i < strength.entropyLength ~/ 8; ++i) {
      final startBit = i * 8;
      entropy[i] =
          binaryStringToInt(totalBits.substring(startBit, startBit + 8));
    }

    final checksumLength = strength.entropyLength ~/ 32;
    final checksumBits =
        totalBits.substring(strength.entropyLength, totalBits.length);

    final sha256entropy = sha256Digest(entropy);
    if (uint8ListToBinaryString(sha256entropy).substring(0, checksumLength) !=
        checksumBits) {
      throw ChecksumException(message: 'Invalid checksum');
    }
    return entropy;
  }

  static List<String> _splitByLength(String value, int length) {
    List<String> pieces = [];

    for (int i = 0; i < value.length; i += length) {
      int offset = i + length;
      pieces.add(
          value.substring(i, offset >= value.length ? value.length : offset));
    }
    return pieces;
  }
}
