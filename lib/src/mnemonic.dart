import 'dart:convert';
import 'dart:core';
import 'dart:math';
import 'dart:typed_data';

import 'package:hd_wallet_kit/hd_wallet_kit.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';

enum EntropyStrength { minimum, low, medium, high, veryHigh }

extension _EntropyStrengthExtension on EntropyStrength {
  int get entropyLength {
    switch (this) {
      case EntropyStrength.minimum:
        return 128;
      case EntropyStrength.low:
        return 160;
      case EntropyStrength.medium:
        return 192;
      case EntropyStrength.high:
        return 224;
      case EntropyStrength.veryHigh:
        return 256;
    }
  }

  int get checksumLength => entropyLength ~/ 32;

  int get totalLength => entropyLength + checksumLength;

  int get wordCount => checksumLength * 3;
}

EntropyStrength fromWordCount({required int wordCount}) {
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

class Mnemonic {
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

  static Uint8List toSeed(List<String> mnemonicKeys, [String passphrase = '']) {
    validate(mnemonicKeys);

    final String mnemonicString = mnemonicKeys.join(' ');
    final salt = Uint8List.fromList(utf8.encode('mnemonic$passphrase'));

    final derivator = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128));
    derivator.init(Pbkdf2Parameters(salt, 2048, 64));
    return derivator.process(Uint8List.fromList(mnemonicString.codeUnits));
  }

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

  static Uint8List toEntropy(List<String> mnemonicKeys, WordList wordlist) {
    final strength = fromWordCount(wordCount: mnemonicKeys.length);
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
