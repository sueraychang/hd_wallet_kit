import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

Uint8List hmacSha512(Uint8List key, Uint8List input) {
  final hmac = HMac(SHA512Digest(), 128);
  hmac.init(KeyParameter(key));
  return hmac.process(input);
}

String uint8ListToHexString(Uint8List input) {
  return input.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
}

String uint8ListToBinaryString(Uint8List input) {
  return input.map((e) => e.toRadixString(2).padLeft(8, '0')).join();
}

Uint8List hexStringToUint8List(String hexString) {
  final results = Uint8List(hexString.length ~/ 2);
  for (int i = 0; i < results.length; ++i) {
    results[i] = int.parse(hexString.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return results;
}

Uint8List intToUint8List(int i) {
  var bytes = ByteData(4);
  bytes.setInt32(0, i, Endian.big);

  return bytes.buffer.asUint8List();
}

int binaryStringToInt(String binaryString) {
  return int.parse(binaryString, radix: 2);
}

Uint8List sha256Digest(Uint8List input) {
  return SHA256Digest().process(input);
}

Uint8List doubleSHA256Digest(Uint8List input) {
  return SHA256Digest().process(SHA256Digest().process(input));
}

Uint8List sha256Hash160(Uint8List input) {
  return RIPEMD160Digest().process(SHA256Digest().process(input));
}
