// ignore_for_file: constant_identifier_names

import 'dart:typed_data';

import 'package:base58check/base58check.dart';
import 'package:hd_wallet_kit/src/base58.dart';
import 'package:hd_wallet_kit/src/eckey.dart';
import 'package:hd_wallet_kit/src/hdextendedkeyversion.dart';
import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';
import 'package:hd_wallet_kit/utils.dart';
import 'package:pointycastle/digests/sha256.dart';

class HDKey extends ECKey {
  static const int HARDENED_FLAG = 0x80000000;

  final Uint8List _chainCode;
  Uint8List get chainCode => _chainCode;

  final HDKey? _parent;
  HDKey? get parent => _parent;

  final int _childNumber;
  int get childNumber => _childNumber;
  int get childNumberEncoded =>
      _isHardened ? (_childNumber | HARDENED_FLAG) : _childNumber;

  final bool _isHardened;
  bool get isHardened => _isHardened;

  final int _depth;
  int get depth => _depth;

  final int _parentFingerprint;
  int get parentFingerprint => _parentFingerprint;

  HDKey.withPrivKey(
    BigInt privKey,
    this._chainCode,
    this._parent,
    this._parentFingerprint,
    this._depth,
    this._childNumber,
    this._isHardened,
  ) : super.withPrivKey(privKey, true) {
    if (privKeyBytes!.length > 33) {
      throw IllegalArgumentException('Private key is longer than 33 bytes');
    }
    if (_chainCode.length != 32) {
      throw IllegalArgumentException('Chain code is not 32 bytes');
    }
    if (pubKey.length != 33) {
      throw IllegalArgumentException('Public key is not compressed');
    }
  }

  HDKey.withPubKey(
    Uint8List pubKey,
    this._chainCode,
    this._parent,
    this._parentFingerprint,
    this._depth,
    this._childNumber,
    this._isHardened,
  ) : super.withPubKey(pubKey) {
    if (pubKey.length != 33) {
      throw IllegalArgumentException('Public key is not compressed');
    }
    if (_chainCode.length != 32) {
      throw IllegalArgumentException('Chain code is not 32 bytes');
    }
  }

  String serializePublic(HDExtendedKeyVersion version) {
    return _toBase58(_serialize(version.value, pubKey));
  }

  String serializePrivate(HDExtendedKeyVersion version) {
    return _toBase58(_serialize(version.value, getPaddedPrivKeyBytes()));
  }

  Uint8List _serialize(int version, Uint8List key) {
    final ser = BytesBuilder();
    ser.add(intToUint8List(version));
    ser.addByte(depth);
    ser.add(intToUint8List(parentFingerprint));
    ser.add(intToUint8List(childNumberEncoded));
    ser.add(chainCode);
    ser.add(key);
    if (ser.length != 78) {
      throw IllegalArgumentException('');
    }
    return ser.toBytes();
  }

  String _toBase58(Uint8List ser) {
    return base58codec.encode(_addChecksum(ser));
  }

  Uint8List getPaddedPrivKeyBytes() {
    final paddedBytes = Uint8List(33);
    final length = privKeyBytes!.length;
    for (int i = 0; i < 33 - length; ++i) {
      paddedBytes[i] = 0;
    }
    paddedBytes.setAll(33 - length, privKeyBytes!);
    return paddedBytes;
  }

  int getFingerprint() {
    return ((pubKeyHash[0] & 255) << 24) |
        ((pubKeyHash[1] & 255) << 16) |
        ((pubKeyHash[2] & 255) << 8) |
        (pubKeyHash[3] & 255);
  }

  String encodeAddress() {
    return base58checkCodec.encode(Base58CheckPayload(0, pubKeyHash));
  }

  static Uint8List _addChecksum(Uint8List input) {
    final output = BytesBuilder();
    output.add(input);
    final checksum =
        SHA256Digest().process(SHA256Digest().process(input)).getRange(0, 4);
    output.add(checksum.toList());
    return output.toBytes();
  }

  @override
  String toString() {
    final stringBuffer = StringBuffer();
    if (parent != null) {
      final parentPath = parent.toString();
      stringBuffer.write(parentPath);
      stringBuffer.write('/');
      stringBuffer.write(childNumber);
      stringBuffer.write(isHardened ? "'" : '');
      return stringBuffer.toString();
    } else {
      return 'm';
    }
  }
}
