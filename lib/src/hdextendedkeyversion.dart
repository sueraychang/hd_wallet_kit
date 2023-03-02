// ignore_for_file: constant_identifier_names

import 'package:hd_wallet_kit/src/hdwallet.dart';
import 'package:hd_wallet_kit/src/hdwalletkitexception.dart';

enum ExtendedKeyCoinType { bitcoin, litecoin }

enum HDExtendedKeyVersion {
  xprv(0x0488ade4, 'xprv', Purpose.BIP44),
  xpub(0x0488b21e, 'xpub', Purpose.BIP44, isPublic: true),
  yprv(0x049d7878, 'yprv', Purpose.BIP49),
  ypub(0x049d7cb2, 'ypub', Purpose.BIP49, isPublic: true),
  zprv(0x04b2430c, 'zprv', Purpose.BIP84),
  zpub(0x04b24746, 'zpub', Purpose.BIP84, isPublic: true),
  Ltpv(0x019d9cfe, 'Ltpv', Purpose.BIP44,
      extendedKeyCoinType: ExtendedKeyCoinType.litecoin),
  Ltub(0x019da462, 'Ltub', Purpose.BIP44,
      extendedKeyCoinType: ExtendedKeyCoinType.litecoin, isPublic: true),
  Mtpv(0x01b26792, 'Mtpv', Purpose.BIP49,
      extendedKeyCoinType: ExtendedKeyCoinType.litecoin),
  Mtub(0x01b26ef6, 'Mtub', Purpose.BIP49,
      extendedKeyCoinType: ExtendedKeyCoinType.litecoin, isPublic: true);

  final int value;
  final String base58Prefix;
  final Purpose purpose;
  final ExtendedKeyCoinType extendedKeyCoinType;
  final bool isPublic;
  const HDExtendedKeyVersion(
    this.value,
    this.base58Prefix,
    this.purpose, {
    this.extendedKeyCoinType = ExtendedKeyCoinType.bitcoin,
    this.isPublic = false,
  });

  HDExtendedKeyVersion get pubKey {
    switch (this) {
      case HDExtendedKeyVersion.xprv:
        return HDExtendedKeyVersion.xpub;
      case HDExtendedKeyVersion.yprv:
        return HDExtendedKeyVersion.ypub;
      case HDExtendedKeyVersion.zprv:
        return HDExtendedKeyVersion.zpub;
      case HDExtendedKeyVersion.Ltpv:
        return HDExtendedKeyVersion.Ltub;
      case HDExtendedKeyVersion.Mtpv:
        return HDExtendedKeyVersion.Mtub;
      default:
        return this;
    }
  }

  HDExtendedKeyVersion get privKey {
    switch (this) {
      case HDExtendedKeyVersion.xprv:
      case HDExtendedKeyVersion.yprv:
      case HDExtendedKeyVersion.zprv:
      case HDExtendedKeyVersion.Ltpv:
      case HDExtendedKeyVersion.Mtpv:
        return this;
      default:
        throw IllegalArgumentException('No privateKey of $base58Prefix');
    }
  }

  static HDExtendedKeyVersion? initFrom(String prefix) {
    for (var element in HDExtendedKeyVersion.values) {
      if (element.base58Prefix == prefix) {
        return element;
      }
    }
    return null;
  }
}
