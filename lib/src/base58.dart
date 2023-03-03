import 'package:base58check/base58.dart';
import 'package:base58check/base58check.dart';

const String _alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
Base58CheckCodec base58checkCodec = Base58CheckCodec(_alphabet);
Base58Codec base58codec = const Base58Codec(_alphabet);
