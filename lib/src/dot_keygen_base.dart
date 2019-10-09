import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:bitcoin_flutter/bitcoin_flutter.dart' as bitcoin;
import 'package:web3dart/web3dart.dart' as web3;
import 'package:urbit_ob/urbit_ob.dart' as ob;

import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';

// we use a constant salt for the root derivator as convention
final ROOT = "dot";
// 8 bytes = 64bits of entropy = 8syl = 4chunk tickets
final SECRET_LENGTH = 8;

// NB(shrugs): parameters via https://blog.filippo.io/the-scrypt-parameters/
// TODO: argon2id when Dart derivator exists ¯\_(ツ)_/¯
KeyDerivator _derivator(Uint8List salt) =>
    Scrypt()..init(ScryptParameters(16384, 8, 1, SECRET_LENGTH, salt));

/// creates a secret by intantiating a derivator salted by [node] and processed with [secret]
Uint8List _secretForNode(String node, Uint8List secret) =>
    _derivator(Uint8List.fromList(node.codeUnits)).process(secret);

// API

class Domain {
  static String Bitcoin = 'bitcoin';
  static String Ethereum = 'ethereum';
}

/// derive a secret for a node in the key graph by recursively applying
/// the parent node's secret as seed and path as salt
Uint8List derive(Uint8List parentSecret, List<String> path) {
  assert(path.isNotEmpty, "path must be provided");
  return path.fold(parentSecret, (s, node) => _secretForNode(node, s));
}

// WALLETS

bitcoin.HDWallet toBitcoinWallet(Uint8List secret) =>
    bitcoin.HDWallet.fromSeed(SHA256Digest().process(secret));

web3.Wallet toEthereumWallet(Uint8List secret) =>
    web3.Wallet.createNew(web3.EthPrivateKey(secret), "", Random.secure());
