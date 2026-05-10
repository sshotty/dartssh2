import 'dart:async';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';
import 'package:dartssh2/src/message/msg_kex.dart';
import 'package:test/test.dart';

void main() {
  group('SSHTransport AEAD', () {
    test('exchanges packets with AES-GCM', () async {
      final key = Uint8List(16);
      final iv = Uint8List(12);
      for (var i = 0; i < key.length; i++) {
        key[i] = i;
      }
      for (var i = 0; i < iv.length; i++) {
        iv[i] = i + 16;
      }

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(
        senderSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      sender.configureForTesting(
        clientCipherType: SSHCipherType.aes128gcm,
        localCipherKey: key,
        localIV: iv,
        kexInProgress: false,
        localPacketSequence: 0,
      );

      final payload = Uint8List.fromList([250, 1, 2, 3, 4, 5]);
      sender.sendPacket(payload);

      final encryptedPacket = senderSocket.packets.last;

      final receiverSocket = _CaptureSSHSocket();
      final receivedPacket = Completer<Uint8List>();
      final receiver = SSHTransport(
        receiverSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
        onPacket: (packet) {
          if (!receivedPacket.isCompleted) {
            receivedPacket.complete(packet);
          }
        },
      );

      receiver.configureForTesting(
        remoteVersion: 'SSH-2.0-test',
        serverCipherType: SSHCipherType.aes128gcm,
        remoteCipherKey: key,
        remoteIV: iv,
        remotePacketSequence: 0,
      );

      receiverSocket.addIncomingBytes(encryptedPacket);

      final received =
          await receivedPacket.future.timeout(const Duration(seconds: 2));
      expect(received, payload);

      sender.close();
      receiver.close();
    });

    test('reports AEAD authentication failure when packet is tampered',
        () async {
      final key = Uint8List(16);
      final iv = Uint8List(12);
      for (var i = 0; i < key.length; i++) {
        key[i] = i;
      }
      for (var i = 0; i < iv.length; i++) {
        iv[i] = i + 16;
      }

      final senderSocket = _CaptureSSHSocket();
      final sender = SSHTransport(
        senderSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      sender.configureForTesting(
        clientCipherType: SSHCipherType.aes128gcm,
        localCipherKey: key,
        localIV: iv,
        kexInProgress: false,
        localPacketSequence: 0,
      );

      sender.sendPacket(Uint8List.fromList([251, 9, 8, 7]));
      final tampered = Uint8List.fromList(senderSocket.packets.last);
      tampered[tampered.length - 1] ^= 0x01;

      final receiverSocket = _CaptureSSHSocket();
      final receiver = SSHTransport(
        receiverSocket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
        ),
      );

      receiver.configureForTesting(
        remoteVersion: 'SSH-2.0-test',
        serverCipherType: SSHCipherType.aes128gcm,
        remoteCipherKey: key,
        remoteIV: iv,
        remotePacketSequence: 0,
      );

      receiverSocket.addIncomingBytes(tampered);

      await expectLater(
        receiver.done,
        throwsA(
          predicate(
            (error) =>
                error is SSHPacketError &&
                error.toString().contains('AEAD authentication failed'),
          ),
        ),
      );

      sender.close();
      receiver.close();
    });

    test('validates AEAD nonce IV length', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transport.nonceForSequenceForTesting(Uint8List(8), 0),
        throwsA(isA<ArgumentError>()),
      );

      transport.close();
    });

    test('consumeAeadPacket returns null for incomplete inputs', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        remoteVersion: 'SSH-2.0-test',
        serverCipherType: SSHCipherType.aes128gcm,
        remoteCipherKey: Uint8List(16),
        remoteIV: Uint8List(12),
        remotePacketSequence: 0,
      );

      final resultNoHeader =
          transport.consumeAeadPacketForTesting(SSHCipherType.aes128gcm);
      expect(resultNoHeader, isNull);

      transport.addIncomingBytesForTesting(
        Uint8List.fromList([0, 0, 0, 20, 1, 2, 3]),
      );

      final resultPartial =
          transport.consumeAeadPacketForTesting(SSHCipherType.aes128gcm);
      expect(resultPartial, isNull);

      transport.close();
    });

    test('applyLocalKeys keeps AEAD mode without cipher/mac instances', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        kexType: SSHKexType.x25519,
        sharedSecret: BigInt.from(1),
        exchangeHash: Uint8List.fromList(List<int>.filled(32, 1)),
        sessionId: Uint8List.fromList(List<int>.filled(32, 2)),
        clientCipherType: SSHCipherType.aes128gcm,
      );

      transport.applyLocalKeysForTesting();

      final localKey = transport.localCipherKeyForTesting;
      final localIv = transport.localIVForTesting;
      expect(localKey, isNotNull);
      expect(localKey!.length, SSHCipherType.aes128gcm.keySize);
      expect(localIv, isNotNull);
      expect(localIv!.length, SSHCipherType.aes128gcm.ivSize);
      expect(transport.encryptCipherForTesting, isNull);
      expect(transport.localMacForTesting, isNull);

      transport.close();
    });

    test('applyRemoteKeys keeps AEAD mode without cipher/mac instances', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        kexType: SSHKexType.x25519,
        sharedSecret: BigInt.from(1),
        exchangeHash: Uint8List.fromList(List<int>.filled(32, 3)),
        sessionId: Uint8List.fromList(List<int>.filled(32, 4)),
        serverCipherType: SSHCipherType.aes128gcm,
      );

      transport.applyRemoteKeysForTesting();

      final remoteKey = transport.remoteCipherKeyForTesting;
      final remoteIv = transport.remoteIVForTesting;
      expect(remoteKey, isNotNull);
      expect(remoteKey!.length, SSHCipherType.aes128gcm.keySize);
      expect(remoteIv, isNotNull);
      expect(remoteIv!.length, SSHCipherType.aes128gcm.ivSize);
      expect(transport.decryptCipherForTesting, isNull);
      expect(transport.remoteMacForTesting, isNull);

      transport.close();
    });

    test('applyLocalKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        kexType: SSHKexType.x25519,
        sharedSecret: BigInt.from(5),
        exchangeHash: Uint8List.fromList(List<int>.filled(32, 6)),
        sessionId: Uint8List.fromList(List<int>.filled(32, 7)),
        clientCipherType: SSHCipherType.aes128ctr,
        clientMacType: SSHMacType.hmacSha256,
      );

      transport.applyLocalKeysForTesting();

      expect(transport.encryptCipherForTesting, isNotNull);
      expect(transport.localMacForTesting, isNotNull);

      transport.close();
    });

    test('applyRemoteKeys creates cipher and mac for non-AEAD algorithms', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        kexType: SSHKexType.x25519,
        sharedSecret: BigInt.from(8),
        exchangeHash: Uint8List.fromList(List<int>.filled(32, 9)),
        sessionId: Uint8List.fromList(List<int>.filled(32, 10)),
        serverCipherType: SSHCipherType.aes128ctr,
        serverMacType: SSHMacType.hmacSha256,
      );

      transport.applyRemoteKeysForTesting();

      expect(transport.decryptCipherForTesting, isNotNull);
      expect(transport.remoteMacForTesting, isNotNull);

      transport.close();
    });

    test('kexinit allows missing MAC when AEAD cipher is selected', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128gcm],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transport.configureForTesting(kexInProgress: true, sentKexInit: true);

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128gcm.name],
        encryptionServerToClient: [SSHCipherType.aes128gcm.name],
        macClientToServer: const ['missing-mac'],
        macServerToClient: const ['missing-mac'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      expect(
        () => transport.handleMessageKexInitForTesting(payload),
        returnsNormally,
      );

      transport.close();
    });

    test('sendPacket buffers non-kex packets during key exchange', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(kexInProgress: true);

      // 94 is outside control/kex message ranges and should be buffered.
      transport.sendPacket(Uint8List.fromList([94, 1, 2]));

      final pending = transport.rekeyPendingPacketsForTesting;
      expect(pending, hasLength(1));
      expect(pending.first, Uint8List.fromList([94, 1, 2]));

      transport.close();
    });

    test('applyLocalKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transport.applyLocalKeysForTesting(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when cipher type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      expect(
        () => transport.applyRemoteKeysForTesting(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyLocalKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        kexType: SSHKexType.x25519,
        sharedSecret: BigInt.from(11),
        exchangeHash: Uint8List.fromList(List<int>.filled(32, 12)),
        sessionId: Uint8List.fromList(List<int>.filled(32, 13)),
        clientCipherType: SSHCipherType.aes128ctr,
      );

      expect(
        () => transport.applyLocalKeysForTesting(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('applyRemoteKeys throws when non-AEAD MAC type is missing', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(socket);

      transport.configureForTesting(
        kexType: SSHKexType.x25519,
        sharedSecret: BigInt.from(14),
        exchangeHash: Uint8List.fromList(List<int>.filled(32, 15)),
        sessionId: Uint8List.fromList(List<int>.filled(32, 16)),
        serverCipherType: SSHCipherType.aes128ctr,
      );

      expect(
        () => transport.applyRemoteKeysForTesting(),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires client MAC when non-AEAD cipher is selected', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transport.configureForTesting(kexInProgress: true, sentKexInit: true);

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: const ['missing-mac'],
        macServerToClient: [SSHMacType.hmacSha256.name],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      expect(
        () => transport.handleMessageKexInitForTesting(payload),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });

    test('kexinit requires server MAC when non-AEAD cipher is selected', () {
      final socket = _CaptureSSHSocket();
      final transport = SSHTransport(
        socket,
        algorithms: const SSHAlgorithms(
          cipher: [SSHCipherType.aes128ctr],
          mac: [SSHMacType.hmacSha256],
        ),
      );

      transport.configureForTesting(kexInProgress: true, sentKexInit: true);

      final payload = SSH_Message_KexInit(
        kexAlgorithms: [SSHKexType.x25519.name],
        serverHostKeyAlgorithms: [SSHHostkeyType.ed25519.name],
        encryptionClientToServer: [SSHCipherType.aes128ctr.name],
        encryptionServerToClient: [SSHCipherType.aes128ctr.name],
        macClientToServer: [SSHMacType.hmacSha256.name],
        macServerToClient: const ['missing-mac'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

      expect(
        () => transport.handleMessageKexInitForTesting(payload),
        throwsA(isA<StateError>()),
      );

      transport.close();
    });
  });
}

class _CaptureSSHSocket implements SSHSocket {
  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final packets = <Uint8List>[];

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _CaptureSink(packets);

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncomingBytes(Uint8List data) {
    _inputController.add(Uint8List.fromList(data));
  }

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }
}

class _CaptureSink implements StreamSink<List<int>> {
  _CaptureSink(this._packets);

  final List<Uint8List> _packets;

  @override
  void add(List<int> data) {
    _packets.add(Uint8List.fromList(data));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
