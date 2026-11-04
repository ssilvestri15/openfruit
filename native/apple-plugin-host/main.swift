@_spi(PluginMessage) import SwiftCompilerPluginMessageHandling
@_spi(PluginMessage) import SwiftLibraryPluginProvider
import Darwin

private enum OPENFRUITMessageConnectionError: Error {
  case readFailed
  case writeFailed
  case oversizedMessage
}

private final class OPENFRUITMessageConnection: MessageConnection {
  private let inputFileDescriptor: Int32
  private let outputFileDescriptor: Int32

  init(inputFileDescriptor: Int32, outputFileDescriptor: Int32) {
    self.inputFileDescriptor = inputFileDescriptor
    self.outputFileDescriptor = outputFileDescriptor
  }

  func sendMessage<Message: Encodable>(_ message: Message) throws {
    let bytes = try JSON.encode(message)
    var size = UInt64(bytes.count).littleEndian
    try withUnsafeBytes(of: &size) { try writeAll($0) }
    try bytes.withUnsafeBytes { try writeAll($0) }
  }

  func waitForNextMessage<Message: Decodable>(_ messageType: Message.Type) throws -> Message? {
    var size: UInt64 = 0
    let hasHeader = try withUnsafeMutableBytes(of: &size) {
      try readAll($0, allowsEOF: true)
    }
    if !hasHeader { return nil }
    size = UInt64(littleEndian: size)
    if size == 0 || size > 256 * 1024 * 1024 {
      throw OPENFRUITMessageConnectionError.oversizedMessage
    }
    var bytes = [UInt8](repeating: 0, count: Int(size))
    _ = try bytes.withUnsafeMutableBytes {
      try readAll($0, allowsEOF: false)
    }
    writeDiagnostic("OPENFRUIT_APPLE_PLUGIN_HOST_FRAME_READ\n")
    let decoded = try bytes.withUnsafeBufferPointer {
      try JSON.decode(messageType, from: $0)
    }
    writeDiagnostic("OPENFRUIT_APPLE_PLUGIN_HOST_FRAME_DECODED\n")
    return decoded
  }

  private func readAll(
    _ buffer: UnsafeMutableRawBufferPointer,
    allowsEOF: Bool
  ) throws -> Bool {
    var offset = 0
    while offset < buffer.count {
      let amount = Darwin.read(
        inputFileDescriptor,
        buffer.baseAddress! + offset,
        buffer.count - offset
      )
      if amount == 0 && offset == 0 && allowsEOF { return false }
      if amount <= 0 { throw OPENFRUITMessageConnectionError.readFailed }
      offset += amount
    }
    return true
  }

  private func writeAll(_ buffer: UnsafeRawBufferPointer) throws {
    var offset = 0
    while offset < buffer.count {
      let amount = Darwin.write(
        outputFileDescriptor,
        buffer.baseAddress! + offset,
        buffer.count - offset
      )
      if amount <= 0 { throw OPENFRUITMessageConnectionError.writeFailed }
      offset += amount
    }
  }

  private func writeDiagnostic(_ text: String) {
    let bytes = Array(text.utf8)
    bytes.withUnsafeBytes {
      _ = Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count)
    }
  }
}

@main
final class OPENFRUITApplePluginHost {
  static func main() {
    let startup = Array("OPENFRUIT_APPLE_PLUGIN_HOST_START\n".utf8)
    startup.withUnsafeBytes { bytes in
      _ = Darwin.write(STDERR_FILENO, bytes.baseAddress, bytes.count)
    }
    do {
      // Darling cannot initialize Apple's terminal-oriented stdio wrapper.
      // Keep Apple's codec/listener/provider and replace only the byte transport.
      let connection = OPENFRUITMessageConnection(
        inputFileDescriptor: STDIN_FILENO,
        outputFileDescriptor: STDOUT_FILENO
      )
      let connected = Array("OPENFRUIT_APPLE_PLUGIN_HOST_CONNECTION_READY\n".utf8)
      connected.withUnsafeBytes {
        _ = Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count)
      }
      let provider = LibraryPluginProvider.shared
      let providerReady = Array("OPENFRUIT_APPLE_PLUGIN_HOST_PROVIDER_READY\n".utf8)
      providerReady.withUnsafeBytes {
        _ = Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count)
      }
      let handler = PluginProviderMessageHandler(provider: provider)
      let handlerReady = Array("OPENFRUIT_APPLE_PLUGIN_HOST_HANDLER_READY\n".utf8)
      handlerReady.withUnsafeBytes {
        _ = Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count)
      }
      let listener = CompilerPluginMessageListener(
        connection: connection,
        messageHandler: handler
      )
      let listening = Array("OPENFRUIT_APPLE_PLUGIN_HOST_LISTENER_READY\n".utf8)
      listening.withUnsafeBytes {
        _ = Darwin.write(STDERR_FILENO, $0.baseAddress, $0.count)
      }
      try listener.main()
    } catch {
      let message = Array("OPENFRUIT_APPLE_PLUGIN_HOST_ERROR\n".utf8)
      message.withUnsafeBytes { bytes in
        _ = Darwin.write(STDERR_FILENO, bytes.baseAddress, bytes.count)
      }
    }
  }
}
