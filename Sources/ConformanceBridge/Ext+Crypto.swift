// Ext+Crypto.swift — conformance bridge extension cluster: M-CRYPTO
//   aes_256_cbc_encrypt / aes_256_cbc_decrypt — raw AES-256-CBC, NO padding
//   token_generate_key                        — Token.generate_key key lengths
//   crypto_provider_op                         — primitive via a named provider
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_aes_256_cbc_encrypt :388, cmd_aes_256_cbc_decrypt :411,
//  cmd_token_generate_key, cmd_crypto_provider_op). Returns nil for any command
// it does not own (dispatch chain: Ext+Dispatch.swift).
//
// FORCED SWIFT DEVIATION (documented in port-deviations.md): RNS chooses its
// crypto backend at import time (PROVIDER_INTERNAL vs PROVIDER_PYCA). reticulum-
// swift has a SINGLE crypto provider (CryptoKit + CryptoSwift), so
// crypto_provider_op accepts the `provider` arg for API parity but maps both
// "internal" and "pyca" onto the same implementation. The conformance test only
// asserts the two providers produce BYTE-IDENTICAL output (NIST/RFC vectors),
// which a single shared implementation satisfies trivially.
import Foundation
import ReticulumSwift
import CryptoKit
import CryptoSwift

/// Reject any key that is not exactly 32 bytes (AES-256) or IV that is not the
/// single 16-byte block AES-CBC requires. CryptoSwift's AES would otherwise accept
/// a 16-byte key and silently downgrade to AES-128 — RNS AES_256_CBC never does.
private func requireAes256KeyAndIv(key: Data, iv: Data) throws {
    guard key.count == 32 else {
        throw BridgeError.invalidData("AES-256-CBC key must be 32 bytes, got \(key.count)")
    }
    guard iv.count == 16 else {
        throw BridgeError.invalidData("AES-256-CBC IV must be 16 bytes, got \(iv.count)")
    }
}

func handleCryptoExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Raw AES-256-CBC block cipher, NO PKCS7 padding — plaintext must already
    // be a multiple of the 16-byte block size; ciphertext is the same length.
    // (cf. `aes_encrypt`, which is the PKCS7+CBC Token composite.)
    case "aes_256_cbc_encrypt":
        let plaintext = try getHex(p, "plaintext")
        let key = try getHex(p, "key")
        let iv = try getHex(p, "iv")
        // RNS AES_256_CBC requires a 32-byte key + 16-byte IV. CryptoSwift would
        // silently do AES-128 for a 16-byte key, so reject any non-256-bit key (and
        // wrong-length IV) rather than fall back to a weaker cipher.
        try requireAes256KeyAndIv(key: key, iv: iv)
        let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .noPadding)
        let ct = try aes.encrypt(Array(plaintext))
        return ["ciphertext": hex(Data(ct))]

    case "aes_256_cbc_decrypt":
        let ciphertext = try getHex(p, "ciphertext")
        let key = try getHex(p, "key")
        let iv = try getHex(p, "iv")
        try requireAes256KeyAndIv(key: key, iv: iv)
        let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .noPadding)
        let pt = try aes.decrypt(Array(ciphertext))
        return ["plaintext": hex(Data(pt))]

    // Token.generate_key(mode): AES_128_CBC -> 32 bytes (16 signing + 16 enc),
    // AES_256_CBC (default) -> 64 bytes (32 + 32). Unknown mode is rejected.
    // RNS produces these from os.urandom; we use a CSPRNG (SymmetricKey).
    case "token_generate_key":
        let mode = getStringOptional(p, "mode") ?? "AES_256_CBC"
        let keyLen: Int
        switch mode {
        case "AES_128_CBC": keyLen = 32
        case "AES_256_CBC": keyLen = 64
        default:
            // Error text must contain "token mode" (test lowercases + substring-matches).
            throw BridgeError.invalidData("unsupported token mode: \(mode)")
        }
        let randomKey = SymmetricKey(size: .init(bitCount: keyLen * 8))
        let keyData = randomKey.withUnsafeBytes { Data($0) }
        return ["key": hex(keyData)]

    // Drive one primitive through a NAMED provider. Single-provider deviation
    // (see file header): the provider arg is validated but does not switch impl.
    case "crypto_provider_op":
        let op = try getString(p, "op")
        let provider = try getString(p, "provider")
        guard provider == "internal" || provider == "pyca" else {
            throw BridgeError.invalidData("Unknown provider: \(provider)")
        }
        switch op {
        case "x25519_exchange":
            let priv = try getHex(p, "private_key")
            let peer = try getHex(p, "peer_public_key")
            let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv)
            let peerPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer)
            let shared = try privKey.sharedSecretFromKeyAgreement(with: peerPub)
            return ["result": hex(shared.withUnsafeBytes { Data($0) })]
        case "ed25519_sign":
            let priv = try getHex(p, "private_key")
            let message = try getHex(p, "message")
            guard let sig = Ed25519Pure.sign(message: message, seed: priv) else {
                throw BridgeError.invalidData("Ed25519 signing failed")
            }
            return ["result": hex(sig)]
        case "ed25519_verify":
            let pub = try getHex(p, "public_key")
            let message = try getHex(p, "message")
            let signature = try getHex(p, "signature")
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: pub)
            return ["valid": boolean(pubKey.isValidSignature(signature, for: message))]
        case "aes_256_cbc_encrypt":
            let plaintext = try getHex(p, "plaintext")
            let key = try getHex(p, "key")
            let iv = try getHex(p, "iv")
            let aes = try AES(key: Array(key), blockMode: CBC(iv: Array(iv)), padding: .noPadding)
            return ["result": hex(Data(try aes.encrypt(Array(plaintext))))]
        default:
            throw BridgeError.invalidData("Unknown op: \(op)")
        }

    default:
        return nil
    }
}
