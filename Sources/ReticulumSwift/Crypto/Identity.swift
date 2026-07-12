// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright (c) 2026 Torlando Tech LLC

//
//  Identity.swift
//  ReticulumSwift
//
//  Reticulum Identity containing Ed25519 signing and X25519 encryption keypairs.
//  The identity hash is the truncated SHA-256 of concatenated public keys.
//
//  Matches Python RNS Identity.py for byte-perfect interoperability.
//

import Foundation
import CryptoKit
import Security

/// Reticulum Identity containing Ed25519 signing and X25519 encryption keypairs.
///
/// Each identity has two keypairs:
/// - **Encryption keypair (X25519):** Used for Diffie-Hellman key agreement
/// - **Signing keypair (Ed25519):** Used for digital signatures
///
/// The identity hash is derived from the SHA-256 of concatenated public keys,
/// truncated to 16 bytes (128 bits).
///
/// Public key concatenation order matches Python RNS: encryption (32 bytes) + signing (32 bytes)
public struct Identity {
    // MARK: - Keys

    /// X25519 private key for key agreement (encryption/decryption)
    /// Nil for public-key-only identities (remote peers)
    public let encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey?

    /// X25519 public key for key agreement
    /// Stored directly for public-key-only identities
    private let _encryptionPublicKey: Curve25519.KeyAgreement.PublicKey?

    /// X25519 public key for key agreement
    public var encryptionPublicKey: Curve25519.KeyAgreement.PublicKey {
        if let privateKey = encryptionPrivateKey {
            return privateKey.publicKey
        }
        return _encryptionPublicKey!
    }

    /// Ed25519 private key for signing
    /// Nil for public-key-only identities (remote peers)
    public let signingPrivateKey: Curve25519.Signing.PrivateKey?

    /// Stored signing public key for public-key-only identities
    private let _signingPublicKey: Curve25519.Signing.PublicKey?

    /// Ed25519 public key for signature verification
    public var signingPublicKey: Curve25519.Signing.PublicKey {
        if let privateKey = signingPrivateKey {
            return privateKey.publicKey
        }
        return _signingPublicKey!
    }

    /// Whether this identity has private keys (can sign)
    public var hasPrivateKeys: Bool {
        signingPrivateKey != nil
    }

    /// Last-heard application data attached to a recalled identity.
    ///
    /// Mirrors RNS `Identity.app_data` (Identity.py:138/:149/:156): `recall`
    /// attaches the `known_destinations` entry's app_data to the returned
    /// identity (or nil for the locally-registered-destination fallback). This is
    /// a plain attribute in python; the swift port surfaces it as a settable
    /// stored property so `recall` can populate it on the value-type copy it
    /// returns. Defaults to nil for freshly-constructed identities.
    public var appData: Data? = nil

    // MARK: - Derived Properties

    /// 16-byte identity hash (truncated SHA-256 of public keys)
    ///
    /// Computed as: SHA256(encryptionPublicKey || signingPublicKey)[:16]
    public var hash: Data {
        Hashing.identityHash(
            encryptionPublicKey: encryptionPublicKey.rawRepresentation,
            signingPublicKey: signingPublicKey.rawRepresentation
        )
    }

    /// 64-byte concatenated public keys (encryption || signing)
    ///
    /// This is the format used in announce packets and for hash computation.
    public var publicKeys: Data {
        var data = Data()
        data.append(encryptionPublicKey.rawRepresentation)
        data.append(signingPublicKey.rawRepresentation)
        return data
    }

    /// Hex string representation of the identity hash
    public var hexHash: String {
        hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Initialization

    /// Generate a new random identity
    ///
    /// Creates fresh Ed25519 and X25519 keypairs using secure random generation.
    public init() {
        self.encryptionPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.signingPrivateKey = Curve25519.Signing.PrivateKey()
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create identity from existing private keys
    ///
    /// Used for testing with known keys or restoring from storage.
    ///
    /// - Parameters:
    ///   - encryptionPrivateKey: X25519 private key for encryption
    ///   - signingPrivateKey: Ed25519 private key for signing
    public init(
        encryptionPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        signingPrivateKey: Curve25519.Signing.PrivateKey
    ) {
        self.encryptionPrivateKey = encryptionPrivateKey
        self.signingPrivateKey = signingPrivateKey
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create identity from raw private key bytes (32 bytes each)
    ///
    /// Used for test vector validation and key import.
    ///
    /// - Parameters:
    ///   - encryptionPrivateKeyBytes: 32-byte X25519 private key
    ///   - signingPrivateKeyBytes: 32-byte Ed25519 private key
    /// - Throws: `IdentityError.invalidKeyLength` if key bytes are wrong size
    public init(
        encryptionPrivateKeyBytes: Data,
        signingPrivateKeyBytes: Data
    ) throws {
        guard encryptionPrivateKeyBytes.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: encryptionPrivateKeyBytes.count,
                keyType: "encryption"
            )
        }
        guard signingPrivateKeyBytes.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: signingPrivateKeyBytes.count,
                keyType: "signing"
            )
        }

        self.encryptionPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: encryptionPrivateKeyBytes
        )
        self.signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: signingPrivateKeyBytes
        )
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create identity from concatenated private key bytes (64 bytes total)
    ///
    /// Used for restoring identity from storage or keychain.
    ///
    /// - Parameter privateKeyBytes: 64-byte concatenated private keys (encryption || signing)
    /// - Throws: `IdentityError.invalidKeyLength` if bytes are wrong size
    public init(privateKeyBytes: Data) throws {
        guard privateKeyBytes.count == 64 else {
            throw IdentityError.invalidKeyLength(
                expected: 64,
                actual: privateKeyBytes.count,
                keyType: "private keys"
            )
        }

        let encPrivBytes = privateKeyBytes[privateKeyBytes.startIndex..<privateKeyBytes.startIndex + 32]
        let sigPrivBytes = privateKeyBytes[privateKeyBytes.startIndex + 32..<privateKeyBytes.startIndex + 64]

        self.encryptionPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: encPrivBytes
        )
        self.signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: sigPrivBytes
        )
        self._encryptionPublicKey = nil
        self._signingPublicKey = nil
    }

    /// Create a public-key-only identity from raw public key bytes.
    ///
    /// Used for remote peer identities where we only have their public keys.
    /// This identity can verify signatures but cannot sign.
    ///
    /// - Parameter publicKeyBytes: 64-byte concatenated public keys (encryption || signing)
    /// - Throws: `IdentityError.invalidKeyLength` if bytes are wrong size
    public init(publicKeyBytes: Data) throws {
        guard publicKeyBytes.count == 64 else {
            throw IdentityError.invalidKeyLength(
                expected: 64,
                actual: publicKeyBytes.count,
                keyType: "public keys"
            )
        }

        let encryptionPubBytes = publicKeyBytes[publicKeyBytes.startIndex..<publicKeyBytes.startIndex + 32]
        let signingPubBytes = publicKeyBytes[publicKeyBytes.startIndex + 32..<publicKeyBytes.startIndex + 64]

        self.encryptionPrivateKey = nil
        self.signingPrivateKey = nil
        self._encryptionPublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: encryptionPubBytes
        )
        self._signingPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: signingPubBytes
        )
    }

    /// Create public-key-only identity from separate encryption and signing keys
    ///
    /// Used for creating identities from LXMF test vectors or other sources
    /// where keys are provided separately.
    ///
    /// - Parameters:
    ///   - encryptionPublicKey: 32-byte X25519 public key
    ///   - signingPublicKey: 32-byte Ed25519 public key
    /// - Throws: `IdentityError.invalidKeyLength` if keys are wrong size
    public init(
        encryptionPublicKey: Data,
        signingPublicKey: Data
    ) throws {
        guard encryptionPublicKey.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: encryptionPublicKey.count,
                keyType: "encryption public"
            )
        }
        guard signingPublicKey.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: signingPublicKey.count,
                keyType: "signing public"
            )
        }

        self.encryptionPrivateKey = nil
        self.signingPrivateKey = nil
        self._encryptionPublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: encryptionPublicKey
        )
        self._signingPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: signingPublicKey
        )
    }

    // MARK: - Signing

    /// Sign data with the identity's Ed25519 private key
    ///
    /// - Parameter data: Data to sign
    /// - Returns: 64-byte Ed25519 signature
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity
    /// - Throws: CryptoKit error if signing fails
    public func sign(_ data: Data) throws -> Data {
        guard let privateKey = signingPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        let signature = try privateKey.signature(for: data)
        return Data(signature)
    }

    /// Verify a signature against this identity's signing public key
    ///
    /// - Parameters:
    ///   - signature: 64-byte Ed25519 signature
    ///   - data: Original data that was signed
    /// - Returns: true if signature is valid, false otherwise
    public func verify(signature: Data, for data: Data) -> Bool {
        signingPublicKey.isValidSignature(signature, for: data)
    }

    /// Static verification with just public key bytes (for received announces)
    ///
    /// This is used when verifying signatures from remote identities where
    /// we only have the public key, not the full identity.
    ///
    /// - Parameters:
    ///   - signature: 64-byte Ed25519 signature
    ///   - data: Original data that was signed
    ///   - publicKey: Ed25519 public key bytes (32 bytes)
    /// - Returns: true if signature is valid
    /// - Throws: `IdentityError.invalidKeyLength` if public key is wrong size
    public static func verify(
        signature: Data,
        for data: Data,
        publicKey: Data
    ) throws -> Bool {
        guard publicKey.count == 32 else {
            throw IdentityError.invalidKeyLength(
                expected: 32,
                actual: publicKey.count,
                keyType: "signing public"
            )
        }
        guard signature.count == 64 else {
            return false
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: data)
    }

    // MARK: - Encryption (SINGLE Destination)

    /// Encrypt data to this identity's public key for SINGLE destination delivery.
    ///
    /// Uses Reticulum's encryption pattern:
    /// 1. Generate ephemeral X25519 keypair
    /// 2. Perform ECDH with recipient's encryption public key
    /// 3. Derive 64-byte key via HKDF using identity hash as salt
    /// 4. Encrypt with Token (AES-256-CBC + HMAC-SHA256)
    /// 5. Prepend ephemeral public key
    ///
    /// Output format: [ephemeral_pub 32B][IV 16B][ciphertext][HMAC 32B]
    ///
    /// IMPORTANT: The HKDF salt is the **identity hash** (SHA256(publicKeys)[:16]),
    /// NOT the destination hash. This matches Python RNS Identity.get_salt().
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Encrypted token with prepended ephemeral public key
    /// - Throws: `IdentityError.encryptionFailed` if encryption fails
    public static func encrypt(
        _ plaintext: Data,
        to encryptionPublicKey: Curve25519.KeyAgreement.PublicKey,
        identityHash: Data
    ) throws -> Data {
        // 1. Generate ephemeral X25519 keypair
        let ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralPrivateKey.publicKey

        // 2. Perform ECDH to get shared secret
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(with: encryptionPublicKey)
        } catch {
            throw IdentityError.encryptionFailed(reason: "ECDH failed: \(error.localizedDescription)")
        }

        // 3. Derive 64-byte key via HKDF using identity hash as salt
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = KeyDerivation.deriveKey(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: identityHash,
            context: nil
        )

        // 4. Encrypt with Token
        let token: Token
        do {
            token = try Token(derivedKey: derivedKey)
        } catch {
            throw IdentityError.encryptionFailed(reason: "Token creation failed: \(error.localizedDescription)")
        }

        let ciphertext: Data
        do {
            ciphertext = try token.encrypt(plaintext)
        } catch {
            throw IdentityError.encryptionFailed(reason: "Token encryption failed: \(error.localizedDescription)")
        }

        // 5. Prepend ephemeral public key
        var result = Data()
        result.append(ephemeralPublicKey.rawRepresentation)
        result.append(ciphertext)

        return result
    }

    /// Encrypt data to this identity (convenience method).
    ///
    /// IMPORTANT: The HKDF salt is the **identity hash** (SHA256(publicKeys)[:16]),
    /// NOT the destination hash. This matches Python RNS Identity.get_salt().
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Encrypted token with prepended ephemeral public key
    /// - Throws: `IdentityError.encryptionFailed` if encryption fails
    public func encryptTo(_ plaintext: Data, identityHash: Data) throws -> Data {
        return try Identity.encrypt(plaintext, to: encryptionPublicKey, identityHash: identityHash)
    }

    /// Decrypt data encrypted to this identity.
    ///
    /// Reverses the encryption process:
    /// 1. Extract ephemeral public key (first 32 bytes)
    /// 2. Perform ECDH with our private key
    /// 3. Derive key via HKDF using identity hash as salt
    /// 4. Decrypt with Token
    ///
    /// IMPORTANT: The HKDF salt is the **identity hash** (SHA256(publicKeys)[:16]),
    /// NOT the destination hash. This matches Python RNS Identity.get_salt().
    ///
    /// - Parameters:
    ///   - ciphertext: Encrypted token with prepended ephemeral public key
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Decrypted plaintext
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity
    /// - Throws: `IdentityError.decryptionFailed` if decryption fails
    public func decrypt(_ ciphertext: Data, identityHash: Data) throws -> Data {
        guard let privateKey = encryptionPrivateKey else {
            throw IdentityError.noPrivateKey
        }

        // Minimum size: 32 (ephemeral pub) + 64 (minimum token: 16 IV + 16 cipher + 32 HMAC)
        guard ciphertext.count >= 96 else {
            throw IdentityError.decryptionFailed(reason: "Ciphertext too short")
        }

        // 1. Extract ephemeral public key
        let ephemeralPubBytes = ciphertext.prefix(32)
        let tokenData = ciphertext.dropFirst(32)

        let ephemeralPublicKey: Curve25519.KeyAgreement.PublicKey
        do {
            ephemeralPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubBytes)
        } catch {
            throw IdentityError.decryptionFailed(reason: "Invalid ephemeral public key")
        }

        // 2. Perform ECDH
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        } catch {
            throw IdentityError.decryptionFailed(reason: "ECDH failed: \(error.localizedDescription)")
        }

        // 3. Derive key via HKDF using identity hash as salt
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = KeyDerivation.deriveKey(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: identityHash,
            context: nil
        )

        // 4. Decrypt with Token
        let token: Token
        do {
            token = try Token(derivedKey: derivedKey)
        } catch {
            throw IdentityError.decryptionFailed(reason: "Token creation failed")
        }

        do {
            return try token.decrypt(Data(tokenData))
        } catch {
            throw IdentityError.decryptionFailed(reason: "Token decryption failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Ratchet Encryption

    /// Encrypt data to a specific ratchet public key (raw 32 bytes).
    ///
    /// Identical to standard encrypt, but takes raw ratchet key bytes
    /// instead of the identity's encryption public key. Used when a
    /// destination has ratchets enabled for forward secrecy.
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt
    ///   - ratchetPublicKey: 32-byte X25519 ratchet public key
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    /// - Returns: Encrypted token with prepended ephemeral public key
    public static func encrypt(
        _ plaintext: Data,
        toRatchetKey ratchetPublicKey: Data,
        identityHash: Data
    ) throws -> Data {
        guard ratchetPublicKey.count == 32 else {
            throw IdentityError.encryptionFailed(reason: "Ratchet key must be 32 bytes")
        }
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ratchetPublicKey)
        return try encrypt(plaintext, to: pubKey, identityHash: identityHash)
    }

    /// Decrypt data with ratchet fallback chain.
    ///
    /// Tries each ratchet private key in order (newest first), then falls
    /// back to the base identity key. This allows decryption of messages
    /// encrypted to any of our current or recent ratchet keys.
    ///
    /// Python reference: Identity.decrypt() with ratchets parameter.
    ///
    /// - Parameters:
    ///   - ciphertext: Encrypted token with prepended ephemeral public key
    ///   - identityHash: 16-byte identity hash (used as HKDF salt)
    ///   - ratchets: Array of 32-byte X25519 ratchet private keys to try
    ///   - enforceRatchets: If true, reject messages not encrypted to a ratchet
    /// - Returns: Decrypted plaintext
    public func decrypt(
        _ ciphertext: Data,
        identityHash: Data,
        ratchets: [Data],
        enforceRatchets: Bool = false
    ) throws -> Data {
        // Minimum size: 32 (ephemeral pub) + 64 (minimum token)
        guard ciphertext.count >= 96 else {
            throw IdentityError.decryptionFailed(reason: "Ciphertext too short")
        }

        // Extract ephemeral public key
        let ephemeralPubBytes = ciphertext.prefix(32)
        let tokenData = Data(ciphertext.dropFirst(32))

        let ephemeralPublicKey: Curve25519.KeyAgreement.PublicKey
        do {
            ephemeralPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubBytes)
        } catch {
            throw IdentityError.decryptionFailed(reason: "Invalid ephemeral public key")
        }

        // Try each ratchet private key
        for ratchetPriv in ratchets {
            guard ratchetPriv.count == 32 else { continue }
            do {
                let ratchetKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ratchetPriv)
                let sharedSecret = try ratchetKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
                let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
                let derivedKey = KeyDerivation.deriveKey(
                    length: 64,
                    inputKeyMaterial: sharedSecretData,
                    salt: identityHash,
                    context: nil
                )
                let token = try Token(derivedKey: derivedKey)
                return try token.decrypt(tokenData)
            } catch {
                // Try next ratchet
                continue
            }
        }

        // No ratchet succeeded
        if enforceRatchets {
            throw IdentityError.decryptionFailed(reason: "No ratchet key could decrypt and ratchets are enforced")
        }

        // Fallback to base identity key
        return try decrypt(ciphertext, identityHash: identityHash)
    }

    /// Decrypt with ratchet fallback AND ratchet-id reporting (RNS `ratchet_id_receiver`).
    ///
    /// Faithful port of RNS `Identity.decrypt(ciphertext_token, ratchets,
    /// enforce_ratchets, ratchet_id_receiver)` (Identity.py:865-913). Unlike the
    /// throwing overload above, this returns `nil` (never throws) on failure or
    /// enforcement rejection — matching python returning `None` — and reports the
    /// id of the ratchet that succeeded via `ratchetIdReceiver`:
    ///   - a ratchet decrypts -> `ratchetIdReceiver.latestRatchetId = _getRatchetId(pub)`
    ///     (Identity.py:889-890),
    ///   - enforcement rejects (no ratchet matched, `enforceRatchets`) ->
    ///     `latestRatchetId = nil`, return nil (Identity.py:897-901, BEFORE the
    ///     static fallback),
    ///   - the static key decrypts -> `latestRatchetId = nil` (Identity.py:903-908),
    ///   - any exception -> `latestRatchetId = nil` (Identity.py:910-912).
    ///
    /// This is the discriminator `Destination.decrypt` surfaces to prove an inbound
    /// ciphertext used an adopted ratchet (id set) vs the static key (id nil).
    ///
    /// - Parameters:
    ///   - ciphertext: Encrypted token with prepended ephemeral public key.
    ///   - identityHash: 16-byte identity hash (HKDF salt, RNS get_salt()).
    ///   - ratchets: Ratchet private keys to try (newest first), or nil.
    ///   - enforceRatchets: Reject (return nil) if no ratchet matches.
    ///   - ratchetIdReceiver: Receives the succeeding ratchet id (or nil).
    /// - Returns: Plaintext, or nil on failure/rejection.
    public func decrypt(
        _ ciphertext: Data,
        identityHash: Data,
        ratchets: [Data]?,
        enforceRatchets: Bool,
        ratchetIdReceiver: RatchetIdReceiver?
    ) -> Data? {
        guard encryptionPrivateKey != nil else {
            // RNS raises KeyError when no private key; swift surfaces nil.
            return nil
        }

        // RNS Identity.py:874 — if len(ciphertext_token) > KEYSIZE//8//2 (== 16)
        guard ciphertext.count > 16 else {
            return nil
        }

        // RNS Identity.py:877-879 — peer_pub = ciphertext[:32], ciphertext = rest
        guard ciphertext.count >= 96 else {
            ratchetIdReceiver?.latestRatchetId = nil
            return nil
        }
        let ephemeralPubBytes = ciphertext.prefix(32)
        guard (try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubBytes)) != nil else {
            ratchetIdReceiver?.latestRatchetId = nil
            return nil
        }

        var plaintext: Data? = nil

        // RNS Identity.py:881-893 — try each ratchet, recording its id on success
        if let ratchets = ratchets {
            for ratchetPriv in ratchets {
                guard ratchetPriv.count == 32 else { continue }
                do {
                    let ratchetId = try Identity.ratchetIdFromPrivate(ratchetPriv)
                    let candidate = try self.decrypt(
                        ciphertext,
                        identityHash: identityHash,
                        ratchets: [ratchetPriv],
                        enforceRatchets: true
                    )
                    plaintext = candidate
                    // RNS Identity.py:889-890 — ratchet_id_receiver.latest_ratchet_id = ratchet_id
                    ratchetIdReceiver?.latestRatchetId = ratchetId
                    break
                } catch {
                    continue
                }
            }
        }

        // RNS Identity.py:897-901 — enforce_ratchets and plaintext == None -> reject
        if enforceRatchets && plaintext == nil {
            ratchetIdReceiver?.latestRatchetId = nil
            return nil
        }

        // RNS Identity.py:903-908 — fall back to the static key, id = None
        if plaintext == nil {
            plaintext = try? self.decrypt(ciphertext, identityHash: identityHash)
            ratchetIdReceiver?.latestRatchetId = nil
        }

        return plaintext
    }

    /// `_get_ratchet_id` of the public key derived from a ratchet PRIVATE key.
    ///
    /// Mirrors RNS Identity.py:889 — `_get_ratchet_id(ratchet_prv.public_key().
    /// public_bytes())`. Throws if the private key is malformed.
    private static func ratchetIdFromPrivate(_ ratchetPriv: Data) throws -> Data {
        let pub = try RatchetManager.publicBytes(from: ratchetPriv)
        return Identity._getRatchetId(pub)
    }

    // MARK: - Persistence

    /// Export private keys for storage (64 bytes: enc_priv + sig_priv)
    ///
    /// This exports the raw private key bytes in a format suitable for secure storage.
    /// The format is: [encryption_private_key: 32 bytes][signing_private_key: 32 bytes]
    ///
    /// - Returns: 64-byte concatenated private keys
    /// - Throws: `IdentityError.noPrivateKey` if this is a public-key-only identity
    public func exportPrivateKeys() throws -> Data {
        guard let encPriv = encryptionPrivateKey,
              let sigPriv = signingPrivateKey else {
            throw IdentityError.noPrivateKey
        }
        var data = Data()
        data.append(encPriv.rawRepresentation)
        data.append(sigPriv.rawRepresentation)
        return data
    }

    /// Save identity to Keychain
    ///
    /// Stores the private keys securely in the system Keychain.
    /// The keys are stored as a generic password item.
    ///
    /// - Parameters:
    ///   - service: Service name for Keychain (e.g., "com.myapp.reticulum")
    ///   - account: Account name for Keychain (e.g., "identity")
    /// - Throws: `IdentityError.noPrivateKey` if no private keys
    /// - Throws: `IdentityError.keychainError` if Keychain operation fails
    public func saveToKeychain(service: String, account: String) throws {
        let privateKeyData = try exportPrivateKeys()

        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        // The identity is the user's account: losing it is unrecoverable. Two hardening
        // choices here:
        //
        // 1. `AfterFirstUnlockThisDeviceOnly` (not `WhenUnlockedThisDeviceOnly`) so the key
        //    stays readable while the screen is locked, once the device has been unlocked
        //    since boot. A background relaunch (BLE/location wake-up) with the phone locked
        //    in a pocket must be able to read it, or the caller would treat the key as
        //    missing and regenerate.
        // 2. A non-destructive update-or-add. The former delete-then-add could, while the
        //    device was locked, succeed at deleting the real key and then FAIL to add the
        //    new one — destroying the only copy. `SecItemUpdate` never removes the item
        //    unless the new value is written in the same operation.
        let attributes: [String: Any] = [
            kSecValueData as String: privateKeyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        // Only "no such item" justifies an add; any other error (e.g.
        // errSecInteractionNotAllowed while locked) must surface, never silently
        // fall through to overwriting.
        guard updateStatus == errSecItemNotFound else {
            throw IdentityError.keychainError(status: updateStatus)
        }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = privateKeyData
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw IdentityError.keychainError(status: addStatus)
        }
    }

    /// Load identity from Keychain
    ///
    /// Retrieves the private keys from the system Keychain and reconstructs
    /// the Identity.
    ///
    /// - Parameters:
    ///   - service: Service name for Keychain (e.g., "com.myapp.reticulum")
    ///   - account: Account name for Keychain (e.g., "identity")
    /// - Returns: The loaded Identity, or nil if not found
    /// - Throws: `IdentityError.keychainError` if Keychain operation fails (other than not found)
    /// - Throws: `IdentityError.invalidKeyLength` if stored data is corrupt
    public static func loadFromKeychain(service: String, account: String) throws -> Identity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw IdentityError.keychainError(status: status)
        }

        guard let privateKeyData = result as? Data else {
            throw IdentityError.keychainError(status: errSecDecode)
        }

        return try Identity(privateKeyBytes: privateKeyData)
    }

    /// Delete identity from Keychain
    ///
    /// - Parameters:
    ///   - service: Service name for Keychain
    ///   - account: Account name for Keychain
    /// - Returns: true if deleted, false if not found
    @discardableResult
    public static func deleteFromKeychain(service: String, account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}

// MARK: - Ratchet Id Receiver

/// A reference type that receives the id of the ratchet a `decrypt` used.
///
/// Mirrors RNS's `ratchet_id_receiver` parameter (Identity.py:865), which RNS
/// uses by writing `ratchet_id_receiver.latest_ratchet_id`. `Destination`
/// conforms so `Destination.decrypt(ciphertext, ratchet_id_receiver=self)`
/// (Destination.py:627/:641) records which ratchet (or the static key) decrypted.
public protocol RatchetIdReceiver: AnyObject {
    /// Id of the ratchet that last decrypted a message (nil for the static key).
    var latestRatchetId: Data? { get set }
}

// MARK: - Known Destinations / Ratchets store (RNS Identity.py class storage)

/// Thread-safe process-wide backing store for the static `Identity` tables.
///
/// RNS keeps `Identity.known_destinations` / `Identity.known_ratchets` as plain
/// module-level dicts guarded by `threading.Lock` (Identity.py:94-98). The swift
/// `Identity` is a value type, so the mutable class-level state lives in this
/// `NSLock`-guarded singleton instead (category (a) deviation — see
/// port-deviations.md). Read/written from the Transport actor, the bridge
/// threads, and `Destination.encrypt`/`decrypt`.
final class IdentityStore: @unchecked Sendable {
    static let shared = IdentityStore()

    /// One `known_destinations` record: [time, packet_hash, public_key, app_data, used]
    /// (RNS 5-element entry, Identity.py:107).
    struct KnownDestination {
        var time: Double
        var packetHash: Data
        var publicKey: Data
        var appData: Data?
        var used: Int
    }

    private let lock = NSLock()
    private var knownDestinations: [Data: KnownDestination] = [:]
    private var knownRatchets: [Data: Data] = [:]
    /// destination hash -> 64-byte public keys, for the `recall`
    /// Transport.destinations fallback (RNS Identity.py:151-159).
    private var localDestinations: [Data: Data] = [:]
    /// Mirrors `RNS.Reticulum.storagepath`; nil disables on-disk persistence.
    private var _storagePath: String?

    var storagePath: String? {
        get { lock.withLock { _storagePath } }
        set { lock.withLock { _storagePath = newValue } }
    }

    // MARK: known_destinations

    func remember(_ entry: KnownDestination, for destinationHash: Data) {
        lock.withLock {
            if var existing = knownDestinations[destinationHash] {
                // RNS Identity.py:108-113 — overwrite [0..3] in place (app_data refresh)
                existing.time = entry.time
                existing.packetHash = entry.packetHash
                existing.publicKey = entry.publicKey
                existing.appData = entry.appData
                knownDestinations[destinationHash] = existing
            } else {
                // RNS Identity.py:106 — new 5-element entry, used marker = 0
                knownDestinations[destinationHash] = entry
            }
        }
    }

    func knownDestination(_ destinationHash: Data) -> KnownDestination? {
        lock.withLock { knownDestinations[destinationHash] }
    }

    func allKnownDestinations() -> [Data: KnownDestination] {
        lock.withLock { knownDestinations }
    }

    func knownDestinationsCount() -> Int {
        lock.withLock { knownDestinations.count }
    }

    func clearKnownDestinations() {
        lock.withLock { knownDestinations = [:] }
    }

    func replaceKnownDestinations(_ table: [Data: KnownDestination]) {
        lock.withLock { knownDestinations = table }
    }

    // MARK: local (Transport.destinations) registry

    func registerLocalDestination(hash: Data, publicKey: Data) {
        lock.withLock { localDestinations[hash] = publicKey }
    }

    func deregisterLocalDestination(_ hash: Data) {
        lock.withLock { _ = localDestinations.removeValue(forKey: hash) }
    }

    func localDestination(_ hash: Data) -> Data? {
        lock.withLock { localDestinations[hash] }
    }

    // MARK: known_ratchets

    func cachedRatchet(_ destinationHash: Data) -> Data? {
        lock.withLock { knownRatchets[destinationHash] }
    }

    func cacheRatchet(_ ratchet: Data, for destinationHash: Data) {
        lock.withLock { knownRatchets[destinationHash] = ratchet }
    }

    func isKnownDestination(_ destinationHash: Data) -> Bool {
        lock.withLock { knownDestinations[destinationHash] != nil }
    }
}

public extension Identity {

    // MARK: - RNS Constants

    /// `Identity.KEYSIZE // 8` — concatenated public-key length (32 enc + 32 sig).
    static let KEYSIZE_BYTES = 64
    /// `Identity.RATCHETSIZE // 8` — ratchet key length (Identity.py:64).
    static let RATCHETSIZE_BYTES = 32
    /// `Identity.NAME_HASH_LENGTH // 8` — ratchet-id / name-hash length (Identity.py:83).
    static let NAME_HASH_LENGTH_BYTES = 10
    /// `Identity.TRUNCATED_HASHLENGTH // 8` — destination/identity hash length.
    static let TRUNCATED_HASHLENGTH_BYTES = 16
    /// `Identity.RATCHET_EXPIRY` — received ratchet lifetime, 30 days (Identity.py:69).
    static let RATCHET_EXPIRY: TimeInterval = 60 * 60 * 24 * 30

    /// Process-wide storage root, mirroring `RNS.Reticulum.storagepath`.
    ///
    /// Used by `saveKnownDestinations`/`loadKnownDestinations` (file
    /// `{storagePath}/known_destinations`) and the received-ratchet file store
    /// (`{storagePath}/ratchets/<hexhash>`). nil leaves the stores in-memory only.
    static var storagePath: String? {
        get { IdentityStore.shared.storagePath }
        set { IdentityStore.shared.storagePath = newValue }
    }

    // MARK: - Ratchet id helpers (Identity.py:395-422)

    /// `_get_ratchet_id(ratchet_pub_bytes)` — `full_hash(pub)[:NAME_HASH_LENGTH//8]`
    /// = SHA-256(pub)[:10] (Identity.py:409-411).
    static func _getRatchetId(_ ratchetPublicBytes: Data) -> Data {
        return Data(SHA256.hash(data: ratchetPublicBytes).prefix(NAME_HASH_LENGTH_BYTES))
    }

    /// `_ratchet_public_bytes(ratchet)` — public key for a ratchet PRIVATE key
    /// (Identity.py:413-414). Returns nil if the private key is malformed.
    static func _ratchetPublicBytes(_ ratchetPrivate: Data) -> Data? {
        return try? RatchetManager.publicBytes(from: ratchetPrivate)
    }

    /// `current_ratchet_id(destination_hash)` — id of the currently adopted
    /// ratchet PUBLIC key for a destination, or nil (Identity.py:395-407).
    static func currentRatchetId(_ destinationHash: Data) -> Data? {
        guard let ratchet = getRatchet(destinationHash) else { return nil }
        return _getRatchetId(ratchet)
    }

    // MARK: - known_destinations: remember / recall (Identity.py:101-174)

    /// `Identity.remember(packet_hash, destination_hash, public_key, app_data)`
    /// (Identity.py:100-113). Inserts a new 5-element record, or overwrites
    /// elements [0..3] in place for a known destination (the app_data refresh).
    ///
    /// - Throws: `IdentityError.invalidKeyLength` when `publicKey` is not
    ///   `KEYSIZE//8` (64) bytes (RNS raises TypeError, Identity.py:101-102).
    static func remember(
        packetHash: Data,
        destinationHash: Data,
        publicKey: Data,
        appData: Data? = nil
    ) throws {
        guard publicKey.count == KEYSIZE_BYTES else {
            throw IdentityError.invalidKeyLength(
                expected: KEYSIZE_BYTES, actual: publicKey.count, keyType: "public keys"
            )
        }
        let entry = IdentityStore.KnownDestination(
            time: Date().timeIntervalSince1970,
            packetHash: packetHash,
            publicKey: publicKey,
            appData: appData,
            used: 0
        )
        IdentityStore.shared.remember(entry, for: destinationHash)
    }

    /// `Identity.recall(target_hash, from_identity_hash)` (Identity.py:115-159).
    ///
    /// Default (destination-hash): returns the `known_destinations` identity with
    /// `.appData` set; if absent, falls back to the locally-registered
    /// destinations (Transport.destinations) returning that identity with
    /// `.appData = nil` (Identity.py:151-159); else nil.
    ///
    /// `fromIdentityHash`: matches `truncated_hash(public_key) == target_hash`
    /// over `known_destinations` (Identity.py:128-141); no local fallback.
    ///
    /// (RNS's `_used_destination_data` LRU bookkeeping is skipped — the library
    /// has no Reticulum instance to mark usage against. See port-deviations.md.)
    static func recall(_ targetHash: Data, fromIdentityHash: Bool = false) -> Identity? {
        if fromIdentityHash {
            // RNS Identity.py:128-141
            for (_, entry) in IdentityStore.shared.allKnownDestinations() {
                guard entry.publicKey.count == KEYSIZE_BYTES,
                      var id = try? Identity(publicKeyBytes: entry.publicKey) else { continue }
                if targetHash == id.hash {   // truncated_hash(public_key) == Identity.hash
                    id.appData = entry.appData
                    return id
                }
            }
            return nil
        }

        // RNS Identity.py:143-150 — known_destinations hit
        if let entry = IdentityStore.shared.knownDestination(targetHash) {
            guard var id = try? Identity(publicKeyBytes: entry.publicKey) else { return nil }
            id.appData = entry.appData
            return id
        }

        // RNS Identity.py:151-159 — Transport.destinations fallback, app_data None
        if let publicKey = IdentityStore.shared.localDestination(targetHash),
           publicKey.count == KEYSIZE_BYTES,
           var id = try? Identity(publicKeyBytes: publicKey) {
            id.appData = nil
            return id
        }

        return nil
    }

    /// `Identity.recall_app_data(destination_hash)` (Identity.py:162-174) —
    /// the last-heard app_data for a destination hash, or nil.
    static func recallAppData(_ destinationHash: Data) -> Data? {
        guard let entry = IdentityStore.shared.knownDestination(destinationHash) else {
            return nil
        }
        return entry.appData
    }

    /// Number of in-memory `known_destinations` entries.
    static var knownDestinationsCount: Int {
        IdentityStore.shared.knownDestinationsCount()
    }

    /// Clear the in-memory `known_destinations` table (RNS:
    /// `Identity.known_destinations = {}`, Identity.py:222) — used to prove the
    /// disk reload, not residual memory, restores entries.
    static func clearKnownDestinations() {
        IdentityStore.shared.clearKnownDestinations()
    }

    /// Element count of a `known_destinations` entry (always 5 when present, nil
    /// when absent) — the canonical [time, packet_hash, public_key, app_data,
    /// used] record shape (Identity.py:107).
    static func knownDestinationEntryLength(_ destinationHash: Data) -> Int? {
        return IdentityStore.shared.knownDestination(destinationHash) != nil ? 5 : nil
    }

    // MARK: - known_destinations persistence (Identity.py:176-265)

    /// `Identity.save_known_destinations()` (Identity.py:176-238): serialise the
    /// WHOLE table to `{storagePath}/known_destinations`, recombining on-disk
    /// entries absent from memory, via an atomic temp+rename write. Each record
    /// is the 5-element [time, packet_hash, public_key, app_data, used] array.
    ///
    /// - Returns: true on success (or no-op when `storagePath` is unset).
    @discardableResult
    static func saveKnownDestinations() -> Bool {
        guard let storagePath = storagePath else { return false }
        let fileURL = URL(fileURLWithPath: storagePath).appendingPathComponent("known_destinations")

        // RNS Identity.py:199-217 — recombine disk entries absent from memory.
        var table = IdentityStore.shared.allKnownDestinations()
        if let onDisk = try? loadKnownDestinationsTable(from: fileURL) {
            for (hash, entry) in onDisk where table[hash] == nil {
                table[hash] = entry
            }
        }

        // RNS Identity.py:221 — umsgpack.dump(known_destinations) of 5-element records.
        var mapEntries: [MessagePackValue: MessagePackValue] = [:]
        for (hash, entry) in table {
            mapEntries[.binary(hash)] = .array([
                .double(entry.time),
                .binary(entry.packetHash),
                .binary(entry.publicKey),
                entry.appData != nil ? .binary(entry.appData!) : .null,
                .int(Int64(entry.used)),
            ])
        }
        let packed = packMsgPack(.map(mapEntries))

        do {
            try FileManager.default.createDirectory(
                at: URL(fileURLWithPath: storagePath), withIntermediateDirectories: true
            )
            // RNS Identity.py:222-223 — temp file + os.rename (atomic).
            try packed.write(to: fileURL, options: .atomic)
            return true
        } catch {
            return false
        }
    }

    /// `Identity.load_known_destinations()` (Identity.py:240-265): read the table
    /// back from `{storagePath}/known_destinations`, REPLACING the in-memory table
    /// with the 5-element records on disk.
    ///
    /// - Returns: true on success (or no-op false when no file/`storagePath`).
    @discardableResult
    static func loadKnownDestinations() -> Bool {
        guard let storagePath = storagePath else { return false }
        let fileURL = URL(fileURLWithPath: storagePath).appendingPathComponent("known_destinations")
        guard let table = try? loadKnownDestinationsTable(from: fileURL) else { return false }
        // RNS Identity.py:246-261 — Identity.known_destinations = {} then fill.
        IdentityStore.shared.replaceKnownDestinations(table)
        return true
    }

    /// Decode a `known_destinations` msgpack file into a typed table. The 5-element
    /// record shape mirrors RNS; a legacy 4-element record is upgraded to 5 by
    /// appending `used = 0` (RNS Identity.py:251-254 partial — the 16-byte-key-skip
    /// branch is deferred per LIMITS.md).
    private static func loadKnownDestinationsTable(
        from fileURL: URL
    ) throws -> [Data: IdentityStore.KnownDestination] {
        let data = try Data(contentsOf: fileURL)
        guard case .map(let dict) = try unpackMsgPack(data) else {
            throw IdentityError.decryptionFailed(reason: "known_destinations not a map")
        }
        var table: [Data: IdentityStore.KnownDestination] = [:]
        for (key, value) in dict {
            guard case .binary(let hash) = key, case .array(let fields) = value,
                  fields.count >= 4 else { continue }
            guard case .double(let time) = msgpackAsDouble(fields[0]),
                  case .binary(let packetHash) = fields[1],
                  case .binary(let publicKey) = fields[2] else { continue }
            let appData: Data?
            if case .binary(let ad) = fields[3] { appData = ad } else { appData = nil }
            var used = 0
            if fields.count >= 5, let u = msgpackAsInt(fields[4]) { used = u }
            table[hash] = IdentityStore.KnownDestination(
                time: time, packetHash: packetHash, publicKey: publicKey,
                appData: appData, used: used
            )
        }
        return table
    }

    /// Normalise a msgpack numeric to `.double` (RNS stores `time.time()` as float64).
    private static func msgpackAsDouble(_ v: MessagePackValue) -> MessagePackValue {
        switch v {
        case .double: return v
        case .float(let f): return .double(Double(f))
        case .int(let i): return .double(Double(i))
        case .uint(let u): return .double(Double(u))
        default: return .double(0)
        }
    }

    private static func msgpackAsInt(_ v: MessagePackValue) -> Int? {
        switch v {
        case .int(let i): return Int(i)
        case .uint(let u): return Int(u)
        default: return nil
        }
    }

    // MARK: - known_ratchets: received-ratchet store (Identity.py:424-522)

    /// `Identity._remember_ratchet(destination_hash, ratchet)` (Identity.py:424-449):
    /// cache the ratchet in memory, and (when `storagePath` is set) persist
    /// `{ratchet, received}` to `<storagePath>/ratchets/<hexhash>` via an atomic
    /// temp `<hexhash>.out` write + replace.
    static func rememberRatchet(destinationHash: Data, ratchet: Data) {
        // RNS Identity.py:426-435 — skip if unchanged, else cache + persist.
        if IdentityStore.shared.cachedRatchet(destinationHash) == ratchet { return }
        IdentityStore.shared.cacheRatchet(ratchet, for: destinationHash)

        guard let storagePath = storagePath else { return }
        let ratchetDir = URL(fileURLWithPath: storagePath).appendingPathComponent("ratchets", isDirectory: true)
        let hexhash = destinationHash.map { String(format: "%02x", $0) }.joined()
        let finalURL = ratchetDir.appendingPathComponent(hexhash)
        let outURL = ratchetDir.appendingPathComponent(hexhash + ".out")

        // RNS Identity.py:438-441 — {"ratchet": ratchet, "received": time.time()}
        let packed = packMsgPack(.map([
            .string("ratchet"): .binary(ratchet),
            .string("received"): .double(Date().timeIntervalSince1970),
        ]))
        do {
            try FileManager.default.createDirectory(at: ratchetDir, withIntermediateDirectories: true)
            // RNS Identity.py:445-449 — write <hash>.out then os.replace -> <hash>.
            try packed.write(to: outURL, options: .atomic)
            if FileManager.default.fileExists(atPath: finalURL.path) {
                try? FileManager.default.removeItem(at: finalURL)
            }
            try FileManager.default.moveItem(at: outURL, to: finalURL)
        } catch {
            try? FileManager.default.removeItem(at: outURL)
        }
    }

    /// `Identity.get_ratchet(destination_hash)` (Identity.py:506-522): return the
    /// in-memory ratchet, else load `<storagePath>/ratchets/<hexhash>` applying the
    /// 32-byte (RATCHETSIZE//8) + RATCHET_EXPIRY gate, caching on success.
    static func getRatchet(_ destinationHash: Data) -> Data? {
        if let cached = IdentityStore.shared.cachedRatchet(destinationHash) {
            return cached
        }
        guard let storagePath = storagePath else { return nil }
        let ratchetDir = URL(fileURLWithPath: storagePath).appendingPathComponent("ratchets", isDirectory: true)
        let hexhash = destinationHash.map { String(format: "%02x", $0) }.joined()
        let fileURL = ratchetDir.appendingPathComponent(hexhash)
        guard FileManager.default.fileExists(atPath: fileURL.path),
              let data = try? Data(contentsOf: fileURL),
              case .map(let dict)? = try? unpackMsgPack(data),
              case .binary(let ratchet)? = dict[.string("ratchet")] else {
            return nil
        }
        let received: Double
        switch dict[.string("received")] {
        case .double(let d)?: received = d
        case .float(let f)?: received = Double(f)
        case .int(let i)?: received = Double(i)
        case .uint(let u)?: received = Double(u)
        default: received = 0
        }
        // RNS Identity.py:512-515 — expiry + size gate.
        if Date().timeIntervalSince1970 < received + RATCHET_EXPIRY,
           ratchet.count == RATCHETSIZE_BYTES {
            IdentityStore.shared.cacheRatchet(ratchet, for: destinationHash)
            return ratchet
        }
        return nil
    }

    /// `Identity._clean_ratchets()` (Identity.py:451-487): remove ratchet files
    /// whose destination is expired, corrupt, or not in `known_destinations`.
    static func cleanRatchets() {
        guard let storagePath = storagePath else { return }
        let ratchetDir = URL(fileURLWithPath: storagePath).appendingPathComponent("ratchets", isDirectory: true)
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: ratchetDir.path) else {
            return
        }
        let now = Date().timeIntervalSince1970
        for filename in files {
            let fileURL = ratchetDir.appendingPathComponent(filename)
            var expired = false
            var corrupted = false
            if let data = try? Data(contentsOf: fileURL),
               case .map(let dict)? = try? unpackMsgPack(data),
               case .double(let received)? = dict[.string("received")] {
                if now > received + RATCHET_EXPIRY { expired = true }
            } else {
                corrupted = true
            }
            // RNS Identity.py:483-484 — destination_hash = bytes.fromhex(filename)
            let destHash = Data(hexString: filename)
            let unknown = destHash.map { !IdentityStore.shared.isKnownDestination($0) } ?? true
            if expired || corrupted || unknown {
                try? FileManager.default.removeItem(at: fileURL)
            }
        }
    }

    // MARK: - Local destination registry (Transport.destinations fallback)

    /// Register a locally-created destination so `recall` can resolve one's OWN
    /// destination hash via the Transport.destinations fallback (Identity.py:
    /// 151-159) — an instance never receives its own announces. The owner should
    /// call this when registering a SINGLE/LINK destination.
    static func registerLocalDestination(hash: Data, publicKey: Data) {
        IdentityStore.shared.registerLocalDestination(hash: hash, publicKey: publicKey)
    }

    /// Deregister a previously-registered local destination.
    static func deregisterLocalDestination(_ hash: Data) {
        IdentityStore.shared.deregisterLocalDestination(hash)
    }

    // MARK: - validate_announce app_data None-vs-empty distinction

    /// Compute the recall app_data for a received announce, faithful to the RNS
    /// `validate_announce` None-vs-empty rule (Identity.py:542,560-561):
    ///   - a present trailing app_data field -> those bytes,
    ///   - no trailing field + a ratchet present -> empty `Data()` (b""),
    ///   - no trailing field + no ratchet -> nil (None).
    ///
    /// The integration point (`AnnounceHandler.process`) should pass the parsed
    /// trailing app_data and whether the announce carried a ratchet, then call
    /// `remember(... appData: announceAppData(...))` so the None-vs-empty
    /// distinction survives into `recall`.
    static func announceAppData(rawAppData: Data?, hasRatchet: Bool) -> Data? {
        if let raw = rawAppData {
            return raw
        }
        return hasRatchet ? Data() : nil
    }
}

// MARK: - Hex helper

private extension Data {
    /// Decode an even-length hex string into bytes, or nil if malformed.
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return nil }
            bytes.append(UInt8(hi << 4 | lo))
            i += 2
        }
        self.init(bytes)
    }
}

// MARK: - Errors

public enum IdentityError: Error, Equatable {
    /// Key has incorrect length
    case invalidKeyLength(expected: Int, actual: Int, keyType: String)

    /// Signature verification failed
    case signatureVerificationFailed

    /// No private key available (public-key-only identity)
    case noPrivateKey

    /// Encryption failed
    case encryptionFailed(reason: String)

    /// Decryption failed
    case decryptionFailed(reason: String)

    /// Keychain operation failed
    case keychainError(status: OSStatus)
}

// MARK: - CustomStringConvertible

extension Identity: CustomStringConvertible {
    public var description: String {
        "Identity<\(hexHash)>"
    }
}
