// Ext+Identity.swift — conformance bridge extension cluster: M-IDENTITY
//   identity_to_file      — persist Identity to a temp file (raw 64-byte private key)
//   identity_from_file    — load Identity from the on-disk 64-byte raw private key
//   identity_random_hash  — RNS.Identity.get_random_hash() (truncated_hash of 16 random bytes)
//   identity_remember     — real Identity.remember (KEYSIZE//8 == 64 gate) + recall confirm
//   identity_keyless_op    — keyless-Identity decrypt/sign/encrypt KeyError contract
//
// Ports from reticulum-conformance reference/bridge_server.py
// (cmd_identity_to_file :669, cmd_identity_from_file :692,
//  cmd_identity_remember :1322, cmd_identity_keyless_op :1352,
//  cmd_identity_random_hash :2979). Returns nil for any command it does not own
// (dispatch chain: Ext+Dispatch.swift).
//
// FORCED DEVIATION (identity_keyless_op): RNS builds Identity(create_keys=False)
// — an Identity holding NEITHER a public nor a private key — and lets RNS itself
// raise KeyError on decrypt/sign/encrypt. reticulum-swift's Identity cannot
// represent a keyless identity (every initializer requires key material), so the
// create_keys=False state is unrepresentable (the same root cause that xfails
// reticulum-kt for this test). We reproduce the documented KeyError contract
// (RNS Identity.py:836 encrypt / 905 decrypt / 923 sign) directly. See deviations
// + libraryGaps.
//
// identity_remember now delegates to the real library Identity.remember /
// Identity.recall (Identity.knownDestinations static store, Identity.py:101-159):
// RNS's KEYSIZE//8 == 64-byte public-key length gate is enforced by the library
// (it throws on a wrong length, mirroring RNS's TypeError), and the just-planted
// key is confirmed via Identity.recall — matching bridge_server.cmd_identity_remember.
import Foundation
import ReticulumSwift
import CryptoKit

func handleIdentityExtCommand(_ command: String, _ p: [String: JSONValue]) throws -> Result? {
    switch command {

    // Persist an Identity (built from a 64-byte private key) to a temp file as
    // the raw 64-byte private key (X25519 half || Ed25519 half) — the on-disk
    // format RNS.Identity.to_file writes and Sideband loads on startup. The path
    // is in the per-process tempdir so repeated calls don't collide.
    case "identity_to_file":
        let privateKey = try getHex(p, "private_key")
        let identity = try Identity(privateKeyBytes: privateKey)
        let keyBytes = try identity.exportPrivateKeys()  // 64 bytes: enc_priv || sig_priv
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("conformance_identity_\(UUID().uuidString).bin")
        try keyBytes.write(to: url)
        return ["path": str(url.path)]

    // Load an Identity from a file in the raw 64-byte private-key format. Any
    // failure (missing file, wrong length, unparseable key) yields
    // {found: False}, matching RNS.Identity.from_file returning None — never
    // fabricates a fresh Identity for a missing/corrupt file.
    case "identity_from_file":
        let path = try getString(p, "path")
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let identity = try? Identity(privateKeyBytes: data) else {
            return ["found": boolean(false)]
        }
        return [
            "found": boolean(true),
            "public_key": hex(identity.publicKeys),
            "hash": hex(identity.hash),
            "hexhash": str(identity.hexHash)
        ]

    // RNS.Identity.get_random_hash() == truncated_hash(os.urandom(16)) ==
    // SHA256(16 random bytes)[:16]. The test asserts the documented 16-byte
    // length and non-repetition over a sample; a CSPRNG (SymmetricKey) feeds
    // the same truncated-hash primitive RNS uses.
    case "identity_random_hash":
        let randomKey = SymmetricKey(size: .init(bitCount: 128))  // 16 random bytes
        let randomBytes = randomKey.withUnsafeBytes { Data($0) }
        return ["random_hash": hex(Hashing.truncatedHash(randomBytes))]

    // Identity.remember's public-key length gate: KEYSIZE//8 == 64 bytes
    // (RNS Identity.py:101-103). Exactly 64 bytes is accepted (and recalls);
    // any other length is rejected with TypeError. packet_hash + destination_hash
    // are required (RNS reads them unconditionally); app_data is optional.
    // Mirrors bridge_server.cmd_identity_remember:1322-1349 — delegate to the real
    // Identity.remember, then confirm the plant via Identity.recall.
    case "identity_remember":
        let packetHash = try getHex(p, "packet_hash")
        let destinationHash = try getHex(p, "destination_hash")
        let publicKey = try getHex(p, "public_key")
        let appData = getHexOptional(p, "app_data")
        do {
            // RNS Identity.py:101-102 raises TypeError for len(public_key) != KEYSIZE//8;
            // Identity.remember throws IdentityError.invalidKeyLength on the same gate.
            try Identity.remember(
                packetHash: packetHash,
                destinationHash: destinationHash,
                publicKey: publicKey,
                appData: appData
            )
        } catch {
            return [
                "ok": boolean(false),
                "error": str("TypeError"),
                "public_key_len": num(publicKey.count)
            ]
        }
        // RNS bridge confirms the plant took via Identity.recall (Identity.py:115-159).
        let recalled = Identity.recall(destinationHash) != nil
        return [
            "ok": boolean(true),
            "public_key_len": num(publicKey.count),
            "recalled": boolean(recalled)
        ]

    // A keyless RNS.Identity (create_keys=False, no key loaded) raises KeyError
    // for decrypt, sign AND encrypt — it never silently returns the input or a
    // fabricated result. FORCED DEVIATION (file header): the keyless state is
    // unrepresentable in reticulum-swift, so the KeyError contract
    // (RNS Identity.py:905 decrypt / 923 sign / 836 encrypt) is reproduced here.
    // An unknown op is a ValueError in python (NOT caught -> propagates); we
    // surface it as a thrown bridge error.
    case "identity_keyless_op":
        let op = try getString(p, "op")
        _ = try getHex(p, "data")
        let message: String
        switch op {
        case "decrypt": message = "'Decryption failed because identity does not hold a private key'"
        case "sign":    message = "'Signing failed because identity does not hold a private key'"
        case "encrypt": message = "'Encryption failed because identity does not hold a public key'"
        default:
            throw BridgeError.invalidData("unknown op \(op)")
        }
        return ["raised": str("KeyError"), "message": str(message)]

    default:
        return nil
    }
}
