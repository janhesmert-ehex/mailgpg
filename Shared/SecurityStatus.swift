// SecurityStatus.swift
// MailGPGExtension

/// A single PGP signer attached to a message.
struct Signer: Equatable, Codable {
    /// The email address associated with the signing key.
    let email: String
    /// Short key ID shown in the UI (last 8 hex chars of the fingerprint).
    let keyID: String
    /// Full 40-char hex fingerprint.
    let fingerprint: String
    /// Owner-trust level of this key in the local GPG keychain.
    let trustLevel: TrustLevel
    /// Convenience: true when trust is full or ultimate.
    var trusted: Bool { trustLevel == .full || trustLevel == .ultimate }
}

/// Which keys a message was encrypted to, and which of ours opened it.
///
/// Carried alongside the status so a failed decrypt can say *which* key it needed
/// rather than only that it failed — with two keys per address (one RSA, one ECC)
/// "encrypted to a key you don't have" is the single most useful signal there is.
///
/// Every field is optional on the wire: an extension paired with a host app that
/// predates these status parsers must still decode the status it is sent.
struct DecryptionDetails: Equatable, Codable {
    /// Key IDs from `ENC_TO` — every key the message was encrypted to.
    var encryptedToKeyIDs: [String] = []
    /// Fingerprint from `DECRYPTION_KEY` — the key of ours that actually opened it.
    var decryptionKeyFingerprint: String? = nil
    /// Key IDs from `NO_SECKEY` — encrypted to these, but we hold no secret key.
    var missingSecretKeyIDs: [String] = []

    var isEmpty: Bool {
        encryptedToKeyIDs.isEmpty && decryptionKeyFingerprint == nil && missingSecretKeyIDs.isEmpty
    }

    enum CodingKeys: String, CodingKey {
        case encryptedToKeyIDs, decryptionKeyFingerprint, missingSecretKeyIDs
    }

    init(encryptedToKeyIDs: [String] = [],
         decryptionKeyFingerprint: String? = nil,
         missingSecretKeyIDs: [String] = []) {
        self.encryptedToKeyIDs = encryptedToKeyIDs
        self.decryptionKeyFingerprint = decryptionKeyFingerprint
        self.missingSecretKeyIDs = missingSecretKeyIDs
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        encryptedToKeyIDs = try c.decodeIfPresent([String].self, forKey: .encryptedToKeyIDs) ?? []
        decryptionKeyFingerprint = try c.decodeIfPresent(String.self, forKey: .decryptionKeyFingerprint)
        missingSecretKeyIDs = try c.decodeIfPresent([String].self, forKey: .missingSecretKeyIDs) ?? []
    }
}

/// The PGP security state of a received message.
enum SecurityStatus: Equatable, Codable {
    /// Message was encrypted. May also carry verified signatures.
    case encrypted(signers: [Signer], details: DecryptionDetails = DecryptionDetails())
    /// Message was not encrypted but carries one or more valid signatures.
    case signed(signers: [Signer])
    /// A signature was present but verification failed (e.g. tampered content).
    case signatureInvalid(reason: String)
    /// The message was encrypted but we could not decrypt it.
    /// `details` names the keys involved so the user can tell a missing key from a
    /// malformed MIME part.
    case decryptionFailed(reason: String, details: DecryptionDetails = DecryptionDetails())
    /// Signed or encrypted with a key we don't have locally and couldn't fetch.
    case keyNotFound(keyID: String)
    /// No PGP content detected.
    case plain

    // MARK: - Codable

    // Hand-written, but deliberately byte-compatible with what Swift used to
    // synthesize: a single-key object named after the case, whose value is keyed by
    // the associated-value labels. Keeping that layout means a host app built before
    // `details` existed still produces JSON this decodes — the synthesized decoder
    // would reject it, because synthesis ignores default values.
    enum CodingKeys: String, CodingKey {
        case encrypted, signed, signatureInvalid, decryptionFailed, keyNotFound, plain
    }
    private enum SignersKeys: String, CodingKey { case signers, details }
    private enum ReasonKeys:  String, CodingKey { case reason, details }
    private enum KeyIDKeys:   String, CodingKey { case keyID }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .encrypted(let signers, let details):
            var n = c.nestedContainer(keyedBy: SignersKeys.self, forKey: .encrypted)
            try n.encode(signers, forKey: .signers)
            try n.encode(details, forKey: .details)
        case .signed(let signers):
            var n = c.nestedContainer(keyedBy: SignersKeys.self, forKey: .signed)
            try n.encode(signers, forKey: .signers)
        case .signatureInvalid(let reason):
            var n = c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .signatureInvalid)
            try n.encode(reason, forKey: .reason)
        case .decryptionFailed(let reason, let details):
            var n = c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .decryptionFailed)
            try n.encode(reason, forKey: .reason)
            try n.encode(details, forKey: .details)
        case .keyNotFound(let keyID):
            var n = c.nestedContainer(keyedBy: KeyIDKeys.self, forKey: .keyNotFound)
            try n.encode(keyID, forKey: .keyID)
        case .plain:
            _ = c.nestedContainer(keyedBy: KeyIDKeys.self, forKey: .plain)
        }
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let n = try? c.nestedContainer(keyedBy: SignersKeys.self, forKey: .encrypted) {
            self = .encrypted(signers: try n.decode([Signer].self, forKey: .signers),
                              details: try n.decodeIfPresent(DecryptionDetails.self, forKey: .details)
                                       ?? DecryptionDetails())
        } else if let n = try? c.nestedContainer(keyedBy: SignersKeys.self, forKey: .signed) {
            self = .signed(signers: try n.decode([Signer].self, forKey: .signers))
        } else if let n = try? c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .signatureInvalid) {
            self = .signatureInvalid(reason: try n.decode(String.self, forKey: .reason))
        } else if let n = try? c.nestedContainer(keyedBy: ReasonKeys.self, forKey: .decryptionFailed) {
            self = .decryptionFailed(reason: try n.decode(String.self, forKey: .reason),
                                     details: try n.decodeIfPresent(DecryptionDetails.self, forKey: .details)
                                              ?? DecryptionDetails())
        } else if let n = try? c.nestedContainer(keyedBy: KeyIDKeys.self, forKey: .keyNotFound) {
            self = .keyNotFound(keyID: try n.decode(String.self, forKey: .keyID))
        } else if c.contains(.plain) {
            self = .plain
        } else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath,
                debugDescription: "Unrecognised SecurityStatus case"))
        }
    }
}
