//! discv5 cryptographic primitives.
//!
//! Session keys are derived via ECDH on secp256k1 + HKDF-SHA256 (discv5 spec §6).
//! Packets are encrypted with AES-128-GCM.
//!
//! secp256k1 ECDH is not in the Zig standard library.  Those operations are
//! stubbed here with clear TODOs; everything else (AES-GCM, HKDF, SHA256)
//! uses `std.crypto` directly.

const std = @import("std");
const aes_gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-128-GCM key size in bytes.
pub const aes_key_len: usize = aes_gcm.key_length; // 16
/// AES-GCM nonce size in bytes.
pub const aes_nonce_len: usize = aes_gcm.nonce_length; // 12
/// AES-GCM authentication tag size in bytes.
pub const aes_tag_len: usize = aes_gcm.tag_length; // 16
/// secp256k1 compressed public key size in bytes.
pub const pubkey_len: usize = 33;
/// secp256k1 private key (scalar) size in bytes.
pub const privkey_len: usize = 32;
/// Node ID size (keccak256 of uncompressed pubkey[1..]).
pub const node_id_len: usize = 32;

// ---------------------------------------------------------------------------
// Session key material (discv5 spec §6.4)
// ---------------------------------------------------------------------------

pub const SessionKeys = struct {
    /// Key for encrypting messages to the peer.
    initiator_key: [aes_key_len]u8,
    /// Key for decrypting messages from the peer.
    recipient_key: [aes_key_len]u8,
};

/// HKDF info strings from the discv5 spec.
const hkdf_info_initiator: []const u8 = "discv5 key agreement";

/// Derive session keys from a shared ECDH secret.
/// `id_nonce` is the challenge nonce from WHOAREYOU; `ephem_pubkey` is the
/// ephemeral public key sent by the initiator.
pub fn deriveSessionKeys(
    secret: [32]u8,
    id_nonce: [16]u8,
    ephem_pubkey: [pubkey_len]u8,
    local_node_id: [node_id_len]u8,
    remote_node_id: [node_id_len]u8,
) SessionKeys {
    // PRK = HKDF-Extract(salt=id_nonce, ikm=secret)
    const prk = hkdf.extract(&id_nonce, &secret);

    // Expand two keys using distinct info strings.
    var info_buf: [128]u8 = undefined;
    const info_len = std.fmt.bufPrint(&info_buf, "{s}{s}{s}{s}", .{
        hkdf_info_initiator,
        ephem_pubkey,
        local_node_id,
        remote_node_id,
    }) catch unreachable;

    var initiator_key: [aes_key_len]u8 = undefined;
    hkdf.expand(&initiator_key, info_buf[0..info_len.len], prk);

    var recipient_key: [aes_key_len]u8 = undefined;
    // Swap node ID order for the recipient direction.
    const info2_len = std.fmt.bufPrint(&info_buf, "{s}{s}{s}{s}", .{
        hkdf_info_initiator,
        ephem_pubkey,
        remote_node_id,
        local_node_id,
    }) catch unreachable;
    hkdf.expand(&recipient_key, info_buf[0..info2_len.len], prk);

    return .{
        .initiator_key = initiator_key,
        .recipient_key = recipient_key,
    };
}

// ---------------------------------------------------------------------------
// AES-128-GCM encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` in-place, appending a 16-byte tag.
/// `nonce` must be unique per key; `aad` is additional authenticated data.
pub fn encryptAesGcm(
    ciphertext_and_tag: []u8,
    plaintext: []const u8,
    aad: []const u8,
    key: [aes_key_len]u8,
    nonce: [aes_nonce_len]u8,
) void {
    std.debug.assert(ciphertext_and_tag.len == plaintext.len + aes_tag_len);
    var tag: [aes_tag_len]u8 = undefined;
    aes_gcm.encrypt(
        ciphertext_and_tag[0..plaintext.len],
        &tag,
        plaintext,
        aad,
        nonce,
        key,
    );
    @memcpy(ciphertext_and_tag[plaintext.len..], &tag);
}

/// Decrypt `ciphertext` (last 16 bytes are the tag) into `plaintext`.
/// Returns error.AuthenticationFailed on tag mismatch.
pub fn decryptAesGcm(
    plaintext: []u8,
    ciphertext_and_tag: []const u8,
    aad: []const u8,
    key: [aes_key_len]u8,
    nonce: [aes_nonce_len]u8,
) error{AuthenticationFailed}!void {
    if (ciphertext_and_tag.len < aes_tag_len) return error.AuthenticationFailed;
    const ct_len = ciphertext_and_tag.len - aes_tag_len;
    const tag = ciphertext_and_tag[ct_len..][0..aes_tag_len];
    aes_gcm.decrypt(
        plaintext,
        ciphertext_and_tag[0..ct_len],
        tag.*,
        aad,
        nonce,
        key,
    ) catch return error.AuthenticationFailed;
}

// ---------------------------------------------------------------------------
// SHA-256 helpers
// ---------------------------------------------------------------------------

pub fn sha256Digest(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    sha256.hash(data, &out, .{});
    return out;
}

// ---------------------------------------------------------------------------
// secp256k1 stubs
// (requires BoringSSL EC_KEY / ECDH — already vendored via lsquic_zig)
// TODO: call BoringSSL EC_KEY_generate_key / ECDH_compute_key
// ---------------------------------------------------------------------------

pub const Secp256k1Error = error{
    /// secp256k1 operation failed (invalid key, point-at-infinity, etc.).
    Secp256k1Error,
};

/// Placeholder: generate an ephemeral secp256k1 keypair.
/// TODO: implement via BoringSSL `EC_KEY_generate_key`.
pub fn generateEphemeralKeypair(
    privkey_out: *[privkey_len]u8,
    pubkey_out: *[pubkey_len]u8,
) Secp256k1Error!void {
    _ = privkey_out;
    _ = pubkey_out;
    return error.Secp256k1Error; // Not yet implemented.
}

/// Placeholder: ECDH shared secret from local privkey and remote pubkey.
/// TODO: implement via BoringSSL `ECDH_compute_key`.
pub fn ecdhSharedSecret(
    secret_out: *[32]u8,
    local_privkey: [privkey_len]u8,
    remote_pubkey: [pubkey_len]u8,
) Secp256k1Error!void {
    _ = secret_out;
    _ = local_privkey;
    _ = remote_pubkey;
    return error.Secp256k1Error; // Not yet implemented.
}

/// Placeholder: derive NodeId from a secp256k1 compressed pubkey.
/// NodeId = keccak256(uncompressed_pubkey[1..]) — the keccak256 part also
/// requires an external library (or a pure-Zig implementation).
/// TODO: decompress pubkey via BoringSSL, then keccak256.
pub fn nodeIdFromPubkey(pubkey: [pubkey_len]u8) [node_id_len]u8 {
    // Fallback: sha256 of the compressed key (incorrect, only for scaffolding).
    _ = pubkey;
    return [_]u8{0} ** node_id_len;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "AES-GCM encrypt then decrypt roundtrip" {
    const key: [aes_key_len]u8 = [_]u8{0x42} ** aes_key_len;
    const nonce: [aes_nonce_len]u8 = [_]u8{0x11} ** aes_nonce_len;
    const plaintext = "hello discv5";
    const aad = "aad-bytes";

    var ct: [plaintext.len + aes_tag_len]u8 = undefined;
    encryptAesGcm(&ct, plaintext, aad, key, nonce);

    var pt: [plaintext.len]u8 = undefined;
    try decryptAesGcm(&pt, &ct, aad, key, nonce);
    try std.testing.expectEqualStrings(plaintext, &pt);
}

test "AES-GCM rejects tampered ciphertext" {
    const key: [aes_key_len]u8 = [_]u8{0x01} ** aes_key_len;
    const nonce: [aes_nonce_len]u8 = [_]u8{0} ** aes_nonce_len;
    const plaintext = "tamper me";

    var ct: [plaintext.len + aes_tag_len]u8 = undefined;
    encryptAesGcm(&ct, plaintext, "", key, nonce);
    ct[0] ^= 0xff; // Flip a byte.

    var pt: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, decryptAesGcm(&pt, &ct, "", key, nonce));
}

test "sha256Digest produces 32 bytes" {
    const d = sha256Digest("ethp2p");
    try std.testing.expectEqual(@as(usize, 32), d.len);
}
