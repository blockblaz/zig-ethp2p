//! discv5 cryptographic primitives.
//!
//! Session keys are derived via ECDH on secp256k1 + HKDF-SHA256 (discv5 spec §6).
//! Packets are encrypted with AES-128-GCM.
//!
//! secp256k1 operations use the BoringSSL EC_KEY / ECDH APIs vendored via
//! lsquic_zig.  BoringSSL is always compiled (not gated on -Denable-quic)
//! because the discovery layer needs these primitives independently of
//! whether the QUIC transport shim is active.

const std = @import("std");

const aes_gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const sha256 = std.crypto.hash.sha2.Sha256;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

const ossl = @cImport({
    @cInclude("openssl/bn.h");
    @cInclude("openssl/ec_key.h");
    @cInclude("openssl/ecdh.h");
    @cInclude("openssl/nid.h");
});

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
// secp256k1  (BoringSSL EC_KEY / ECDH)
// ---------------------------------------------------------------------------

pub const Secp256k1Error = error{
    /// secp256k1 operation failed (invalid key, point-at-infinity, etc.).
    Secp256k1Error,
};

/// Generate an ephemeral secp256k1 keypair.
/// `privkey_out` receives the 32-byte big-endian scalar.
/// `pubkey_out` receives the 33-byte compressed public key (0x02/0x03 + x).
pub fn generateEphemeralKeypair(
    privkey_out: *[privkey_len]u8,
    pubkey_out: *[pubkey_len]u8,
) Secp256k1Error!void {
    const key = ossl.EC_KEY_new_by_curve_name(ossl.NID_secp256k1) orelse
        return error.Secp256k1Error;
    defer ossl.EC_KEY_free(key);

    if (ossl.EC_KEY_generate_key(key) != 1) return error.Secp256k1Error;

    // Private key — big-endian scalar, zero-padded to 32 bytes.
    const privbn = ossl.EC_KEY_get0_private_key(key) orelse return error.Secp256k1Error;
    if (ossl.BN_bn2binpad(privbn, privkey_out, privkey_len) < 0) return error.Secp256k1Error;

    // Compressed public key (0x02/0x03 + 32-byte x).
    const group = ossl.EC_KEY_get0_group(key) orelse return error.Secp256k1Error;
    const point = ossl.EC_KEY_get0_public_key(key) orelse return error.Secp256k1Error;
    const written = ossl.EC_POINT_point2oct(
        group,
        point,
        ossl.POINT_CONVERSION_COMPRESSED,
        pubkey_out,
        pubkey_len,
        null,
    );
    if (written != pubkey_len) return error.Secp256k1Error;
}

/// Compute the ECDH shared secret (raw x-coordinate of the product point).
/// `local_privkey` is our 32-byte scalar; `remote_pubkey` is the 33-byte
/// compressed public key of the peer.
pub fn ecdhSharedSecret(
    secret_out: *[32]u8,
    local_privkey: [privkey_len]u8,
    remote_pubkey: [pubkey_len]u8,
) Secp256k1Error!void {
    // Build the local EC_KEY from the raw private scalar.
    const local_key = ossl.EC_KEY_new_by_curve_name(ossl.NID_secp256k1) orelse
        return error.Secp256k1Error;
    defer ossl.EC_KEY_free(local_key);

    const privbn = ossl.BN_bin2bn(&local_privkey, privkey_len, null) orelse
        return error.Secp256k1Error;
    defer ossl.BN_free(privbn);

    if (ossl.EC_KEY_set_private_key(local_key, privbn) != 1) return error.Secp256k1Error;

    // Decode the remote compressed public key into an EC_POINT.
    const group = ossl.EC_KEY_get0_group(local_key) orelse return error.Secp256k1Error;
    const remote_point = ossl.EC_POINT_new(group) orelse return error.Secp256k1Error;
    defer ossl.EC_POINT_free(remote_point);

    if (ossl.EC_POINT_oct2point(group, remote_point, &remote_pubkey, pubkey_len, null) != 1)
        return error.Secp256k1Error;

    // ECDH — KDF=null gives us the raw x-coordinate (32 bytes for secp256k1).
    const written = ossl.ECDH_compute_key(secret_out, 32, remote_point, local_key, null);
    if (written != 32) return error.Secp256k1Error;
}

/// Derive the discv5 NodeId from a secp256k1 compressed public key.
/// NodeId = keccak256(uncompressed_pubkey[1..])  (discv5 spec §4.1).
pub fn nodeIdFromPubkey(pubkey: [pubkey_len]u8) Secp256k1Error![node_id_len]u8 {
    // Decompress the key to 65-byte uncompressed form (0x04 + x + y).
    const key = ossl.EC_KEY_new_by_curve_name(ossl.NID_secp256k1) orelse
        return error.Secp256k1Error;
    defer ossl.EC_KEY_free(key);

    const group = ossl.EC_KEY_get0_group(key) orelse return error.Secp256k1Error;
    const point = ossl.EC_POINT_new(group) orelse return error.Secp256k1Error;
    defer ossl.EC_POINT_free(point);

    if (ossl.EC_POINT_oct2point(group, point, &pubkey, pubkey_len, null) != 1)
        return error.Secp256k1Error;

    var uncompressed: [65]u8 = undefined;
    const written = ossl.EC_POINT_point2oct(
        group,
        point,
        ossl.POINT_CONVERSION_UNCOMPRESSED,
        &uncompressed,
        65,
        null,
    );
    if (written != 65) return error.Secp256k1Error;

    // Hash the 64-byte payload (strip the 0x04 prefix).
    var node_id: [node_id_len]u8 = undefined;
    Keccak256.hash(uncompressed[1..], &node_id, .{});
    return node_id;
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

test "secp256k1 keygen and ECDH roundtrip" {
    var priv_a: [privkey_len]u8 = undefined;
    var pub_a: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv_a, &pub_a);

    var priv_b: [privkey_len]u8 = undefined;
    var pub_b: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv_b, &pub_b);

    // ECDH(a_priv, b_pub) must equal ECDH(b_priv, a_pub).
    var secret_ab: [32]u8 = undefined;
    var secret_ba: [32]u8 = undefined;
    try ecdhSharedSecret(&secret_ab, priv_a, pub_b);
    try ecdhSharedSecret(&secret_ba, priv_b, pub_a);
    try std.testing.expectEqualSlices(u8, &secret_ab, &secret_ba);
}

test "nodeIdFromPubkey produces 32-byte keccak256" {
    var priv: [privkey_len]u8 = undefined;
    var pub_key: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv, &pub_key);

    const node_id = try nodeIdFromPubkey(pub_key);
    try std.testing.expectEqual(@as(usize, 32), node_id.len);

    // Node IDs derived from different keys must differ.
    var priv2: [privkey_len]u8 = undefined;
    var pub_key2: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv2, &pub_key2);
    const node_id2 = try nodeIdFromPubkey(pub_key2);
    try std.testing.expect(!std.mem.eql(u8, &node_id, &node_id2));
}
