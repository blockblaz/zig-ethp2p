//! discv5 cryptographic primitives.
//!
//! All secp256k1 operations use Zig's standard library (`std.crypto.ecc.Secp256k1`
//! and `std.crypto.ecdsa`), which has had native secp256k1 support since 0.15.
//! No BoringSSL dependency is required here.
//!
//! Session keys are derived via ECDH on secp256k1 + HKDF-SHA256 (discv5 spec §6).
//! Packets are encrypted with AES-128-GCM.

const std = @import("std");

const aes_gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const sha256 = std.crypto.hash.sha2.Sha256;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;

/// ECDSA over secp256k1 with Keccak-256 (Ethereum convention).
const EcdsaK = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

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
/// Compact ECDSA signature: 32-byte r followed by 32-byte s.
pub const ecdsa_sig_len: usize = 64;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

pub const Secp256k1Error = error{
    /// secp256k1 operation failed (invalid key, point-at-infinity, etc.).
    Secp256k1Error,
};

// ---------------------------------------------------------------------------
// Session key material (discv5 spec §6.4)
// ---------------------------------------------------------------------------

pub const SessionKeys = struct {
    /// Key for encrypting messages to the peer.
    initiator_key: [aes_key_len]u8,
    /// Key for decrypting messages from the peer.
    recipient_key: [aes_key_len]u8,
};

/// HKDF info string from the discv5 spec.
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

/// Encrypt `plaintext`, appending a 16-byte authentication tag.
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
// SHA-256 helper
// ---------------------------------------------------------------------------

pub fn sha256Digest(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    sha256.hash(data, &out, .{});
    return out;
}

// ---------------------------------------------------------------------------
// secp256k1 key generation  (pure Zig std.crypto)
// ---------------------------------------------------------------------------

/// Generate an ephemeral secp256k1 keypair using the OS CSPRNG.
/// `privkey_out` receives the 32-byte big-endian scalar.
/// `pubkey_out` receives the 33-byte compressed public key (0x02/0x03 + x).
pub fn generateEphemeralKeypair(
    privkey_out: *[privkey_len]u8,
    pubkey_out: *[pubkey_len]u8,
) Secp256k1Error!void {
    const kp = EcdsaK.KeyPair.generate();
    privkey_out.* = kp.secret_key.toBytes();
    pubkey_out.* = kp.public_key.toCompressedSec1();
}

/// Derive the compressed public key from a private scalar.
pub fn generatePubkey(pubkey_out: *[pubkey_len]u8, privkey: [privkey_len]u8) Secp256k1Error!void {
    const sk = EcdsaK.SecretKey.fromBytes(privkey) catch return error.Secp256k1Error;
    const kp = EcdsaK.KeyPair.fromSecretKey(sk) catch return error.Secp256k1Error;
    pubkey_out.* = kp.public_key.toCompressedSec1();
}

// ---------------------------------------------------------------------------
// ECDH shared secret  (pure Zig std.crypto)
// ---------------------------------------------------------------------------

/// Compute the ECDH shared secret (raw x-coordinate of the product point).
/// `local_privkey` is our 32-byte scalar; `remote_pubkey` is the 33-byte
/// compressed public key of the peer.
pub fn ecdhSharedSecret(
    secret_out: *[32]u8,
    local_privkey: [privkey_len]u8,
    remote_pubkey: [pubkey_len]u8,
) Secp256k1Error!void {
    const pub_point = Secp256k1.fromSec1(&remote_pubkey) catch return error.Secp256k1Error;
    const shared = pub_point.mul(local_privkey, .big) catch return error.Secp256k1Error;
    secret_out.* = shared.affineCoordinates().x.toBytes(.big);
}

// ---------------------------------------------------------------------------
// Node ID derivation  (pure Zig std.crypto)
// ---------------------------------------------------------------------------

/// Derive the discv5 NodeId from a secp256k1 compressed public key.
/// NodeId = keccak256(uncompressed_pubkey[1..])  (discv5 spec §4.1).
pub fn nodeIdFromPubkey(pubkey: [pubkey_len]u8) Secp256k1Error![node_id_len]u8 {
    const pk = EcdsaK.PublicKey.fromSec1(&pubkey) catch return error.Secp256k1Error;
    const uncompressed = pk.toUncompressedSec1(); // 65 bytes: 0x04 || x || y
    var node_id: [node_id_len]u8 = undefined;
    Keccak256.hash(uncompressed[1..], &node_id, .{}); // hash x || y (64 bytes)
    return node_id;
}

// ---------------------------------------------------------------------------
// ECDSA sign / verify  (pure Zig std.crypto, secp256k1 + Keccak-256)
// ---------------------------------------------------------------------------

/// Sign `message` with a secp256k1 private key.
/// The signature covers keccak256(message).
/// `sig_out` receives the 64-byte compact signature (r || s).
pub fn ecdsaSign(
    sig_out: *[ecdsa_sig_len]u8,
    message: []const u8,
    privkey: [privkey_len]u8,
) Secp256k1Error!void {
    const sk = EcdsaK.SecretKey.fromBytes(privkey) catch return error.Secp256k1Error;
    const kp = EcdsaK.KeyPair.fromSecretKey(sk) catch return error.Secp256k1Error;
    const sig = kp.sign(message, null) catch return error.Secp256k1Error;
    sig_out.* = sig.toBytes();
}

/// Verify a compact (r || s) signature over keccak256(message).
pub fn ecdsaVerify(
    sig_bytes: [ecdsa_sig_len]u8,
    message: []const u8,
    pubkey: [pubkey_len]u8,
) Secp256k1Error!void {
    const pk = EcdsaK.PublicKey.fromSec1(&pubkey) catch return error.Secp256k1Error;
    const sig = EcdsaK.Signature.fromBytes(sig_bytes);
    sig.verify(message, pk) catch return error.Secp256k1Error;
}

// ---------------------------------------------------------------------------
// discv5 id-nonce signature  (streaming, multi-part message)
// ---------------------------------------------------------------------------

/// Sign the discv5 id-nonce challenge (discv5 spec §5.4).
/// Covers: keccak256("discv5 id nonce" || challenge_data || eph_pubkey || dest_id).
pub fn ecdsaSignIdNonce(
    sig_out: *[ecdsa_sig_len]u8,
    challenge_data: []const u8,
    eph_pubkey: [pubkey_len]u8,
    dest_id: [node_id_len]u8,
    privkey: [privkey_len]u8,
) Secp256k1Error!void {
    const sk = EcdsaK.SecretKey.fromBytes(privkey) catch return error.Secp256k1Error;
    const kp = EcdsaK.KeyPair.fromSecretKey(sk) catch return error.Secp256k1Error;
    var st = kp.signer(null) catch return error.Secp256k1Error;
    st.update("discv5 id nonce");
    st.update(challenge_data);
    st.update(&eph_pubkey);
    st.update(&dest_id);
    const sig = st.finalize() catch return error.Secp256k1Error;
    sig_out.* = sig.toBytes();
}

/// Verify a discv5 id-nonce signature.
pub fn ecdsaVerifyIdNonce(
    sig_bytes: [ecdsa_sig_len]u8,
    challenge_data: []const u8,
    eph_pubkey: [pubkey_len]u8,
    dest_id: [node_id_len]u8,
    pubkey: [pubkey_len]u8,
) Secp256k1Error!void {
    const pk = EcdsaK.PublicKey.fromSec1(&pubkey) catch return error.Secp256k1Error;
    const sig = EcdsaK.Signature.fromBytes(sig_bytes);
    var v = sig.verifier(pk) catch return error.Secp256k1Error;
    v.update("discv5 id nonce");
    v.update(challenge_data);
    v.update(&eph_pubkey);
    v.update(&dest_id);
    v.verify() catch return error.Secp256k1Error;
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
    ct[0] ^= 0xff;

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

    var priv2: [privkey_len]u8 = undefined;
    var pub_key2: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv2, &pub_key2);
    const node_id2 = try nodeIdFromPubkey(pub_key2);
    try std.testing.expect(!std.mem.eql(u8, &node_id, &node_id2));
}

test "nodeIdFromPubkey is deterministic" {
    const privkey = [_]u8{0x99} ** privkey_len;
    var pubkey: [pubkey_len]u8 = undefined;
    try generatePubkey(&pubkey, privkey);
    const id1 = try nodeIdFromPubkey(pubkey);
    const id2 = try nodeIdFromPubkey(pubkey);
    try std.testing.expectEqual(id1, id2);
}

test "ecdsaSign and ecdsaVerify roundtrip" {
    var priv: [privkey_len]u8 = undefined;
    var pub_key: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv, &pub_key);

    const message = "test content for ecdsa signing";
    var sig: [ecdsa_sig_len]u8 = undefined;
    try ecdsaSign(&sig, message, priv);
    try ecdsaVerify(sig, message, pub_key);
}

test "ecdsaVerify rejects wrong message" {
    var priv: [privkey_len]u8 = undefined;
    var pub_key: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv, &pub_key);

    var sig: [ecdsa_sig_len]u8 = undefined;
    try ecdsaSign(&sig, "correct message", priv);
    try std.testing.expectError(
        error.Secp256k1Error,
        ecdsaVerify(sig, "wrong message", pub_key),
    );
}

test "ecdsaSignIdNonce and ecdsaVerifyIdNonce roundtrip" {
    var priv: [privkey_len]u8 = undefined;
    var pub_key: [pubkey_len]u8 = undefined;
    try generateEphemeralKeypair(&priv, &pub_key);

    const challenge = [_]u8{0xaa} ** 32;
    const eph_pub = [_]u8{0x02} ++ [_]u8{0xbb} ** 32;
    const dest = [_]u8{0xcc} ** node_id_len;

    var sig: [ecdsa_sig_len]u8 = undefined;
    try ecdsaSignIdNonce(&sig, &challenge, eph_pub, dest, priv);
    try ecdsaVerifyIdNonce(sig, &challenge, eph_pub, dest, pub_key);
}
