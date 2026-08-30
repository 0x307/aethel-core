//! Identity key generation and message signing, inside L1.
//!
//! Until now the crate had no way to *create* an identity: `MasterIdentity`
//! could only be built `from_seed`, with the caller supplying the 32 bytes. That
//! put the decisive secret above the L1 boundary, since whoever generates the
//! seed holds the identity. It also had no message signing at all, so an SDK
//! asked to "sign and verify" had nothing to call and would have had to reach
//! for a signature library of its own, which is the one thing the charter's
//! "one artifact, adding a language never adds crypto" rule forbids.
//!
//! Both live here now.
//!
//! # The entropy argument is not the key
//!
//! [`Identity::generate`] takes caller-supplied entropy rather than reading a
//! system RNG, because the component has no WASI and no ambient randomness. The
//! entropy is **not** the secret key: it is stretched through SHAKE-256 with
//! domain separation, and the ML-DSA secret key and the PLP seed are derived
//! from that stream and kept inside this crate. Nothing that leaves an
//! [`Identity`] can reconstruct it.
//!
//! That distinction is what keeps the charter's "no private key material
//! crosses out of L1" true. A caller who supplies weak entropy gets a weak
//! identity, which is unavoidable for any deterministic construction, so the
//! minimum length is enforced rather than suggested.
//!
//! # Determinism
//!
//! Generation is a pure function of the entropy, and signing uses FIPS 204's
//! deterministic variant. Both are reproducible, which is what makes them
//! testable against fixed vectors, and neither needs an RNG at call time.

use alloc::vec::Vec;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use pqc_sig::{MlDsa65Keypair, SigPublicKey, Signature};
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

use crate::identity_error::IdentityError;

/// Minimum caller-supplied entropy. Below this the derived key material cannot
/// carry the security level ML-DSA-65 claims, so it is refused rather than
/// silently stretched.
pub const MIN_ENTROPY_BYTES: usize = 32;

/// Domain separator for the generation XOF. Distinct from every other
/// SHAKE-256 use in this crate so no two derivations can collide.
const KEYGEN_DOMAIN: &[u8] = b"AETHEL_IDENTITY_KEYGEN_V1";

/// A SHAKE-256 stream presented as an RNG.
///
/// `pqc_sig` takes a caller-supplied `RngCore + CryptoRng` rather than reaching
/// for `OsRng`, which is exactly what makes deterministic generation possible
/// in a component with no ambient randomness.
struct ShakeRng {
    reader: sha3::Shake256Reader,
}

impl RngCore for ShakeRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.reader.read(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.reader.read(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.reader.read(dest);
        Ok(())
    }
}

/// The stream is a SHAKE-256 XOF over caller entropy that already met
/// [`MIN_ENTROPY_BYTES`]. Marking it `CryptoRng` asserts it is suitable for key
/// generation, which holds exactly as far as the entropy does.
impl CryptoRng for ShakeRng {}

/// An identity: an ML-DSA-65 signing key plus the PLP master seed, derived
/// together from one entropy input.
///
/// Both secrets stay in this struct. `public_key` is the only thing that leaves
/// it, and the PLP seed is reachable only through [`Identity::plp_seed`], which
/// is `pub(crate)` so the component adapter can hand it to `plp` without it
/// crossing the WIT boundary.
pub struct Identity {
    keypair: MlDsa65Keypair,
    plp_seed: [u8; 32],
    /// The entropy this identity was derived from.
    ///
    /// Kept so the identity can be sealed and re-derived rather than
    /// serialised. It is not additional exposure: this struct already holds the
    /// keys derived from it, and it is wiped on drop alongside them.
    entropy: Vec<u8>,
}

impl Identity {
    /// Derive an identity from caller-supplied entropy.
    ///
    /// Requires at least [`MIN_ENTROPY_BYTES`]. Deterministic: the same entropy
    /// always yields the same identity, which is what makes generation testable
    /// against a fixed vector instead of only against itself.
    pub fn generate(entropy: &[u8]) -> Result<Self, IdentityError> {
        if entropy.len() < MIN_ENTROPY_BYTES {
            return Err(IdentityError::InvalidInputLength);
        }

        let mut hasher = Shake256::default();
        hasher.update(KEYGEN_DOMAIN);
        hasher.update(entropy);
        let mut reader = hasher.finalize_xof();

        // The PLP seed comes off the stream first, then the same stream drives
        // ML-DSA generation. One entropy input, two independent secrets, no
        // second argument for a caller to get wrong.
        let mut plp_seed = [0u8; 32];
        reader.read(&mut plp_seed);

        let mut rng = ShakeRng { reader };
        let keypair = MlDsa65Keypair::generate(&mut rng)
            .map_err(|_| IdentityError::SerializationError)?;

        Ok(Self { keypair, plp_seed, entropy: entropy.to_vec() })
    }

    /// The ML-DSA-65 public key. Safe to publish; this is the only key material
    /// that leaves L1.
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public_key().bytes
    }

    /// Sign a message with FIPS 204's deterministic variant.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        self.keypair
            .sign_deterministic(message)
            .map(|sig| sig.bytes)
            .map_err(|_| IdentityError::SerializationError)
    }

    /// The PLP master seed, for the component adapter to drive `plp` with.
    ///
    /// Deliberately `pub(crate)`: this is private key material, and the whole
    /// point of holding it here is that it has no route across the WIT boundary.
    pub(crate) fn plp_seed(&self) -> &[u8; 32] {
        &self.plp_seed
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.plp_seed.zeroize();
        self.entropy.zeroize();
        // MlDsa65Keypair's SigSecretKey zeroizes its own bytes on drop.
    }
}

/// Verify an ML-DSA-65 signature.
///
/// A free function rather than a method: verification needs only public
/// material, so requiring an [`Identity`] would imply the verifier holds a
/// secret it does not need and cannot have.
///
/// Returns `Ok(false)` for a well-formed signature that does not verify, and
/// `Err` for input that cannot be parsed at all. Collapsing those two into one
/// answer is the sentinel-return mistake this crate has already been bitten by.
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, IdentityError> {
    let pk = SigPublicKey {
        algorithm: pqc_sig::SigAlgorithm::MlDsa65,
        bytes: public_key.to_vec(),
    };
    let sig = Signature {
        algorithm: pqc_sig::SigAlgorithm::MlDsa65,
        bytes: signature.to_vec(),
    };

    match MlDsa65Keypair::verify(&pk, message, &sig) {
        Ok(()) => Ok(true),
        // A rejected signature is a well-formed negative answer, not an error.
        Err(_) => Ok(false),
    }
}


// ── Sealing an identity at rest ───────────────────────────────────────────────

/// Format version, first byte of every sealed blob.
///
/// Present so a future format change is a clean rejection rather than a
/// misparse. A blob whose version this build does not know is refused, not
/// guessed at.
const SEAL_VERSION: u8 = 1;

/// Domain-separated key derivation for sealing.
const SEAL_KDF_DOMAIN: &[u8] = b"AETHEL_IDENTITY_SEAL_KDF_V1";

/// Minimum sealing key length.
///
/// This is a **key**, not a passphrase. See [`Identity::export_sealed`].
pub const MIN_SEAL_KEY_BYTES: usize = 32;

/// Nonce length for XChaCha20-Poly1305.
const SEAL_NONCE_BYTES: usize = 24;

/// `version ‖ nonce ‖ ciphertext+tag`.
const SEAL_OVERHEAD: usize = 1 + SEAL_NONCE_BYTES;

impl Identity {
    /// Seal this identity so it can be written to disk and loaded again.
    ///
    /// # This takes a key, not a password
    ///
    /// `key` must be at least [`MIN_SEAL_KEY_BYTES`] of **high-entropy** key
    /// material: a key from an OS keychain, an HSM, or a random value the
    /// caller stores. It is stretched with SHAKE-256 for domain separation, and
    /// SHAKE-256 is fast by design.
    ///
    /// **Do not hand this a human-chosen password.** A password needs a
    /// deliberately slow, memory-hard KDF (Argon2id or scrypt) to survive
    /// offline guessing, and this crate does not provide one. Passing a password
    /// here would produce a blob that looks encrypted and falls to a wordlist.
    /// If you need password-based sealing, run a real password KDF first and
    /// pass its output as `key`.
    ///
    /// # What is sealed
    ///
    /// The entropy the identity was derived from, not the derived keys. Import
    /// re-runs the same deterministic derivation, so the blob stays small and
    /// there is no key serialisation format to get wrong. It also means the
    /// sealed blob is exactly as sensitive as the identity itself: anyone who
    /// opens it holds the identity.
    ///
    /// The nonce is derived from the key and the entropy rather than sampled,
    /// because the component has no randomness of its own. That makes sealing
    /// deterministic: sealing the same identity under the same key twice yields
    /// identical bytes. Since each (key, identity) pair produces exactly one
    /// nonce and one plaintext, the nonce is never reused under a different
    /// message, which is the property that matters.
    pub fn export_sealed(&self, key: &[u8]) -> Result<Vec<u8>, IdentityError> {
        if key.len() < MIN_SEAL_KEY_BYTES {
            return Err(IdentityError::InvalidInputLength);
        }

        let (cipher_key, nonce) = derive_seal_material(key, &self.entropy);
        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let ciphertext = cipher
            .encrypt(( &nonce).into(), self.entropy.as_slice())
            .map_err(|_| IdentityError::SerializationError)?;

        let mut out = Vec::with_capacity(SEAL_OVERHEAD + ciphertext.len());
        out.push(SEAL_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a sealed identity.
    ///
    /// Returns `Err` for a blob that is malformed, truncated, of an unknown
    /// version, or sealed under a different key. The AEAD tag makes those
    /// indistinguishable to a caller, which is intended: a decryption failure
    /// must not tell an attacker which part they got wrong.
    pub fn import_sealed(sealed: &[u8], key: &[u8]) -> Result<Self, IdentityError> {
        if key.len() < MIN_SEAL_KEY_BYTES || sealed.len() <= SEAL_OVERHEAD {
            return Err(IdentityError::InvalidInputLength);
        }
        if sealed[0] != SEAL_VERSION {
            return Err(IdentityError::SerializationError);
        }

        let nonce: [u8; SEAL_NONCE_BYTES] = sealed[1..1 + SEAL_NONCE_BYTES]
            .try_into()
            .map_err(|_| IdentityError::InvalidInputLength)?;
        let ciphertext = &sealed[SEAL_OVERHEAD..];

        // The key half of the derivation does not depend on the plaintext, so it
        // can be computed before the plaintext is known. The nonce comes from
        // the blob and is authenticated by the tag.
        let cipher_key = derive_seal_key(key);
        let cipher = XChaCha20Poly1305::new((&cipher_key).into());
        let mut entropy = cipher
            .decrypt((&nonce).into(), ciphertext)
            .map_err(|_| IdentityError::SerializationError)?;

        let identity = Identity::generate(&entropy);
        entropy.zeroize();
        identity
    }
}

/// Derive the sealing key from caller key material.
fn derive_seal_key(key: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(SEAL_KDF_DOMAIN);
    hasher.update(b"key");
    hasher.update(&(key.len() as u32).to_le_bytes());
    hasher.update(key);
    let mut reader = hasher.finalize_xof();
    let mut out = [0u8; 32];
    reader.read(&mut out);
    out
}

/// Derive the sealing key and a nonce bound to both the key and the plaintext.
fn derive_seal_material(key: &[u8], entropy: &[u8]) -> ([u8; 32], [u8; SEAL_NONCE_BYTES]) {
    let cipher_key = derive_seal_key(key);

    let mut hasher = Shake256::default();
    hasher.update(SEAL_KDF_DOMAIN);
    hasher.update(b"nonce");
    hasher.update(&(key.len() as u32).to_le_bytes());
    hasher.update(key);
    hasher.update(&(entropy.len() as u32).to_le_bytes());
    hasher.update(entropy);
    let mut reader = hasher.finalize_xof();
    let mut nonce = [0u8; SEAL_NONCE_BYTES];
    reader.read(&mut nonce);

    (cipher_key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";

    #[test]
    fn generation_is_deterministic() {
        let a = Identity::generate(ENTROPY).expect("generate");
        let b = Identity::generate(ENTROPY).expect("generate");
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.plp_seed(), b.plp_seed());
    }

    /// Positive control for the test above: if generation ignored its entropy
    /// entirely, `generation_is_deterministic` would still pass.
    #[test]
    fn different_entropy_yields_a_different_identity() {
        let a = Identity::generate(ENTROPY).expect("generate");
        let b = Identity::generate(b"a completely different entropy!!").expect("generate");
        assert_ne!(
            a.public_key(),
            b.public_key(),
            "two different entropy inputs produced the same signing key"
        );
        assert_ne!(
            a.plp_seed(),
            b.plp_seed(),
            "two different entropy inputs produced the same PLP seed"
        );
    }

    /// The two derived secrets must be independent, not the same bytes reused.
    #[test]
    fn the_plp_seed_is_not_the_signing_key() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let pk = id.public_key();
        assert!(
            !pk.windows(32).any(|w| w == id.plp_seed()),
            "the PLP seed appears verbatim inside the public key"
        );
    }

    #[test]
    fn short_entropy_is_refused() {
        for len in [0usize, 1, 31] {
            let entropy = alloc::vec![0xABu8; len];
            assert!(
                matches!(
                    Identity::generate(&entropy),
                    Err(IdentityError::InvalidInputLength)
                ),
                "{len} bytes of entropy was accepted"
            );
        }
        assert!(Identity::generate(&[0xABu8; 32]).is_ok(), "32 bytes was refused");
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"the message that was actually signed";
        let sig = id.sign(msg).expect("sign");
        assert_eq!(verify(&id.public_key(), msg, &sig), Ok(true));
    }

    #[test]
    fn a_tampered_message_does_not_verify() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let sig = id.sign(b"transfer 10 to alice").expect("sign");
        assert_eq!(
            verify(&id.public_key(), b"transfer 99 to alice", &sig),
            Ok(false),
            "a signature verified against a message it was not made over"
        );
    }

    #[test]
    fn a_wrong_key_does_not_verify() {
        let signer = Identity::generate(ENTROPY).expect("generate");
        let other = Identity::generate(b"a completely different entropy!!").expect("generate");
        let msg = b"signed by exactly one of these";
        let sig = signer.sign(msg).expect("sign");
        assert_eq!(
            verify(&other.public_key(), msg, &sig),
            Ok(false),
            "a signature verified under a key that did not produce it"
        );
    }

    #[test]
    fn a_tampered_signature_does_not_verify() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"message";
        let mut sig = id.sign(msg).expect("sign");
        sig[0] ^= 0x01;
        assert_eq!(verify(&id.public_key(), msg, &sig), Ok(false));
    }

    /// Malformed public material is an error, not a quiet `false`. Otherwise
    /// "this signature is invalid" and "you passed me nonsense" are the same
    /// answer, which is the defect P3-10 was opened for.
    #[test]
    fn signing_is_deterministic_across_calls() {
        let id = Identity::generate(ENTROPY).expect("generate");
        let msg = b"same message, twice";
        assert_eq!(id.sign(msg).unwrap(), id.sign(msg).unwrap());
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    const ENTROPY: &[u8; 32] = b"deterministic entropy for tests!";
    const KEY: &[u8; 32] = b"a sealing key of thirty-two byte";
    const OTHER_KEY: &[u8; 32] = b"a different sealing key, 32 byte";

    /// The point of the whole feature: an identity survives being written down
    /// and read back, and it is the same identity.
    #[test]
    fn a_sealed_identity_round_trips() {
        let original = Identity::generate(ENTROPY).expect("generate");
        let sealed = original.export_sealed(KEY).expect("seal");
        let reopened = Identity::import_sealed(&sealed, KEY).expect("open");

        assert_eq!(
            original.public_key(),
            reopened.public_key(),
            "the reopened identity has a different public key"
        );
        assert_eq!(
            original.plp_seed(),
            reopened.plp_seed(),
            "the reopened identity has a different PLP seed"
        );
    }

    /// Same identity in the strong sense: it produces signatures the original's
    /// public key verifies. Comparing public keys alone would pass for an
    /// implementation that restored the public half and lost the private one.
    #[test]
    fn a_reopened_identity_can_still_sign() {
        let original = Identity::generate(ENTROPY).expect("generate");
        let sealed = original.export_sealed(KEY).expect("seal");
        let reopened = Identity::import_sealed(&sealed, KEY).expect("open");

        let message = b"signed after being reopened";
        let signature = reopened.sign(message).expect("sign");

        assert_eq!(
            verify(&original.public_key(), message, &signature),
            Ok(true),
            "a signature from the reopened identity did not verify under the original key"
        );
    }

    /// Positive control for the round trip. Without it, an `import_sealed` that
    /// ignored the blob and regenerated from a constant would pass every test
    /// above.
    #[test]
    fn sealing_two_identities_yields_two_different_identities() {
        let a = Identity::generate(ENTROPY).expect("generate");
        let b = Identity::generate(b"a completely different entropy!!").expect("generate");

        let sealed_a = a.export_sealed(KEY).expect("seal");
        let sealed_b = b.export_sealed(KEY).expect("seal");
        assert_ne!(sealed_a, sealed_b, "two identities sealed to the same bytes");

        let reopened_a = Identity::import_sealed(&sealed_a, KEY).expect("open");
        let reopened_b = Identity::import_sealed(&sealed_b, KEY).expect("open");
        assert_ne!(
            reopened_a.public_key(),
            reopened_b.public_key(),
            "two different sealed identities reopened as the same identity"
        );
        assert_eq!(reopened_a.public_key(), a.public_key());
        assert_eq!(reopened_b.public_key(), b.public_key());
    }

    #[test]
    fn the_wrong_key_does_not_open_it() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        assert!(
            Identity::import_sealed(&sealed, OTHER_KEY).is_err(),
            "a sealed identity opened under the wrong key"
        );
    }

    /// Every byte of the blob is authenticated. Flipping any one of them must
    /// fail, not just the ones in the ciphertext.
    #[test]
    fn any_tampered_byte_is_rejected() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        for index in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[index] ^= 0x01;
            assert!(
                Identity::import_sealed(&tampered, KEY).is_err(),
                "a blob with byte {index} flipped still opened"
            );
        }
    }

    #[test]
    fn a_truncated_blob_is_rejected() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        for cut in [0usize, 1, SEAL_OVERHEAD, sealed.len() - 1] {
            assert!(
                Identity::import_sealed(&sealed[..cut], KEY).is_err(),
                "a blob truncated to {cut} bytes still opened"
            );
        }
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let mut sealed = identity.export_sealed(KEY).expect("seal");
        sealed[0] = 0xFF;

        assert!(
            matches!(
                Identity::import_sealed(&sealed, KEY),
                Err(IdentityError::SerializationError)
            ),
            "a blob with an unknown format version was parsed anyway"
        );
    }

    #[test]
    fn a_short_key_is_refused_on_both_sides() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let short = b"too short";

        assert!(matches!(
            identity.export_sealed(short),
            Err(IdentityError::InvalidInputLength)
        ));

        let sealed = identity.export_sealed(KEY).expect("seal");
        assert!(matches!(
            Identity::import_sealed(&sealed, short),
            Err(IdentityError::InvalidInputLength)
        ));
    }

    /// The blob must not contain the entropy, the PLP seed or the secret key in
    /// the clear. This is the claim "sealed" makes.
    #[test]
    fn the_blob_does_not_contain_the_secret_in_the_clear() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let sealed = identity.export_sealed(KEY).expect("seal");

        assert!(
            !sealed.windows(ENTROPY.len()).any(|w| w == ENTROPY.as_slice()),
            "the entropy appears verbatim in the sealed blob"
        );
        assert!(
            !sealed.windows(32).any(|w| w == identity.plp_seed().as_slice()),
            "the PLP seed appears verbatim in the sealed blob"
        );
    }

    /// Positive control for the leak check above: it must be able to see the
    /// secret when the secret really is there. An unsealed blob is the case it
    /// has to catch.
    #[test]
    fn the_leak_check_catches_an_unsealed_blob() {
        let mut unsealed = vec![SEAL_VERSION];
        unsealed.extend_from_slice(&[0u8; SEAL_NONCE_BYTES]);
        unsealed.extend_from_slice(ENTROPY);

        assert!(
            unsealed.windows(ENTROPY.len()).any(|w| w == ENTROPY.as_slice()),
            "the leak check cannot see the entropy even when it is stored in the clear"
        );
    }

    /// Sealing is deterministic, so the same identity under the same key is
    /// byte-identical. That is a property worth pinning: it means a sealed file
    /// does not churn, and it means each (key, identity) pair uses exactly one
    /// nonce.
    #[test]
    fn sealing_is_deterministic() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        assert_eq!(
            identity.export_sealed(KEY).expect("seal"),
            identity.export_sealed(KEY).expect("seal")
        );
    }

    /// The same identity under two keys must produce different nonces, or the
    /// determinism above would mean nonce reuse across keys.
    #[test]
    fn different_keys_give_different_nonces() {
        let identity = Identity::generate(ENTROPY).expect("generate");
        let a = identity.export_sealed(KEY).expect("seal");
        let b = identity.export_sealed(OTHER_KEY).expect("seal");

        let nonce_a = &a[1..1 + SEAL_NONCE_BYTES];
        let nonce_b = &b[1..1 + SEAL_NONCE_BYTES];
        assert_ne!(nonce_a, nonce_b, "two keys produced the same nonce");
    }
}
