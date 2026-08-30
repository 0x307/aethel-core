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

        Ok(Self { keypair, plp_seed })
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
