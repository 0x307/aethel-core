// aethel-core/c/ct_sampling.c — Fixed-Time Rejection Sampling Loop for Enclave

void enclave_plp_prove_fixed_time(
    uint8_t *proof_out,
    const int32_t s[MODULE_K][RING_N],
    const uint8_t tau[32]
) {
    uint32_t proof_captured = 0;
    uint8_t candidate_proof[sizeof(plp_proof_t)];
    uint8_t dummy_proof[sizeof(plp_proof_t)];
    for (size_t iter = 0; iter < 16; iter++) {
        // 1. Generate candidate y and compute candidate z
        int32_t z[MODULE_K][RING_N];
        plp_generate_candidate(z, s, tau, iter);
        // 2. Constant-time norm check (0 = ACCEPT, 0xFFFFFFFF = REJECT)
        uint32_t reject_mask = ct_check_norm_bound(z, GAMMA1 - BETA);
        // 3. Constant-time selection: capture if valid AND not previously captured
        uint32_t capture_mask = (~reject_mask) & (~proof_captured);
        // Update target buffer or dummy buffer in constant time
        ct_cond_copy(candidate_proof, z, sizeof(candidate_proof), capture_mask);
        ct_cond_copy(dummy_proof, z, sizeof(dummy_proof), ~capture_mask);
        // Accumulate capture status
        proof_captured |= capture_mask;
    }
    // Copy out valid proof (or fail securely if all 16 iterations rejected)
    ct_cond_copy(proof_out, candidate_proof, sizeof(candidate_proof), proof_captured);
}
