// SPDX-License-Identifier: BSD-2-Clause
/*
 * ECDSA Sign TA - Trusted Application for ECDSA signing benchmarks
 * Measures signing time on Cortex-A72 via QEMU
 */

#include <inttypes.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <ecdsa_sign_ta.h>

struct ecdsa_state {
	TEE_ObjectHandle key;
	uint32_t key_size;
};

/* Get current time in TEE */
static void get_time(TEE_Time *time)
{
	TEE_GetREETime(time);
}

/* Calculate time difference in nanoseconds */
static uint64_t time_diff_ns(TEE_Time *start, TEE_Time *end)
{
	uint64_t diff_sec = end->seconds - start->seconds;
	int64_t diff_ms = (int64_t)end->millis - (int64_t)start->millis;

	return diff_sec * 1000000000ULL + diff_ms * 1000000ULL;
}

static TEE_Result cmd_gen_key(struct ecdsa_state *state, uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_ECDSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;

	/* Validate key size - support P-256 (256 bits) */
	if (key_size != 256) {
		EMSG("Unsupported key size: %" PRId32 ", use 256 for P-256", key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32,
		     key_type, key_size, res);
		return res;
	}

	/* Set ECC curve attribute for P-256 */
	TEE_Attribute attr;
	TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_NIST_P256, 0);

	res = TEE_GenerateKey(key, key_size, &attr, 1);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}

	/* Free old key if exists */
	if (state->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(state->key);

	state->key = key;
	state->key_size = key_size;

	IMSG("ECDSA P-256 key generated successfully");
	return TEE_SUCCESS;
}

static TEE_Result cmd_sign(struct ecdsa_state *state, uint32_t pt,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *digest;
	uint32_t digest_len;
	void *sig;
	uint32_t sig_len;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	const uint32_t alg = TEE_ALG_ECDSA_SHA256;
	TEE_Time start_time, end_time;
	uint64_t elapsed_ns;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (state->key == TEE_HANDLE_NULL) {
		EMSG("No key generated yet");
		return TEE_ERROR_BAD_STATE;
	}

	digest = params[0].memref.buffer;
	digest_len = params[0].memref.size;
	sig = params[1].memref.buffer;
	sig_len = params[1].memref.size;

	/* Allocate operation */
	res = TEE_AllocateOperation(&op, alg, TEE_MODE_SIGN, state->key_size);
	if (res) {
		EMSG("TEE_AllocateOperation: %#" PRIx32, res);
		return res;
	}

	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	/* Measure signing time */
	get_time(&start_time);

	res = TEE_AsymmetricSignDigest(op, NULL, 0, digest, digest_len, sig, &sig_len);

	get_time(&end_time);

	if (res) {
		EMSG("TEE_AsymmetricSignDigest: %#" PRIx32, res);
		goto out;
	}

	params[1].memref.size = sig_len;

	/* Calculate elapsed time */
	elapsed_ns = time_diff_ns(&start_time, &end_time);
	params[2].value.a = (uint32_t)(elapsed_ns / 1000);  /* microseconds */
	params[2].value.b = (uint32_t)(elapsed_ns % 1000);  /* nanoseconds remainder */

	IMSG("ECDSA sign completed in %" PRIu64 " ns (%" PRIu32 " us)",
	     elapsed_ns, params[2].value.a);

out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_sign_benchmark(struct ecdsa_state *state, uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *digest;
	uint32_t digest_len;
	uint32_t iterations;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	const uint32_t alg = TEE_ALG_ECDSA_SHA256;
	TEE_Time start_time, end_time;
	uint64_t total_ns;
	uint32_t i;
	uint8_t sig[72];  /* Max ECDSA P-256 signature size */
	uint32_t sig_len;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (state->key == TEE_HANDLE_NULL) {
		EMSG("No key generated yet");
		return TEE_ERROR_BAD_STATE;
	}

	digest = params[0].memref.buffer;
	digest_len = params[0].memref.size;
	iterations = params[1].value.a;

	if (iterations == 0 || iterations > 10000) {
		EMSG("Invalid iteration count: %" PRIu32, iterations);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Allocate operation */
	res = TEE_AllocateOperation(&op, alg, TEE_MODE_SIGN, state->key_size);
	if (res) {
		EMSG("TEE_AllocateOperation: %#" PRIx32, res);
		return res;
	}

	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	/* Benchmark loop */
	get_time(&start_time);

	for (i = 0; i < iterations; i++) {
		sig_len = sizeof(sig);
		res = TEE_AsymmetricSignDigest(op, NULL, 0, digest, digest_len,
					       sig, &sig_len);
		if (res) {
			EMSG("TEE_AsymmetricSignDigest failed at iteration %" PRIu32 ": %#" PRIx32,
			     i, res);
			goto out;
		}
	}

	get_time(&end_time);

	/* Calculate total and average time */
	total_ns = time_diff_ns(&start_time, &end_time);
	params[2].value.a = (uint32_t)(total_ns / 1000);  /* total microseconds */
	params[2].value.b = (uint32_t)(total_ns / iterations);  /* avg nanoseconds per sign */

	IMSG("ECDSA benchmark: %" PRIu32 " iterations in %" PRIu64 " ns (avg %" PRIu32 " ns/sign)",
	     iterations, total_ns, params[2].value.b);

out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	IMSG("ECDSA Sign TA created");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	IMSG("ECDSA Sign TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **session)
{
	struct ecdsa_state *state;

	state = TEE_Malloc(sizeof(*state), TEE_MALLOC_FILL_ZERO);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->key = TEE_HANDLE_NULL;
	state->key_size = 0;

	*session = state;

	IMSG("ECDSA Sign session opened");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct ecdsa_state *state = session;

	if (state->key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(state->key);

	TEE_Free(state);
	IMSG("ECDSA Sign session closed");
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_ECDSA_CMD_GEN_KEY:
		return cmd_gen_key(session, param_types, params);
	case TA_ECDSA_CMD_SIGN:
		return cmd_sign(session, param_types, params);
	case TA_ECDSA_CMD_SIGN_BENCHMARK:
		return cmd_sign_benchmark(session, param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
