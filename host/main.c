// SPDX-License-Identifier: BSD-2-Clause
/*
 * ECDSA Sign Host Application
 * Measures ECDSA signing time on Cortex-A72 (QEMU)
 * For TEE attestation benchmarking
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OP-TEE TEE client API */
#include <tee_client_api.h>

/* TA header */
#include <ecdsa_sign_ta.h>

/* ECDSA P-256 signature max size (DER encoded) */
#define ECDSA_SIG_MAX_SIZE	72

static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
{
	errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
	size_t i;
	printf("%s (%zu bytes): ", label, len);
	for (i = 0; i < len && i < 32; i++)
		printf("%02x", data[i]);
	if (len > 32)
		printf("...");
	printf("\n");
}

static uint64_t get_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t eo;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	const TEEC_UUID uuid = TA_ECDSA_SIGN_UUID;
	uint32_t iterations = 100;

	/* Test data matching attestation protocol */
	/* attestdiv = SignTEE(Hash(W) || metrics) - 48 bytes */
	uint8_t attestdiv_data[ATTESTDIV_DATA_SIZE];
	/* attestquorum = SignTEE(Hash(Header) || bitmap) - 40 bytes */
	uint8_t attestquorum_data[ATTESTQUORUM_DATA_SIZE];

	uint8_t signature[ECDSA_SIG_MAX_SIZE];
	uint64_t host_start, host_end;
	uint32_t tee_time_us, tee_time_ns_rem;

	if (argc > 1)
		iterations = atoi(argv[1]);

	printf("=================================================\n");
	printf("ECDSA P-256 Signing Benchmark on Cortex-A72 (QEMU)\n");
	printf("=================================================\n\n");

	/* Initialize test data with pseudo-random values */
	printf("Preparing test data...\n");
	for (size_t i = 0; i < sizeof(attestdiv_data); i++)
		attestdiv_data[i] = (uint8_t)(i * 17 + 0x5A);
	for (size_t i = 0; i < sizeof(attestquorum_data); i++)
		attestquorum_data[i] = (uint8_t)(i * 23 + 0xA5);

	print_hex("attestdiv_data (Hash(W)||metrics)", attestdiv_data, sizeof(attestdiv_data));
	print_hex("attestquorum_data (Hash(Header)||bitmap)", attestquorum_data, sizeof(attestquorum_data));
	printf("\n");

	/* Initialize TEE context */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext: %#" PRIx32, res);

	/* Open session with ECDSA Sign TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
	if (res)
		teec_err(res, eo, "TEEC_OpenSession");

	printf("Session opened with ECDSA Sign TA\n\n");

	/* Generate ECDSA P-256 key */
	printf("--- Key Generation ---\n");
	host_start = get_time_ns();

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 256;  /* P-256 */

	res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_GEN_KEY, &op, &eo);
	if (res)
		teec_err(res, eo, "TA_ECDSA_CMD_GEN_KEY");

	host_end = get_time_ns();
	printf("Key generation time (host measured): %" PRIu64 " us\n\n",
	       (host_end - host_start) / 1000);

	/* Test 1: Sign attestdiv data (48 bytes) */
	printf("--- Test 1: attestdiv Signature (Hash(W)||metrics, %d bytes) ---\n",
	       ATTESTDIV_DATA_SIZE);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = attestdiv_data;
	op.params[0].tmpref.size = sizeof(attestdiv_data);
	op.params[1].tmpref.buffer = signature;
	op.params[1].tmpref.size = sizeof(signature);

	host_start = get_time_ns();
	res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_SIGN, &op, &eo);
	host_end = get_time_ns();

	if (res)
		teec_err(res, eo, "TA_ECDSA_CMD_SIGN (attestdiv)");

	tee_time_us = op.params[2].value.a;
	tee_time_ns_rem = op.params[2].value.b;

	printf("Signature size: %zu bytes\n", op.params[1].tmpref.size);
	print_hex("Signature", signature, op.params[1].tmpref.size);
	printf("TEE signing time: %" PRIu32 " us + %" PRIu32 " ns\n", tee_time_us, tee_time_ns_rem);
	printf("Host total time: %" PRIu64 " us\n\n", (host_end - host_start) / 1000);

	/* Test 2: Sign attestquorum data (40 bytes) */
	printf("--- Test 2: attestquorum Signature (Hash(Header)||bitmap, %d bytes) ---\n",
	       ATTESTQUORUM_DATA_SIZE);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = attestquorum_data;
	op.params[0].tmpref.size = sizeof(attestquorum_data);
	op.params[1].tmpref.buffer = signature;
	op.params[1].tmpref.size = sizeof(signature);

	host_start = get_time_ns();
	res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_SIGN, &op, &eo);
	host_end = get_time_ns();

	if (res)
		teec_err(res, eo, "TA_ECDSA_CMD_SIGN (attestquorum)");

	tee_time_us = op.params[2].value.a;
	tee_time_ns_rem = op.params[2].value.b;

	printf("Signature size: %zu bytes\n", op.params[1].tmpref.size);
	print_hex("Signature", signature, op.params[1].tmpref.size);
	printf("TEE signing time: %" PRIu32 " us + %" PRIu32 " ns\n", tee_time_us, tee_time_ns_rem);
	printf("Host total time: %" PRIu64 " us\n\n", (host_end - host_start) / 1000);

	/* Test 3: Benchmark - multiple iterations */
	printf("--- Test 3: Benchmark (%u iterations, attestdiv data) ---\n", iterations);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = attestdiv_data;
	op.params[0].tmpref.size = sizeof(attestdiv_data);
	op.params[1].value.a = iterations;

	host_start = get_time_ns();
	res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_SIGN_BENCHMARK, &op, &eo);
	host_end = get_time_ns();

	if (res)
		teec_err(res, eo, "TA_ECDSA_CMD_SIGN_BENCHMARK");

	printf("TEE total time: %" PRIu32 " us\n", op.params[2].value.a);
	printf("TEE avg time per sign: %" PRIu32 " ns = %.3f us\n",
	       op.params[2].value.b, op.params[2].value.b / 1000.0);
	printf("Host total time: %" PRIu64 " us\n", (host_end - host_start) / 1000);
	printf("Host avg time per sign: %.3f us\n\n",
	       (host_end - host_start) / 1000.0 / iterations);

	/* Test 4: Benchmark with attestquorum data */
	printf("--- Test 4: Benchmark (%u iterations, attestquorum data) ---\n", iterations);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = attestquorum_data;
	op.params[0].tmpref.size = sizeof(attestquorum_data);
	op.params[1].value.a = iterations;

	host_start = get_time_ns();
	res = TEEC_InvokeCommand(&sess, TA_ECDSA_CMD_SIGN_BENCHMARK, &op, &eo);
	host_end = get_time_ns();

	if (res)
		teec_err(res, eo, "TA_ECDSA_CMD_SIGN_BENCHMARK");

	printf("TEE total time: %" PRIu32 " us\n", op.params[2].value.a);
	printf("TEE avg time per sign: %" PRIu32 " ns = %.3f us\n",
	       op.params[2].value.b, op.params[2].value.b / 1000.0);
	printf("Host total time: %" PRIu64 " us\n", (host_end - host_start) / 1000);
	printf("Host avg time per sign: %.3f us\n\n",
	       (host_end - host_start) / 1000.0 / iterations);

	/* Summary */
	printf("=================================================\n");
	printf("SUMMARY\n");
	printf("=================================================\n");
	printf("Platform: Cortex-A72 (QEMU emulated)\n");
	printf("Algorithm: ECDSA P-256 (secp256r1)\n");
	printf("attestdiv data size: %d bytes (Hash(W) || metrics)\n", ATTESTDIV_DATA_SIZE);
	printf("attestquorum data size: %d bytes (Hash(Header) || bitmap)\n", ATTESTQUORUM_DATA_SIZE);
	printf("Benchmark iterations: %u\n", iterations);
	printf("=================================================\n");

	/* Cleanup */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
