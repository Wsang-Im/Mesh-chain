// SPDX-License-Identifier: BSD-2-Clause
/*
 * ECDSA Sign TA - Header
 * For measuring ECDSA signing time on Cortex-A72 (QEMU)
 */

#ifndef __ECDSA_SIGN_TA_H__
#define __ECDSA_SIGN_TA_H__

/* UUID of the ECDSA sign trusted application */
#define TA_ECDSA_SIGN_UUID \
	{ 0x12345678, 0xabcd, 0x1234, { \
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 } }

/*
 * TA_ECDSA_CMD_GEN_KEY - Generate ECDSA key pair
 * in	params[0].value.a: key size (256 for P-256)
 */
#define TA_ECDSA_CMD_GEN_KEY		0

/*
 * TA_ECDSA_CMD_SIGN - Sign data with ECDSA
 * in	params[0].memref: data to sign (hash)
 * out	params[1].memref: signature output
 * out	params[2].value.a: signing time in microseconds
 * out	params[2].value.b: signing time in nanoseconds (remainder)
 */
#define TA_ECDSA_CMD_SIGN		1

/*
 * TA_ECDSA_CMD_SIGN_BENCHMARK - Sign multiple times for benchmark
 * in	params[0].memref: data to sign (hash)
 * in	params[1].value.a: number of iterations
 * out	params[2].value.a: total time in microseconds
 * out	params[2].value.b: average time in nanoseconds per sign
 */
#define TA_ECDSA_CMD_SIGN_BENCHMARK	2

/* Data sizes matching attestation protocol */
#define WITNESS_SET_HASH_SIZE		32	/* SHA-256 hash of witness set */
#define METRICS_SIZE			16	/* Diversity metrics */
#define HEADER_HASH_SIZE		32	/* Block header hash */
#define BITMAP_SIZE			8	/* Witness bitmap */
#define ATTESTDIV_DATA_SIZE		(WITNESS_SET_HASH_SIZE + METRICS_SIZE)  /* 48 bytes */
#define ATTESTQUORUM_DATA_SIZE		(HEADER_HASH_SIZE + BITMAP_SIZE)        /* 40 bytes */

#endif /* __ECDSA_SIGN_TA_H */
