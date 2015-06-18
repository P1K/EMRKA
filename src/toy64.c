/* PoC implementation of a related-key key-recovery attack on Proest-OTR
 * (with a custom 64-bit permutation instead of Proest)
 * The nonces are drawn at random for convenience
 * See https://eprint.iacr.org/2015/134 for details
 * PK 2015
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define ROL32(x,r) (((x) << (r)) ^ ((x) >> (32 - (r))))
#define MIX(hi,lo,r) { (hi) += (lo); (lo) = ROL32((lo),(r)) ; (lo) ^= (hi); }

#define TIMES2(x) ((x & 0x8000000000000000ULL) ? ((x) << 1ULL) ^ 0x000000000000001BULL : (x << 1ULL))
#define TIMES4(x) TIMES2(TIMES2((x)))

#define DELTA(x) (1ULL << (x))
#define MSB(x) ((x) & 0xFFFFFFFF00000000ULL)
#define LSB(x) ((x) & 0x00000000FFFFFFFFULL)

/* Replace arc4random() by your favourite PRNG */

/* 64-bit permutation using Skein's MIX */
uint64_t p64(uint64_t x)
{
	uint32_t hi = x >> 32;
	uint32_t lo = LSB(x);
	unsigned rcon[8] = {1, 29, 4, 8, 17, 12, 3, 14};

	for (int i = 0; i < 32; i++)
	{
	   MIX(hi, lo, rcon[i % 8]);
	   lo += i;
	}

	return ((((uint64_t)hi) << 32) ^ lo);
}

uint64_t em64(uint64_t k, uint64_t p)
{
	return p64(k ^ p) ^ k;
}

uint64_t potr_1(uint64_t k, uint64_t n, uint64_t m1, uint64_t m2)
{
	uint64_t l, c;

	l = TIMES4(em64(k, n));
	c = em64(k, l ^ m1) ^ m2;

	return c;
}

uint64_t recover_hi(uint64_t secret_key)
{
	uint64_t kk = 0;

	for (int i = 62; i >= 32; i--)
	{
		uint64_t m1, m2, c11, c12, n;

		m1 = (((uint64_t)arc4random()) << 32) ^ arc4random();
		m2 = (((uint64_t)arc4random()) << 32) ^ arc4random();
		n  = (((uint64_t)arc4random()) << 32) ^ 0x80000000ULL;
		c11 = potr_1(secret_key, n, m1, m2);
		c12 = potr_1(secret_key + DELTA(i), n ^ DELTA(i), m1 ^ DELTA(i) ^ TIMES4(DELTA(i)), m2);

		if (c11 != (c12 ^ DELTA(i)))
			kk |= DELTA(i);
	}

	return kk;
}

uint64_t recover_lo(uint64_t secret_key, uint64_t hi_key)
{
	uint64_t kk = hi_key;

	for (int i = 31; i >= 0; i--)
	{
		uint64_t m1, m2, c11, c12, n;
		uint64_t delta_p, delta_m;

		m1 = (((uint64_t)arc4random()) << 32) ^ arc4random();
		m2 = (((uint64_t)arc4random()) << 32) ^ arc4random();
		n  = (((uint64_t)arc4random()) << 32) ^ 0x80000000ULL;

		delta_p = DELTA(i) - MSB(kk) + (((LSB(~kk)) >> (i + 1)) << (i + 1));
		delta_m = DELTA(i) + MSB(kk) + LSB(kk);
		c11 = potr_1(secret_key + delta_p, n ^ DELTA(32), m1 ^ DELTA(32), m2);
		c12 = potr_1(secret_key - delta_m, n, m1 ^ TIMES4(DELTA(32)), m2);

		if (c11 == (c12 ^ DELTA(32)))
			kk |= DELTA(i);
	}

	return kk;
}

int main()
{
	uint64_t secret_key = (((uint64_t)arc4random()) << 32) ^ arc4random();
	uint64_t kk1 = recover_lo(secret_key, recover_hi(secret_key));
	uint64_t kk2 = kk1 ^ 0x8000000000000000ULL;

	printf("The real key is %016llx, the key candidates are %016llx, %016llx     ", secret_key, kk1, kk2);
	if ((kk1 == secret_key) || (kk2 == secret_key))
		printf("SUCCESS!\n");
	else
		printf("FAILURE!\n");

	return 0;
}
