/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * getrandom-seed.c — LD_PRELOAD shim for deterministic GnuTLS randomness
 *
 * When LD_PRELOADed into a process that sets FP_DEVICE_EMULATION=1, this
 * replaces gnutls_rnd() with a deterministic counter so that TLS
 * handshakes are reproducible across record / replay runs.
 *
 * This is needed for pcap-based umockdev tests on drivers that use
 * TLS/crypto (e.g. goodixtls), because umockdev compares BULK-OUT URB
 * payloads byte-for-byte.
 *
 * The counter is reset to zero whenever gnutls_init() is called, ensuring
 * the byte sequence seen by GnuTLS is identical regardless of library
 * initialisation order.
 *
 * When FP_DEVICE_EMULATION is unset or != "1", all calls pass through to
 * the real implementations.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Real library functions, resolved lazily. */
static int (*real_gnutls_rnd) (int, void *, size_t);
static int (*real_gnutls_init) (void *, unsigned int);

/* 0 = pass-through, 1 = deterministic */
static int emulation;

/* Simple counter-based DRBG. */
static uint32_t counter;

static void __attribute__ ((constructor))
init (void)
{
  const char *env = getenv ("FP_DEVICE_EMULATION");
  emulation = (env && strcmp (env, "1") == 0) ? 1 : 0;
}

/* Override gnutls_rnd() — the single entry point GnuTLS uses for all
 * random byte generation.  This intercepts regardless of the underlying
 * entropy source (getrandom, leancrypto jitter, etc.). */
int
gnutls_rnd (int level, void *data, size_t len)
{
  (void) level;

  if (emulation)
    {
      uint8_t *p = data;
      for (size_t i = 0; i < len; i++)
        p[i] = (uint8_t) (counter++ & 0xff);
      return 0;
    }

  if (!real_gnutls_rnd)
    real_gnutls_rnd = dlsym (RTLD_NEXT, "gnutls_rnd");

  return real_gnutls_rnd (level, data, len);
}

/* Hook gnutls_init() to reset the counter at a well-known point.
 * Both recording and replay call gnutls_init() exactly once before
 * the handshake, so the counter position is synchronised. */
int
gnutls_init (void *session, unsigned int flags)
{
  if (!real_gnutls_init)
    real_gnutls_init = dlsym (RTLD_NEXT, "gnutls_init");

  if (emulation)
    counter = 0;

  return real_gnutls_init (session, flags);
}
