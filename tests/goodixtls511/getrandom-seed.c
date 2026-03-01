/*
 * Deterministic RNG shim for TLS test replay.
 *
 * When loaded via LD_PRELOAD, this replaces getrandom(), getentropy(),
 * and gnutls_rnd() with deterministic versions, and intercepts
 * gnutls_init() to reset PRNG state before each TLS session.
 *
 * The gnutls_rnd() override is critical: GnuTLS maintains an internal
 * DRBG that accumulates state from getrandom() calls.  Even with
 * deterministic getrandom(), the DRBG state can diverge between
 * recording and replay if different numbers of pre-TLS getrandom()
 * calls occur.  By overriding gnutls_rnd() directly, we bypass the
 * DRBG entirely and ensure identical TLS output.
 *
 * This makes GnuTLS DHE-PSK key exchange produce identical bytes across
 * recording and replay runs, which is required for umockdev pcap replay.
 *
 * Only activates when FP_DEVICE_EMULATION=1 is set.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* _GNU_SOURCE is set by the build system */
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static uint64_t s[4];
static int prng_ready;  /* set after gnutls_init resets PRNG */

static uint64_t
rotl (uint64_t x, int k)
{
  return (x << k) | (x >> (64 - k));
}

static uint64_t
xoshiro256ss (void)
{
  uint64_t result = rotl (s[1] * 5, 7) * 9;
  uint64_t t = s[1] << 17;
  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = rotl (s[3], 45);
  return result;
}

static void
prng_reset (void)
{
  s[0] = 0x4758544C53353131ULL;  /* "GXTLS511" */
  s[1] = 0x6670726E74746573ULL;  /* "fprnttes" */
  s[2] = 0xDEADBEEFCAFEBABEULL;
  s[3] = 0x0123456789ABCDEFULL;
  for (int i = 0; i < 20; i++)
    xoshiro256ss ();
  prng_ready = 1;
  fprintf (stderr, "getrandom-seed: PRNG reset\n");
}

static int
is_emulation (void)
{
  const char *env = getenv ("FP_DEVICE_EMULATION");
  return env && strcmp (env, "1") == 0;
}

static void
fill_deterministic (void *buf, size_t buflen)
{
  uint8_t *p = buf;
  for (size_t i = 0; i < buflen; i += 8)
    {
      uint64_t val = xoshiro256ss ();
      size_t   chunk = (buflen - i < 8) ? buflen - i : 8;
      memcpy (p + i, &val, chunk);
    }
}

/* --- getrandom / getentropy interposition --- */

ssize_t
getrandom (void *buf, size_t buflen, unsigned int flags)
{
  if (!is_emulation ())
    return syscall (SYS_getrandom, buf, buflen, flags);
  fill_deterministic (buf, buflen);
  return (ssize_t) buflen;
}

int
getentropy (void *buf, size_t buflen)
{
  if (buflen > 256)
    {
      errno = EIO;
      return -1;
    }
  ssize_t r = getrandom (buf, buflen, 0);
  if (r < 0)
    return -1;
  return 0;
}

/* --- gnutls_rnd interposition --- */

int
gnutls_rnd (gnutls_rnd_level_t level, void *data, size_t len)
{
  static int (*real_gnutls_rnd) (gnutls_rnd_level_t, void *, size_t) = NULL;

  if (!real_gnutls_rnd)
    {
      real_gnutls_rnd = dlsym (RTLD_NEXT, "gnutls_rnd");
      if (!real_gnutls_rnd)
        {
          fprintf (stderr, "getrandom-seed: FATAL: cannot find real gnutls_rnd\n");
          abort ();
        }
    }

  if (is_emulation () && prng_ready)
    {
      fill_deterministic (data, len);
      return 0;
    }
  return real_gnutls_rnd (level, data, len);
}

/* --- gnutls_init interposition --- */

int
gnutls_init (gnutls_session_t *session, unsigned int flags)
{
  static int (*real_gnutls_init) (gnutls_session_t *, unsigned int) = NULL;

  if (!real_gnutls_init)
    {
      real_gnutls_init = dlsym (RTLD_NEXT, "gnutls_init");
      if (!real_gnutls_init)
        {
          fprintf (stderr, "getrandom-seed: FATAL: cannot find real gnutls_init\n");
          abort ();
        }
    }

  if (is_emulation ())
    prng_reset ();

  return real_gnutls_init (session, flags);
}
