/*
 * Goodix Tls driver for libfprint
 *
 * Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
 * Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
 * Copyright (C) 2021 Natasha England-Elbro <ashenglandelbro@protonmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Community credits — Goodix TLS (51xx MOH) driver
 *
 * This driver builds on years of reverse-engineering by the
 * goodix-fp-linux-dev community (https://github.com/goodix-fp-linux-dev):
 *
 *   Matthieu Charette (@mpi3d)       — protocol RE lead, goodix-fp-dump
 *   Thomas Lambertz (@tlambertz)      — TLS-over-USB discovery, PSK auth
 *   Alexander Meiler (@delanodev)     — early protocol RE, first images
 *   Natasha England-Elbro (@0x00002a) — first libfprint driver, SIGFM, AUR
 *   @gulp                             — 5117 support, PR #32
 *   @egormanga                        — project maintenance, code review
 *   @rootd, @EliaGeretto, @mincrmatt12 — additional contributions
 *
 * Upstream guidance: Benjamin Berg (@benzea), Bastien Nocera (@hadess).
 */

#include <gio/gio.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <string.h>

#include "fpi-log.h"
#include "goodixtls.h"

/* TLS 1.2, DHE-PSK only — matches GF511 firmware expectations */
#define GOODIX_TLS_PRIORITY "NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+DHE-PSK:+PSK"
#define GOODIX_TLS_PRIORITY_5120 \
  "NORMAL:+VERS-ALL:+PSK:+DHE-PSK:+ECDHE-PSK:+RSA-PSK:+AES-128-CBC:+SHA256:+CIPHER-ALL:+MAC-ALL:%PROFILE_LOW:%COMPAT"

/* Under FP_DEVICE_EMULATION: use PSK-only (no DHE) so that no ephemeral
 * DH private key is generated.  Combined with a fixed server random this
 * makes the TLS handshake fully deterministic for umockdev pcap replay. */
#define GOODIX_TLS_PRIORITY_EMULATED \
  "NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+PSK"

/* TLS session PSK: the symmetric key for the GnuTLS PSK-DHE TLS 1.2
 * handshake between the host (server) and sensor firmware (client).
 *
 * This is the all-zeros "factory default" PSK.  The sensor must have
 * been provisioned with this key (via goodix-fp-dump or equivalent)
 * for TLS to succeed. */
static const guint8 goodix_tls_psk[32] = { 0 };

/* Fixed server random used under FP_DEVICE_EMULATION to make the
 * ServerHello deterministic for pcap record/replay. */
static const guint8 emulated_server_random[32] = {
  0x54, 0x45, 0x53, 0x54, 0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
  0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
};


/* -------------------------------------------------------------------------- */
/* GnuTLS transport callbacks (in-memory buffers, no sockets/threads)         */
/* -------------------------------------------------------------------------- */

static ssize_t
tls_pull_func(gnutls_transport_ptr_t ptr, void *buf, size_t len)
{
  GoodixTlsServer *self = ptr;

  if (self->in_buf->len == 0)
    {
      gnutls_transport_set_errno(self->session, EAGAIN);
      return -1;
    }

  gsize to_copy = MIN(len, (gsize)self->in_buf->len);

  memcpy(buf, self->in_buf->data, to_copy);
  g_byte_array_remove_range(self->in_buf, 0, to_copy);
  return (ssize_t)to_copy;
}

static ssize_t
tls_push_func(gnutls_transport_ptr_t ptr, const void *buf, size_t len)
{
  GoodixTlsServer *self = ptr;

  g_byte_array_append(self->out_buf, buf, len);
  return (ssize_t)len;
}

/* -------------------------------------------------------------------------- */
/* PSK callback                                                                */
/* -------------------------------------------------------------------------- */

static int
tls_psk_server_cb(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
  GoodixTlsServer *self = gnutls_session_get_ptr(session);
  const guint8 *psk = self->psk_len ? self->psk : goodix_tls_psk;
  gsize len = self->psk_len ? self->psk_len : sizeof(goodix_tls_psk);

  key->data = gnutls_malloc(len);
  if (!key->data)
    return GNUTLS_E_MEMORY_ERROR;
  memcpy(key->data, psk, len);
  key->size = len;
  return 0;
}

void
goodix_tls_server_set_compat_profile (GoodixTlsServer *self, gboolean compat)
{
  g_return_if_fail (self != NULL && self->session == NULL);
  self->compat_profile = compat;
}

void
goodix_tls_server_set_psk (GoodixTlsServer *self, const guint8 *psk, gsize len)
{
  g_return_if_fail (self != NULL && !self->handshake_started);
  g_return_if_fail ((psk == NULL && len == 0) || (psk != NULL && len >= 1 && len <= 64));
  gnutls_memset (self->psk, 0, sizeof (self->psk));
  self->psk_len = 0;
  if (psk)
    {
      memcpy (self->psk, psk, len);
      self->psk_len = len;
    }
}

gboolean
goodix_tls_psk_hash_matches_fallback (const guint8 *hash, gsize len)
{
  static const guint8 goodix_5120_wb_zero_psk_hash[32] = {
    0xb5, 0xe0, 0xbe, 0xeb, 0x94, 0xc8, 0x4e, 0xb9,
    0x9b, 0x88, 0x3a, 0xbd, 0x5c, 0x25, 0x10, 0x73,
    0xc5, 0x6b, 0x91, 0x03, 0x5c, 0x56, 0x2a, 0x91,
    0xa4, 0x6c, 0x7f, 0x33, 0x49, 0xc3, 0x6c, 0x89,
  };
  g_autoptr(GChecksum) sum = NULL;
  guint8 digest[32];
  gsize digest_len = sizeof (digest);

  if (!hash || len != sizeof (digest))
    return FALSE;
  sum = g_checksum_new (G_CHECKSUM_SHA256);
  g_checksum_update (sum, goodix_tls_psk, sizeof (goodix_tls_psk));
  g_checksum_get_digest (sum, digest, &digest_len);
  return memcmp (digest, hash, sizeof (digest)) == 0 ||
         memcmp (goodix_5120_wb_zero_psk_hash, hash, len) == 0;
}

static const char *
tls_suite_name (guint8 hi, guint8 lo)
{
  unsigned char id[2];
  const char *name;

  for (size_t i = 0; (name = gnutls_cipher_suite_info (i, id, NULL, NULL, NULL, NULL)); i++)
    if (id[0] == hi && id[1] == lo)
      return name;
  return "unsupported";
}

/* Only public, cleartext fields are reported: versions and offered suites.
 * Random, session ID and extensions (which may carry PSK identities) are not. */
gchar *
goodix_tls_describe_client_hello (const guint8 *record, gsize len)
{
  GString *out;
  gsize end, pos, suites_len;

  /* record header (5) + handshake header (4) + client_version (2) + random (32) */
  if (!record || len < 44 || record[0] != 0x16 || record[5] != 0x01)
    return NULL;
  end = MIN (len, 5 + (((gsize) record[3] << 8) | record[4]));
  pos = 43;                                   /* len >= 44: in bounds */
  pos += 1 + record[pos];                     /* session ID */
  if (pos + 2 > end)
    return NULL;
  suites_len = ((gsize) record[pos] << 8) | record[pos + 1];
  pos += 2;
  if (suites_len == 0 || suites_len % 2 || pos + suites_len > end)
    return NULL;

  out = g_string_new (NULL);
  g_string_append_printf (out, "record=0x%02x%02x client_version=0x%02x%02x suites=%"
                          G_GSIZE_FORMAT ":", record[1], record[2], record[9],
                          record[10], suites_len / 2);
  for (gsize i = pos; i < pos + suites_len; i += 2)
    g_string_append_printf (out, " 0x%02x%02x(%s)", record[i], record[i + 1],
                            tls_suite_name (record[i], record[i + 1]));
  return g_string_free (out, FALSE);
}

/* Logged once per session so that "no supported cipher suites" can be
 * diagnosed against what the sensor actually offered. */
static void
tls_log_client_hello (GoodixTlsServer *self, const guint8 *data, guint16 length)
{
  g_autofree gchar *summary = NULL;
  gsize take = MIN ((gsize) length, sizeof (self->hello) - self->hello_len);
  gsize want;

  if (take)
    memcpy (self->hello + self->hello_len, data, take);
  self->hello_len += take;
  if (self->hello_len < 5)
    return;
  want = MIN (sizeof (self->hello),
              5 + (((gsize) self->hello[3] << 8) | self->hello[4]));
  if (self->hello_len < want)
    return;

  self->hello_logged = TRUE;
  summary = goodix_tls_describe_client_hello (self->hello, self->hello_len);
  fp_dbg ("TLS ClientHello: %s", summary ? summary : "not a parseable ClientHello");
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                  */
/* -------------------------------------------------------------------------- */

gboolean
goodix_tls_server_init(GoodixTlsServer *self, GError **error)
{
  int r;
  gboolean emulation = g_strcmp0 (g_getenv ("FP_DEVICE_EMULATION"), "1") == 0;
  const char *priority = emulation ? GOODIX_TLS_PRIORITY_EMULATED
                         : self->compat_profile ? GOODIX_TLS_PRIORITY_5120
                                                : GOODIX_TLS_PRIORITY;

  self->in_buf = g_byte_array_new();
  self->out_buf = g_byte_array_new();
  self->handshake_done = FALSE;
  self->handshake_started = FALSE;

  r = gnutls_psk_allocate_server_credentials(&self->creds);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                  "gnutls_psk_allocate_server_credentials: %s", gnutls_strerror(r));
      goto fail;
    }

  gnutls_psk_set_server_credentials_function(self->creds, tls_psk_server_cb);

  r = gnutls_init(&self->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "gnutls_init: %s",
                  gnutls_strerror(r));
      goto fail;
    }

  r = gnutls_priority_set_direct(self->session, priority, NULL);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "gnutls_priority_set_direct: %s",
                  gnutls_strerror(r));
      goto fail;
    }

  r = gnutls_credentials_set(self->session, GNUTLS_CRD_PSK, self->creds);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                  "gnutls_credentials_set: %s", gnutls_strerror(r));
      goto fail;
    }
  gnutls_session_set_ptr(self->session, self);

  /* Under emulation, fix the server random so the ServerHello is
   * byte-identical across record and replay runs.  The remaining
   * random bytes (session_id, etc.) are made deterministic by the
   * getrandom-seed LD_PRELOAD shim loaded by tests/meson.build. */
  if (emulation)
    {
      gnutls_datum_t rand_datum = {
        .data = (unsigned char *) emulated_server_random,
        .size = sizeof (emulated_server_random),
      };
      gnutls_handshake_set_random (self->session, &rand_datum);
      fp_dbg ("FP_DEVICE_EMULATION: using deterministic TLS (PSK-only, "
              "fixed server random)");
    }

  gnutls_transport_set_ptr(self->session, self);
  gnutls_transport_set_push_function(self->session, tls_push_func);
  gnutls_transport_set_pull_function(self->session, tls_pull_func);

  fp_dbg("GnuTLS TLS server initialised (profile=%s)",
         emulation ? "emulated" : self->compat_profile ? "5120" : "legacy");
  return TRUE;

fail:
  if (self->session) gnutls_deinit(self->session);
  if (self->creds) gnutls_psk_free_server_credentials(self->creds);
  if (self->in_buf) g_byte_array_unref(self->in_buf);
  if (self->out_buf) g_byte_array_unref(self->out_buf);
  self->session = NULL; self->creds = NULL;
  self->in_buf = self->out_buf = NULL;
  gnutls_memset(self->psk, 0, sizeof(self->psk));
  self->psk_len = 0;
  return FALSE;
}

/*
 * goodix_tls_client_write: feed encrypted bytes from the sensor into the
 * TLS engine.  If the handshake is not yet complete, advance it.
 */
int
goodix_tls_client_write(GoodixTlsServer *self, guint8 *data, guint16 length)
{
  if (!self->hello_logged)
    tls_log_client_hello(self, data, length);
  if (!self->handshake_done)
    fp_dbg("TLS client input: %u bytes", length);
  self->handshake_started = TRUE;
  g_byte_array_append(self->in_buf, data, length);

  if (!self->handshake_done)
    {
      int r;

      do
        r = gnutls_handshake(self->session);
      while (r == GNUTLS_E_INTERRUPTED);

      if (r == 0)
        {
          self->handshake_done = TRUE;
          fp_dbg("GnuTLS handshake complete: %s / %s",
                 gnutls_protocol_get_name(gnutls_protocol_get_version(self->session)),
                 gnutls_cipher_suite_get_name(gnutls_kx_get(self->session),
                                              gnutls_cipher_get(self->session),
                                              gnutls_mac_get(self->session)));
        }
      else if (r != GNUTLS_E_AGAIN)
        {
          fp_err("gnutls_handshake error %d: %s", r, gnutls_strerror(r));
          return r;
        }
    }

  return length;
}

/*
 * goodix_tls_client_read: drain TLS-engine output that should be sent to the
 * sensor (handshake messages or encrypted application data).
 */
int
goodix_tls_client_read(GoodixTlsServer *self, guint8 *data, guint16 length)
{
  guint16 to_copy = (guint16)MIN((guint)length, self->out_buf->len);

  if (to_copy == 0)
    return 0;

  memcpy(data, self->out_buf->data, to_copy);
  g_byte_array_remove_range(self->out_buf, 0, to_copy);
  return to_copy;
}

/*
 * goodix_tls_server_read: decrypt one application-data record from the sensor.
 * The caller must have already fed the encrypted bytes via goodix_tls_client_write().
 */
int
goodix_tls_server_read(GoodixTlsServer *self, guint8 *data, guint32 length,
                       GError **error)
{
  int r = gnutls_record_recv(self->session, data, length);

  if (r < 0)
    g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "gnutls_record_recv: %s",
                gnutls_strerror(r));
  return r;
}

gboolean
goodix_tls_server_deinit(GoodixTlsServer *self, GError **error)
{
  if (self->handshake_done)
    gnutls_bye(self->session, GNUTLS_SHUT_WR);

  gnutls_deinit(self->session);
  gnutls_psk_free_server_credentials(self->creds);

  g_byte_array_unref(self->in_buf);
  g_byte_array_unref(self->out_buf);
  gnutls_memset(self->psk, 0, sizeof(self->psk));
  self->hello_len = 0;
  self->psk_len = 0;
  self->session = NULL; self->creds = NULL;
  self->in_buf = self->out_buf = NULL;

  return TRUE;
}
