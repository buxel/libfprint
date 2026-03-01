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

#include <gio/gio.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <string.h>

#include "fpi-log.h"
#include "goodixtls.h"

/* TLS 1.2, DHE-PSK only — matches GF511 firmware expectations */
#define GOODIX_TLS_PRIORITY "NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+DHE-PSK:+PSK"

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
  key->data = gnutls_malloc(sizeof(goodix_tls_psk));
  if (!key->data)
    return GNUTLS_E_MEMORY_ERROR;

  memcpy(key->data, goodix_tls_psk, sizeof(goodix_tls_psk));
  key->size = sizeof(goodix_tls_psk);
  return 0;
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
                                   : GOODIX_TLS_PRIORITY;

  self->in_buf = g_byte_array_new();
  self->out_buf = g_byte_array_new();
  self->handshake_done = FALSE;

  r = gnutls_psk_allocate_server_credentials(&self->creds);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                  "gnutls_psk_allocate_server_credentials: %s", gnutls_strerror(r));
      return FALSE;
    }

  gnutls_psk_set_server_credentials_function(self->creds, tls_psk_server_cb);

  r = gnutls_init(&self->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "gnutls_init: %s",
                  gnutls_strerror(r));
      gnutls_psk_free_server_credentials(self->creds);
      return FALSE;
    }

  r = gnutls_priority_set_direct(self->session, priority, NULL);
  if (r < 0)
    {
      g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "gnutls_priority_set_direct: %s",
                  gnutls_strerror(r));
      gnutls_deinit(self->session);
      gnutls_psk_free_server_credentials(self->creds);
      return FALSE;
    }

  gnutls_credentials_set(self->session, GNUTLS_CRD_PSK, self->creds);

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

  fp_dbg("GnuTLS TLS server initialised");
  return TRUE;
}

/*
 * goodix_tls_client_write: feed encrypted bytes from the sensor into the
 * TLS engine.  If the handshake is not yet complete, advance it.
 */
int
goodix_tls_client_write(GoodixTlsServer *self, guint8 *data, guint16 length)
{
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
          fp_dbg("GnuTLS handshake complete");
        }
      else if (r != GNUTLS_E_AGAIN)
        {
          fp_err("gnutls_handshake error: %s", gnutls_strerror(r));
          return -1;
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

  return TRUE;
}
