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

#pragma once

#include <glib.h>
#include <gnutls/gnutls.h>

struct _GoodixTlsServer;

/**
 * GoodixTlsServer:
 *
 * TLS server context for Goodix devices (GnuTLS in-memory transport).
 *
 * Data flow:
 *   sensor  →  goodix_tls_client_write()  →  in_buf  →  GnuTLS pull cb
 *   GnuTLS push cb  →  out_buf  →  goodix_tls_client_read()  →  sensor
 *   goodix_tls_server_read()  →  gnutls_record_recv()  (plaintext from sensor)
 *
 * The handshake is driven non-blocking: each call to goodix_tls_client_write()
 * advances gnutls_handshake() as far as the available input allows.  No
 * background thread is required.
 */
typedef struct _GoodixTlsServer
{
  gpointer user_data; /* passed to all callbacks */

  gnutls_session_t session;
  gnutls_psk_server_credentials_t creds;

  GByteArray *in_buf;  /* encrypted bytes sensor → TLS engine  */
  GByteArray *out_buf; /* encrypted bytes TLS engine → sensor  */

  gboolean handshake_done;
} GoodixTlsServer;

/**
 * goodix_tls_server_init:
 * @self:  context to initialise (already allocated by caller)
 * @error: output error
 *
 * Initialises the GnuTLS session with TLS 1.2 DHE-PSK (32 zero-byte key).
 * Returns: %TRUE on success.
 */
gboolean
goodix_tls_server_init(GoodixTlsServer *self, GError **error);

/**
 * goodix_tls_server_read:
 * @self:   server context
 * @data:   buffer to receive plaintext
 * @length: maximum bytes to read
 * @error:  output error
 *
 * Decrypts one application-data record received from the sensor.
 * Returns: bytes read, or ≤ 0 on error.
 */
int
goodix_tls_server_read(GoodixTlsServer *self, guint8 *data, guint32 length,
                       GError **error);

/**
 * goodix_tls_client_write:
 * @self:   server context
 * @data:   encrypted bytes received from the sensor
 * @length: number of bytes
 *
 * Feeds encrypted data from the sensor into the TLS engine and advances
 * the handshake if it is not yet complete.
 * Returns: @length on success, -1 on handshake error.
 */
int
goodix_tls_client_write(GoodixTlsServer *self, guint8 *data, guint16 length);

/**
 * goodix_tls_client_read:
 * @self:   server context
 * @data:   buffer to receive encrypted bytes for the sensor
 * @length: buffer capacity
 *
 * Reads TLS-engine output that should be forwarded to the sensor.
 * Returns: bytes copied (0 if the output buffer is empty).
 */
int
goodix_tls_client_read(GoodixTlsServer *self, guint8 *data, guint16 length);

/**
 * goodix_tls_server_deinit:
 * @self:  context to tear down
 * @error: output error
 *
 * Shuts down the TLS session and frees all associated resources.
 * Returns: %TRUE on success.
 */
gboolean
goodix_tls_server_deinit(GoodixTlsServer *self, GError **error);
