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

#define FP_COMPONENT "goodixtls"

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodixtls.h"

#include <string.h>

typedef struct
{
  GoodixTlsServer *tls_hop;

  GSource *timeout;

  guint8 cmd;

  gboolean ack;
  gboolean reply;

  GoodixCmdCallback callback;
  gpointer user_data;

  guint8 *data;
  guint32 length;
  guint8 last_pack_flags;

  GoodixCallbackInfo *tls_ready_callback;
  GSource *tls_deadline;
  gboolean tls_confirming;
  gboolean tls_exit_pending;
  guint tls_exit_tries;
  gboolean tls_closing;
  gboolean usb_claimed;
  guint tls_generation;
  guint8 device_psk[64];
  gsize device_psk_len;
  guint32 psk_response_flags;
  guint16 psk_response_len;
  gboolean psk_fallback_match;

  GCancellable *transfer_cancel_tkn;
  gboolean inited;

  guint8 ep_in;
  guint8 ep_out;
} FpiDeviceGoodixTlsPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE(FpiDeviceGoodixTls, fpi_device_goodixtls,
                                    FP_TYPE_DEVICE);

gchar *
data_to_str(guint8 *data, guint32 length)
{
  gchar *string = g_malloc((length * 2) + 1);

  for (guint32 i = 0; i < length; i++)
    g_snprintf(string + i * 2, 3, "%02x", data[i]);

  return string;
}

/* ---- GOODIX RECEIVE SECTION START ---- */

static void goodix_receive_data (FpDevice *dev);
static void goodix_tls_complete (FpDevice *dev, GError *error);
static void goodix_tls_ready_image_handler (FpDevice *dev, guint8 *data,
                                             guint16 length, gpointer user_data,
                                             GError *error);

static void
goodix_receive_done(FpDevice *dev, guint8 *data, guint16 length, GError *error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  GoodixCmdCallback callback = priv->callback;
  gpointer user_data = priv->user_data;

  if (!(priv->ack || priv->reply))
    return;

  goodix_reset_state(dev);
  if (!error)
    fp_dbg("Completed command: 0x%02x", priv->cmd);

  if (callback)
    callback(dev, data, length, user_data, error);
}

static void
goodix_receive_none(FpDevice *dev, guint8 *data, guint16 length, gpointer user_data,
                    GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixNoneCallback callback = (GoodixNoneCallback)cb_info->callback;

  callback(dev, cb_info->user_data, error);
}

static void
goodix_receive_default(FpDevice *dev, guint8 *data, guint16 length, gpointer user_data,
                       GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixDefaultCallback callback = (GoodixDefaultCallback)cb_info->callback;

  callback(dev, data, length, cb_info->user_data, error);
}

static void
goodix_receive_success(FpDevice *dev, guint8 *data, guint16 length, gpointer user_data,
                       GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixSuccessCallback callback = (GoodixSuccessCallback)cb_info->callback;

  if (error)
    {
      callback(dev, FALSE, cb_info->user_data, error);
      return;
    }

  if (length != sizeof(guint8) * 2)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid success reply length: %d", length);
      callback(dev, FALSE, cb_info->user_data, error);
      return;
    }

  callback(dev, data[0] == 0x00 ? FALSE : TRUE, cb_info->user_data, NULL);
}

static void
goodix_receive_reset(FpDevice *dev, guint8 *data, guint16 length, gpointer user_data,
                     GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixResetCallback callback = (GoodixResetCallback)cb_info->callback;

  if (error)
    {
      callback(dev, FALSE, 0, cb_info->user_data, error);
      return;
    }

  if (length != sizeof(guint8) + sizeof(guint16))
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid reset reply length: %d", length);
      callback(dev, FALSE, 0, cb_info->user_data, error);
      return;
    }

  guint16 reset_number;
  memcpy (&reset_number, data + sizeof (guint8), sizeof (guint16));
  reset_number = GUINT16_FROM_LE (reset_number);

  callback (dev, data[0] == 0x00 ? FALSE : TRUE,
            reset_number, cb_info->user_data, NULL);
}

static void
goodix_receive_preset_psk_read(FpDevice *dev, guint8 *data, guint16 length,
                               gpointer user_data, GError *error)
{
  guint32 psk_len;
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixPresetPskReadCallback callback = (GoodixPresetPskReadCallback)cb_info->callback;

  if (error)
    {
      callback(dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  if (length < sizeof(guint8))
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid preset PSK read reply length: %d", length);
      callback(dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  if (data[0] != 0x00)
    {
      callback(dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, NULL);
      return;
    }

  if (length < sizeof(guint8) + sizeof(GoodixPresetPsk))
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid preset PSK read reply length: %d", length);
      callback(dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  psk_len = GUINT32_FROM_LE(((GoodixPresetPsk *)(data + sizeof(guint8)))->length);

  if (psk_len > (guint32)length - sizeof(guint8) - sizeof(GoodixPresetPsk) ||
      psk_len > G_MAXUINT16)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid preset PSK read reply length: %d", length);
      callback(dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  callback(
      dev, TRUE, GUINT32_FROM_LE(((GoodixPresetPsk *)(data + sizeof(guint8)))->flags),
      data + sizeof(guint8) + sizeof(GoodixPresetPsk), psk_len, cb_info->user_data, NULL);
}

static void
goodix_receive_preset_psk_write(FpDevice *dev, guint8 *data, guint16 length,
                                gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixSuccessCallback callback = (GoodixSuccessCallback)cb_info->callback;

  if (error)
    {
      callback(dev, FALSE, cb_info->user_data, error);
      return;
    }

  if (length < sizeof(guint8))
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid preset PSK write reply length: %d", length);
      callback(dev, FALSE, cb_info->user_data, error);
      return;
    }

  callback(dev, data[0] == 0x00 ? TRUE : FALSE, cb_info->user_data, NULL);
}

static void
goodix_receive_firmware_version(FpDevice *dev, guint8 *data, guint16 length,
                                gpointer user_data, GError *error)
{
  g_autofree gchar *payload = g_malloc(length + sizeof(gchar));
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixFirmwareVersionCallback callback
      = (GoodixFirmwareVersionCallback)cb_info->callback;

  if (error)
    {
      callback(dev, NULL, cb_info->user_data, error);
      return;
    }

  memcpy(payload, data, length);

  /* Some device send the firmware without the null terminator */
  payload[length] = 0x00;

  callback(dev, payload, cb_info->user_data, NULL);
}

static void
goodix_receive_ack(FpDevice *dev, guint8 *data, guint16 length, gpointer user_data,
                   GError *error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  GoodixAck *ack = (GoodixAck *)data;
  guint8 cmd;

  if (length != sizeof(GoodixAck))
    {
      fp_warn("Invalid ACK length: %d", length);
      return;
    }

  if (!ack->always_true)
    {
      /* Warn about error. */
      fp_warn("Invalid ACK flags: 0x%02x", data[sizeof(guint8)]);
      return;
    }

  cmd = ack->cmd;

  if (ack->has_no_config)
    fp_warn("MCU has no config");

  if (priv->cmd != cmd)
    {
      fp_warn("Invalid ACK command: 0x%02x", cmd);
      return;
    }

  if (!priv->ack)
    {
      fp_warn("Didn't expect an ACK for command: 0x%02x", priv->cmd);
      return;
    }

  if (!priv->reply)
    {
      G_DEBUG_HERE();
      goodix_receive_done(dev, NULL, 0, NULL);
      return;
    }

  priv->ack = FALSE;
}

static void
goodix_receive_protocol(FpDevice *dev, guint8 *data, guint32 length)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  guint8 cmd;
  g_autofree guint8 *payload = NULL;
  guint16 payload_len;
  gboolean valid_checksum, valid_null_checksum;

  if (!goodix_decode_protocol(data, length, &cmd, &payload, &payload_len, &valid_checksum,
                              &valid_null_checksum))
    {
      fp_err("Incomplete, size: %d", length);
      return;
    }

  if (cmd == GOODIX_CMD_ACK)
    {
      fp_dbg("got ack");
      goodix_receive_ack(dev, payload, payload_len, NULL, NULL);
      return;
    }

  if (priv->cmd != cmd)
    {
      fp_warn("Invalid protocol command: 0x%02x", cmd);
      return;
    }

  if (!priv->reply)
    {
      fp_warn("Didn't expect a reply for command: 0x%02x", priv->cmd);
      return;
    }

  if (priv->ack)
    fp_warn("Didn't get ACK for command: 0x%02x", priv->cmd);

  goodix_receive_done(dev, payload, payload_len, NULL);
}

static void
goodix_receive_pack(FpDevice *dev, guint8 *data, guint32 length)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  guint8 flags;
  g_autofree guint8 *payload = NULL;
  guint16 payload_len;
  gboolean valid_checksum;

  priv->data = g_realloc(priv->data, priv->length + length);
  memcpy(priv->data + priv->length, data, length);
  priv->length += length;

  if (!goodix_decode_pack(priv->data, priv->length, &flags, &payload, &payload_len,
                          &valid_checksum))
    {
      /* Packet is not full, we still need data. */
      fp_dbg("not full packet");
      return;
    }

  /* Checksum mismatch is logged but not treated as a hard error:
   * the sensor firmware uses the placeholder value 0x88 for many
   * responses, so rejecting would break normal operation. */
  if (!valid_checksum)
    fp_warn ("pack checksum mismatch (accepted anyway)");

  priv->last_pack_flags = flags;
  switch (flags)
    {
    case GOODIX_FLAGS_MSG_PROTOCOL:
      fp_dbg("Got protocol msg");
      goodix_receive_protocol(dev, payload, payload_len);
      break;

    case GOODIX_FLAGS_TLS:
      fp_dbg("Got TLS msg");
      goodix_receive_done(dev, payload, payload_len, NULL);
      break;

    case GOODIX_FLAGS_MSG_DATA:
      if (priv->cmd == GOODIX_CMD_MCU_GET_IMAGE && priv->reply && !priv->ack &&
          priv->callback == goodix_receive_default)
        goodix_receive_done(dev, payload, payload_len, NULL);
      else
        fp_warn("Unexpected image data packet");
      break;

    default:
      fp_warn("Unknown flags: 0x%02x", flags);
      break;
    }

  g_clear_pointer(&priv->data, g_free);
  priv->length = 0;
}

static void
goodix_receive_data_cb(FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data,
                       GError *error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  fp_dbg("goodix_receive_data_cb: actual_length=%u, inited=%d, err=%s",
         (guint)transfer->actual_length, priv->inited, error ? error->message : "none");

  if (!priv->inited || g_cancellable_is_cancelled(priv->transfer_cancel_tkn))
    {
      fp_dbg("read loop stopped, discarding transfer");
      g_clear_error(&error);
      return;
    }
  if (error)
    {
      fp_warn("Receive data error: %s", error->message);
      if (priv->tls_ready_callback)
        {
          /* This transfer is gone; a later activation must start a new IN
           * loop rather than believing one is still outstanding. */
          priv->inited = FALSE;
          goodix_tls_complete (dev, error);
          return;
        }
      g_clear_error (&error);
      goodix_receive_data(dev);
      return;
    }

  if (transfer->actual_length > 0)
    goodix_receive_pack(dev, transfer->buffer, transfer->actual_length);

  if (priv->inited && !g_cancellable_is_cancelled (priv->transfer_cancel_tkn))
    goodix_receive_data(dev);
}

static void
goodix_receive_timeout_cb(FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  GError *error = NULL;

  g_set_error(&error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "Command timed out: 0x%02x",
              priv->cmd);
  goodix_receive_done(dev, NULL, 0, error);
}

void
goodix_start_read_loop(FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  if (priv->inited)
    /* Already going */
    return;
  else
    priv->inited = TRUE;
  if (g_cancellable_is_cancelled(priv->transfer_cancel_tkn))
    g_cancellable_reset(priv->transfer_cancel_tkn);

  goodix_receive_data(dev);
}

static void
goodix_receive_data(FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  transfer->short_is_error = FALSE;

  fp_dbg("goodix_receive_data: submitting bulk IN on ep 0x%02x", priv->ep_in);
  fpi_usb_transfer_fill_bulk(transfer, priv->ep_in, GOODIX_EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit(transfer, 0, priv->transfer_cancel_tkn, goodix_receive_data_cb,
                          NULL);
}

/* ---- GOODIX RECEIVE SECTION END ---- */

/* ----------------------------------------------------------------------------- */

/* ---- GOODIX SEND SECTION START ---- */

static gboolean
goodix_send_data(FpDevice *dev, guint8 *data, guint32 length, GDestroyNotify free_func,
                 GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  fp_dbg("goodix_send_data: sending %u bytes on ep 0x%02x", length, priv->ep_out);

  for (guint32 i = 0; i < length; i += GOODIX_EP_OUT_MAX_BUF_SIZE)
    {
      FpiUsbTransfer *transfer = fpi_usb_transfer_new(dev);
      transfer->short_is_error = TRUE;

      fpi_usb_transfer_fill_bulk_full(transfer, priv->ep_out, data + i,
                                      GOODIX_EP_OUT_MAX_BUF_SIZE, NULL);

      if (!fpi_usb_transfer_submit_sync(transfer, GOODIX_TIMEOUT, error))
        {
          if (free_func)
            free_func(data);
          fpi_usb_transfer_unref(transfer);
          return FALSE;
        }
      fpi_usb_transfer_unref(transfer);
    }

  if (free_func)
    free_func(data);
  return TRUE;
}

static gboolean
goodix_send_pack(FpDevice *dev, guint8 flags, guint8 *payload, guint16 length,
                 GDestroyNotify free_func, GError **error)
{
  guint8 *data;
  guint32 data_len;

  goodix_encode_pack(flags, payload, length, TRUE, &data, &data_len);
  if (free_func)
    free_func(payload);

  return goodix_send_data(dev, data, data_len, g_free, error);
}

/* A protocol write without a command slot.  Recovery must not reserve the
 * slot needed by the next NOP, nor wait for firmware that may be wedged. */
gboolean
goodix_tls_recover_device (FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  GoodixNone payload = { .reserved = { 0x00, 0x00 } };
  guint8 *data;
  guint32 length;

  if (g_usb_device_get_pid (fpi_device_get_usb_device (dev)) != 0x5120)
    return TRUE;
  if (!priv->usb_claimed)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CLOSED,
                           "Goodix USB interface is not claimed");
      return FALSE;
    }
  goodix_encode_protocol (GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED,
                          (guint8 *)&payload, sizeof payload, TRUE, FALSE,
                          &data, &length);
  return goodix_send_pack (dev, GOODIX_FLAGS_MSG_PROTOCOL, data, length,
                           g_free, error);
}

static void
goodix_send_protocol(FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 length,
                     GDestroyNotify free_func, gboolean calc_checksum, guint timeout_ms,
                     gboolean reply, GoodixCmdCallback callback, gpointer user_data)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  GError *error = NULL;
  guint8 *data;
  guint32 data_len;

  if (priv->ack || priv->reply || priv->timeout)
    {
      /* A command is already running. */
      fp_warn("A command is already running: 0x%02x", priv->cmd);
      if (free_func)
        free_func((void *)payload);
      return;
    }

  fp_dbg("Running command: 0x%02x", cmd);

  if (timeout_ms)
    priv->timeout
        = fpi_device_add_timeout(dev, timeout_ms, goodix_receive_timeout_cb, NULL, NULL);
  priv->cmd = cmd;
  priv->ack = TRUE;
  priv->reply = reply;
  priv->callback = callback;
  priv->user_data = user_data;

  goodix_encode_protocol(cmd, payload, length, calc_checksum, FALSE, &data, &data_len);
  if (free_func)
    free_func((void *)payload);

  if (!goodix_send_pack(dev, GOODIX_FLAGS_MSG_PROTOCOL, data, data_len, g_free, &error))
    {
      goodix_receive_done(dev, NULL, 0, error);
      return;
    };
}

/* Helper: allocate a GoodixCallbackInfo if callback is non-NULL. */
static GoodixCallbackInfo *
goodix_make_cb_info (GCallback callback, gpointer user_data)
{
  if (!callback)
    return NULL;

  GoodixCallbackInfo *cb_info = g_new (GoodixCallbackInfo, 1);
  cb_info->callback = callback;
  cb_info->user_data = user_data;
  return cb_info;
}

void
goodix_send_nop(FpDevice *dev, GoodixNoneCallback callback, gpointer user_data)
{
  GoodixNop payload = { .unknown = 0x00000000 };

  goodix_send_protocol(dev, GOODIX_CMD_NOP, (guint8 *)&payload, sizeof(payload), NULL,
                       FALSE, GOODIX_TIMEOUT, FALSE,
                       callback ? goodix_receive_none : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
  goodix_receive_done(dev, NULL, 0, NULL);
}

static void
goodix_send_mcu_get_image(FpDevice *dev, GoodixImageCallback callback, gpointer user_data)
{
  GoodixDefault payload = { .unused_flags = 0x01 };

  goodix_send_protocol(dev, GOODIX_CMD_MCU_GET_IMAGE, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_mcu_switch_to_fdt_down(FpDevice *dev, const guint8 *mode, guint16 length,
                                   GDestroyNotify free_func,
                                   GoodixDefaultCallback callback, gpointer user_data)
{
  guint8 *payload = g_malloc(length + 1);

  memcpy(payload + 1, mode, length);
  payload[0] = 0xc;
  if (free_func)
    free_func((void *)mode);

  goodix_send_protocol(dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN, payload, length + 1, g_free,
                       TRUE, 0, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_mcu_switch_to_fdt_up(FpDevice *dev, const guint8 *mode, guint16 length,
                                 GDestroyNotify free_func, GoodixDefaultCallback callback,
                                 gpointer user_data)
{
  guint8 *payload = g_malloc(length + 1);

  memcpy(payload + 1, mode, length);
  payload[0] = 0xe;
  if (free_func)
    free_func((void *)mode);

  goodix_send_protocol(dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP, payload, length + 1, g_free,
                       TRUE, 0, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_mcu_switch_to_fdt_mode(FpDevice *dev, const guint8 *mode, guint16 length,
                                   GDestroyNotify free_func,
                                   GoodixDefaultCallback callback, gpointer user_data)
{
  guint8 *payload = g_malloc(length);
  memcpy(payload, mode, length);
  if (free_func)
    free_func((void *)mode);

  goodix_send_protocol(dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE, payload, length, g_free,
                       TRUE, 0, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_nav_0(FpDevice *dev, GoodixDefaultCallback callback, gpointer user_data)
{
  GoodixDefault payload = { .unused_flags = 0x01 };

  goodix_send_protocol(dev, GOODIX_CMD_NAV_0, (guint8 *)&payload, sizeof(payload),
                       NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_mcu_switch_to_idle_mode(FpDevice *dev, guint8 sleep_time,
                                    GoodixNoneCallback callback, gpointer user_data)
{
  GoodixMcuSwitchToIdleMode payload = { .sleep_time = sleep_time };

  goodix_send_protocol(dev, GOODIX_CMD_MCU_SWITCH_TO_IDLE_MODE, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE,
                       callback ? goodix_receive_none : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_write_sensor_register(FpDevice *dev, guint16 address, guint16 value,
                                  GoodixNoneCallback callback, gpointer user_data)
{
  /* Only support one address and one value */
  GoodixWriteSensorRegister payload = { .multiples = FALSE,
                                        .address = GUINT16_TO_LE(address),
                                        .value = GUINT16_TO_LE(value) };

  goodix_send_protocol(dev, GOODIX_CMD_WRITE_SENSOR_REGISTER, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE,
                       callback ? goodix_receive_none : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_read_sensor_register(FpDevice *dev, guint16 address, guint8 length,
                                 GoodixDefaultCallback callback, gpointer user_data)
{
  /* Only support one address */
  GoodixReadSensorRegister payload
      = { .multiples = FALSE, .address = GUINT16_TO_LE(address), .length = length };

  goodix_send_protocol(dev, GOODIX_CMD_READ_SENSOR_REGISTER, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_upload_config_mcu(FpDevice *dev, guint8 *config, guint16 length,
                              GDestroyNotify free_func, GoodixSuccessCallback callback,
                              gpointer user_data)
{
  goodix_send_protocol(dev, GOODIX_CMD_UPLOAD_CONFIG_MCU, config, length, free_func,
                       TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_success : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_set_powerdown_scan_frequency(FpDevice *dev, guint16 powerdown_scan_frequency,
                                         GoodixSuccessCallback callback,
                                         gpointer user_data)
{
  GoodixSetPowerdownScanFrequency payload
      = { .powerdown_scan_frequency = GUINT16_TO_LE(powerdown_scan_frequency) };

  goodix_send_protocol(dev, GOODIX_CMD_SET_POWERDOWN_SCAN_FREQUENCY,
                       (guint8 *)&payload, sizeof(payload), NULL, TRUE,
                       GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_success : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_set_powerdown_scan_frequency_ack_only(FpDevice *dev,
                                                  guint16 powerdown_scan_frequency,
                                                  GoodixNoneCallback callback,
                                                  gpointer user_data)
{
  GoodixSetPowerdownScanFrequency payload
      = { .powerdown_scan_frequency = GUINT16_TO_LE(powerdown_scan_frequency) };

  goodix_send_protocol(dev, GOODIX_CMD_SET_POWERDOWN_SCAN_FREQUENCY,
                       (guint8 *)&payload, sizeof(payload), NULL, TRUE,
                       GOODIX_TIMEOUT, FALSE,
                       callback ? goodix_receive_none : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_enable_chip(FpDevice *dev, gboolean enable, GoodixNoneCallback callback,
                        gpointer user_data)
{
  GoodixEnableChip payload = { .enable = enable ? TRUE : FALSE };

  goodix_send_protocol(dev, GOODIX_CMD_ENABLE_CHIP, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE,
                       callback ? goodix_receive_none : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_reset(FpDevice *dev, gboolean reset_sensor, guint8 sleep_time,
                  GoodixResetCallback callback, gpointer user_data)
{
  /* Only support reset sensor */
  GoodixReset payload = { .soft_reset_mcu = FALSE,
                          .reset_sensor = reset_sensor ? TRUE : FALSE,
                          .sleep_time = sleep_time };

  goodix_send_protocol(dev, GOODIX_CMD_RESET, (guint8 *)&payload, sizeof(payload),
                       NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_reset : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_query_firmware_version(FpDevice *dev, GoodixFirmwareVersionCallback callback,
                                   gpointer user_data)
{
  GoodixNone payload = { .reserved = { 0x00, 0x00 } };

  goodix_send_protocol(dev, GOODIX_CMD_FIRMWARE_VERSION, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_firmware_version : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_query_mcu_state(FpDevice *dev, GoodixDefaultCallback callback,
                            gpointer user_data)
{
  GoodixQueryMcuState payload = { .unused_flags = 0x55 };

  goodix_send_protocol(dev, GOODIX_CMD_QUERY_MCU_STATE, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_request_tls_connection(FpDevice *dev, GoodixDefaultCallback callback,
                                   gpointer user_data)
{
  GoodixNone payload = { .reserved = { 0x00, 0x00 } };

  goodix_send_protocol(dev, GOODIX_CMD_REQUEST_TLS_CONNECTION, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, 0, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_tls_successfully_established(FpDevice *dev, GoodixNoneCallback callback,
                                         gpointer user_data)
{
  GoodixNone payload = { .reserved = { 0x00, 0x00 } };

  /* Known issue: the TLS-established command always times out after 10 ms.
   * The sensor acknowledges the command via TLS but does not send a
   * protocol-level reply.  The 10 ms timeout lets the command complete
   * without blocking.  The Python reference driver exhibits the same
   * behaviour. */
  goodix_send_protocol(dev, GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED,
                       (guint8 *)&payload, sizeof(payload), NULL, TRUE, 10, FALSE,
                       callback ? goodix_receive_none : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_read_otp(FpDevice *dev, GoodixDefaultCallback callback, gpointer user_data)
{
  GoodixNone payload = { .reserved = { 0x00, 0x00 } };

  goodix_send_protocol(dev, GOODIX_CMD_READ_OTP, (guint8 *)&payload, sizeof(payload),
                       NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_default : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_preset_psk_write(FpDevice *dev, guint32 flags, guint8 *psk, guint16 length,
                             GDestroyNotify free_func, GoodixSuccessCallback callback,
                             gpointer user_data)
{
  gsize payload_len = sizeof (GoodixPresetPsk) + (gsize)length;
  guint8 *payload;
  if (g_usb_device_get_pid (fpi_device_get_usb_device (dev)) == 0x5120)
    payload_len = (payload_len + 3) & ~(gsize)3;
  if (!psk || payload_len > G_MAXUINT16 - 4)
    {
      if (free_func)
        free_func (psk);
      if (callback)
        callback (dev, FALSE, user_data,
                  g_error_new_literal (G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                                       "Invalid preset PSK write length"));
      return;
    }
  payload = g_malloc0 (payload_len);
  GoodixPresetPsk *preset_psk = (GoodixPresetPsk *)payload;

  preset_psk->flags = GUINT32_TO_LE(flags);
  preset_psk->length = GUINT32_TO_LE(length);
  memcpy(payload + sizeof(GoodixPresetPsk), psk, length);
  if (free_func)
    free_func(psk);

  goodix_send_protocol(dev, GOODIX_CMD_PRESET_PSK_WRITE, payload,
                       (guint16)payload_len, g_free, TRUE,
                       GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_preset_psk_write : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

void
goodix_send_preset_psk_read(FpDevice *dev, guint32 flags, guint16 length,
                            GoodixPresetPskReadCallback callback, gpointer user_data)
{
  GoodixPresetPsk payload
      = { .flags = GUINT32_TO_LE(flags), .length = GUINT32_TO_LE(length) };

  goodix_send_protocol(dev, GOODIX_CMD_PRESET_PSK_READ, (guint8 *)&payload,
                       sizeof(payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                       callback ? goodix_receive_preset_psk_read : NULL,
                       goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

/* ---- GOODIX SEND SECTION END ---- */

/* ----------------------------------------------------------------------------- */

/* ---- DEV SECTION START ---- */

static void
goodix_resolve_endpoints(FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS(self);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  g_autoptr(GPtrArray) interfaces = NULL;
  g_autoptr(GError) error = NULL;

  priv->ep_in = class->ep_in;
  priv->ep_out = class->ep_out;

  interfaces = g_usb_device_get_interfaces(fpi_device_get_usb_device(dev), &error);
  if (!interfaces)
    {
      fp_warn("Cannot read USB interfaces, using default endpoints: %s",
              error->message);
      return;
    }

  for (guint i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *iface = g_ptr_array_index(interfaces, i);
      g_autoptr(GPtrArray) endpoints = NULL;

      if (g_usb_interface_get_number(iface) != class->interface)
        continue;

      endpoints = g_usb_interface_get_endpoints(iface);
      if (!endpoints)
        continue;

      for (guint j = 0; j < endpoints->len; j++)
        {
          GUsbEndpoint *ep = g_ptr_array_index(endpoints, j);

          if (g_usb_endpoint_get_direction(ep) == G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST)
            priv->ep_in = g_usb_endpoint_get_address(ep);
          else
            priv->ep_out = g_usb_endpoint_get_address(ep);
        }
    }

  fp_dbg("Resolved endpoints: in=0x%02x out=0x%02x", priv->ep_in, priv->ep_out);
}

gboolean
goodix_dev_init(FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS(self);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  priv->timeout = NULL;
  priv->ack = FALSE;
  priv->reply = FALSE;
  priv->callback = NULL;
  priv->user_data = NULL;
  priv->data = NULL;
  priv->length = 0;
  priv->tls_closing = FALSE;
  priv->tls_exit_pending = FALSE;
  priv->tls_exit_tries = 0;
  priv->usb_claimed = FALSE;
  priv->transfer_cancel_tkn = g_cancellable_new();

  goodix_resolve_endpoints(dev);

  priv->usb_claimed = g_usb_device_claim_interface (
    fpi_device_get_usb_device (dev), class->interface, 0, error);
  return priv->usb_claimed;
}
void
goodix_reset_state(FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  if (priv->timeout)
    g_clear_pointer(&priv->timeout, g_source_destroy);
  priv->ack = FALSE;
  priv->reply = FALSE;
  priv->callback = NULL;
  priv->user_data = NULL;
}

static void
goodix_abort_command (FpDevice *dev)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if (priv->user_data &&
      (priv->callback == goodix_receive_none ||
       priv->callback == goodix_receive_default ||
       priv->callback == goodix_receive_success ||
       priv->callback == goodix_receive_reset ||
       priv->callback == goodix_receive_preset_psk_read ||
       priv->callback == goodix_receive_preset_psk_write ||
       priv->callback == goodix_receive_firmware_version))
    {
      GoodixCallbackInfo *info = priv->user_data;
      if (priv->cmd == GOODIX_CMD_MCU_GET_IMAGE &&
          info->callback == G_CALLBACK (goodix_tls_ready_image_handler))
        g_free (info->user_data);
      g_free (info);
    }
  goodix_reset_state (dev);
}

/* A failed write gets one bounded retry at the first shutdown/deinit. */
static gboolean
goodix_tls_exit (FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if (!priv->tls_exit_pending)
    return TRUE;
  if (priv->tls_exit_tries >= 2)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "Goodix TLS recovery writes exhausted");
      return FALSE;
    }
  priv->tls_exit_tries++;
  if (!goodix_tls_recover_device (dev, error))
    return FALSE;
  priv->tls_exit_pending = FALSE;
  return TRUE;
}

gboolean
goodix_dev_deinit(FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS(self);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  if (priv->tls_closing)
    return TRUE;
  priv->tls_closing = TRUE;
  if (priv->tls_ready_callback)
    goodix_tls_complete (dev, g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                           "TLS attempt cancelled"));
  goodix_tls_clear_device_psk (dev);
  priv->inited = FALSE;
  g_cancellable_cancel (priv->transfer_cancel_tkn);
  g_clear_pointer (&priv->data, g_free);
  priv->length = 0;

  GError *tls_error = NULL;
  goodix_shutdown_tls(dev, &tls_error);
  if (tls_error)
    {
      fp_warn("TLS shutdown error: %s", tls_error->message);
      if (error && !*error)
        *error = g_steal_pointer (&tls_error);
      g_clear_error (&tls_error);
    }

  goodix_abort_command (dev);
  g_clear_object (&priv->transfer_cancel_tkn);
  if (priv->usb_claimed)
    {
      GError *release_error = NULL;
      priv->usb_claimed = FALSE;
      if (!g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                           class->interface, 0, &release_error))
        {
          if (error && !*error)
            *error = g_steal_pointer (&release_error);
          g_clear_error (&release_error);
        }
    }
  return !error || !*error;
}

/* ---- DEV SECTION END ---- */

/* ----------------------------------------------------------------------------- */

/* ---- TLS SECTION START ---- */

static void
goodix_read_tls(FpDevice *dev, GoodixTlsCallback callback, gpointer user_data)
{

  fp_dbg("goodix_read_tls()");
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);
  priv->callback = callback;
  priv->user_data = user_data;
  priv->reply = TRUE;
  priv->cmd = 0;
}

/* The continuation is detached before any caller code runs: callbacks may close
 * the device or start a new attempt.  Errors are owned by the continuation. */
static void
goodix_tls_complete (FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  GoodixCallbackInfo *info = g_steal_pointer (&priv->tls_ready_callback);
  if (!info)
    { g_clear_error (&error); return; }
  g_clear_pointer (&priv->tls_deadline, g_source_destroy);
  goodix_abort_command (dev);
  priv->tls_confirming = FALSE;
  if (error)
    {
      GError *exit_error = NULL;
      if (!goodix_tls_exit (dev, &exit_error))
        fp_warn ("TLS recovery write failed: %s", exit_error->message);
      g_clear_error (&exit_error);
    }
  GoodixNoneCallback cb = (GoodixNoneCallback)info->callback;
  gpointer ud = info->user_data;
  g_free (info);
  cb (dev, ud, error);
}

gboolean
goodix_tls_cancel_attempt (FpDevice *dev)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if (!priv->tls_ready_callback)
    return FALSE;
  goodix_tls_complete (dev, g_error_new_literal (
    G_IO_ERROR, G_IO_ERROR_CANCELLED, "TLS attempt cancelled"));
  return TRUE;
}

gboolean
goodix_tls_cancel_session (FpDevice *dev, GError **error)
{
  goodix_abort_command (dev);
  return goodix_shutdown_tls (dev, error);
}

static void
goodix_tls_deadline_cb (FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if (GPOINTER_TO_UINT (user_data) != priv->tls_generation)
    return;
  priv->tls_deadline = NULL;
  goodix_tls_complete (dev, g_error_new (G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                                        "TLS handshake timed out"));
}

static void
goodix_tls_established (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if (GPOINTER_TO_UINT (user_data) != priv->tls_generation ||
      !priv->tls_ready_callback)
    { g_clear_error (&error); return; }
  /* 0xd4 arms a 10 ms timer before its synchronous USB write, so a timeout
   * says nothing about the handshake GnuTLS has already verified.  Upstream
   * and the Python reference ignore it too; USB errors still propagate. */
  if (error && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    {
      fp_dbg ("TLS established (0xd4) not acknowledged in time; ignored");
      g_clear_error (&error);
    }
  goodix_tls_complete (dev, error);
}

static void goodix_tls_pump (FpDevice *dev);

static void
goodix_tls_input (FpDevice *dev, guint8 *data, guint16 length,
                  gpointer user_data, GError *error)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if ((user_data && GPOINTER_TO_UINT (user_data) != priv->tls_generation) ||
      !priv->tls_ready_callback)
    { g_clear_error (&error); return; }
  if (error)
    { goodix_tls_complete (dev, error); return; }
  int r = goodix_tls_client_write (priv->tls_hop, data, length);
  if (r < 0)
    {
      gboolean wrong_key = priv->psk_response_len == 32 &&
                           !priv->psk_fallback_match && !priv->device_psk_len;
      goodix_tls_complete (dev, g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                                            "TLS handshake failed (%d): %s%s",
                                            r, gnutls_strerror (r), wrong_key ?
                                            " (device PSK hash does not match the"
                                            " zero-key fallback)" : ""));
      return;
    }
  goodix_tls_pump (dev);
}

static void
goodix_tls_pump (FpDevice *dev)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  guint8 buf[1024];
  int n;
  if (!priv->tls_ready_callback || priv->tls_confirming)
    return;
  while ((n = goodix_tls_client_read (priv->tls_hop, buf, sizeof buf)) > 0)
    {
      GError *error = NULL;
      if (!goodix_send_pack (dev, GOODIX_FLAGS_TLS, buf, n, NULL, &error))
        { goodix_tls_complete (dev, error); return; }
    }
  if (priv->tls_hop->handshake_done)
    {
      priv->tls_confirming = TRUE;
      goodix_send_tls_successfully_established (
        dev, goodix_tls_established, GUINT_TO_POINTER (priv->tls_generation));
    }
  else
    goodix_read_tls (dev, goodix_tls_input,
                     GUINT_TO_POINTER (priv->tls_generation));
}

static void
goodix_tls_requested (FpDevice *dev, guint8 *data, guint16 length,
                      gpointer user_data, GError *error)
{
  goodix_tls_input (dev, data, length, user_data, error);
}

gboolean
goodix_tls_set_device_psk (FpDevice *dev, const guint8 *psk, gsize len,
                             gboolean verified, GError **error)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  if (!verified || !psk || len < 1 || len > sizeof (priv->device_psk) ||
      priv->tls_ready_callback)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "Unverified, invalid or late TLS PSK");
      return FALSE;
    }
  gnutls_memset (priv->device_psk, 0, sizeof priv->device_psk);
  memcpy (priv->device_psk, psk, len);
  priv->device_psk_len = len;
  return TRUE;
}

void
goodix_tls_clear_device_psk (FpDevice *dev)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  gnutls_memset (priv->device_psk, 0, sizeof priv->device_psk);
  priv->device_psk_len = 0;
  priv->psk_response_flags = 0;
  priv->psk_response_len = 0;
  priv->psk_fallback_match = FALSE;
}

void
goodix_tls_classify_psk_response (FpDevice *dev, guint32 flags,
                                  const guint8 *psk, guint16 len)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  goodix_tls_clear_device_psk (dev);
  priv->psk_response_flags = flags;
  priv->psk_response_len = len;
  /* The response is a hash of the provisioned key, never the key itself:
   * only its relation to the zero-key fallback is recorded, not its value. */
  priv->psk_fallback_match = goodix_tls_psk_hash_matches_fallback (psk, len);
  fp_dbg ("Preset PSK response: flags=0x%08x, len=%u, matches zero-key fallback: %s",
          flags, len, priv->psk_fallback_match ? "yes" : "no");
  if (len == 32 && !priv->psk_fallback_match)
    fp_warn ("Device PSK is not the zero-key fallback; TLS is expected to fail "
             "until the provisioned key is known");
}

void
goodix_tls_init (FpDevice *dev, GoodixNoneCallback callback, gpointer user_data)
{
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (FPI_DEVICE_GOODIXTLS (dev));
  GError *error = NULL;
  if (priv->tls_closing || priv->tls_hop || priv->tls_ready_callback)
    {
      callback (dev, user_data,
                g_error_new_literal (G_IO_ERROR, G_IO_ERROR_BUSY,
                                     "TLS session is already active or closing"));
      return;
    }
  priv->tls_generation++;
  if (!priv->tls_generation)
    priv->tls_generation++;
  priv->tls_exit_pending = FALSE;
  priv->tls_exit_tries = 0;
  priv->tls_ready_callback = goodix_make_cb_info (G_CALLBACK (callback), user_data);
  priv->tls_hop = g_new0 (GoodixTlsServer, 1);
  goodix_tls_server_set_compat_profile (priv->tls_hop,
    g_usb_device_get_pid (fpi_device_get_usb_device (dev)) == 0x5120);
  if (priv->device_psk_len)
    goodix_tls_server_set_psk (priv->tls_hop, priv->device_psk, priv->device_psk_len);
  if (!goodix_tls_server_init (priv->tls_hop, &error))
    {
      g_clear_pointer (&priv->tls_hop, g_free);
      goodix_tls_complete (dev, error);
      return;
    }
  priv->tls_exit_pending = TRUE;
  priv->tls_deadline = fpi_device_add_timeout (
    dev, GOODIX_TLS_HANDSHAKE_TIMEOUT, goodix_tls_deadline_cb,
    GUINT_TO_POINTER (priv->tls_generation), NULL);
  goodix_send_request_tls_connection (
    dev, goodix_tls_requested, GUINT_TO_POINTER (priv->tls_generation));
}

gboolean
goodix_shutdown_tls(FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  gboolean result = TRUE;
  GError *exit_error = NULL;
  if (priv->tls_exit_pending)
    result = goodix_tls_exit (dev, &exit_error);
  if (exit_error)
    {
      if (error && !*error)
        *error = g_steal_pointer (&exit_error);
      g_clear_error (&exit_error);
    }
  if (priv->tls_hop)
    {
      GError *tls_error = NULL;
      gboolean rs = goodix_tls_server_deinit (priv->tls_hop, &tls_error);
      g_free(priv->tls_hop);
      priv->tls_hop = NULL;
      if (tls_error)
        {
          if (error && !*error)
            *error = g_steal_pointer (&tls_error);
          g_clear_error (&tls_error);
        }
      result = result && rs;
    }
  return result;
}
static gboolean
goodix_image_frame_valid (FpDevice *dev, const guint8 *data, gsize length)
{
  guint16 pid = g_usb_device_get_pid (fpi_device_get_usb_device (dev));
  gsize expected = pid == 0x5120 ? 7693 : 10573;

  return data && length == expected && length >= 13 &&
         data[0] == GOODIX_CMD_MCU_GET_IMAGE &&
         ((guint16)data[1] | ((guint16)data[2] << 8)) == length - 3;
}

static void
goodix_tls_ready_image_handler(FpDevice *dev, guint8 *data, guint16 length,
                               gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixImageCallback callback = (GoodixImageCallback)cb_info->callback;

  if (error)
    {
      callback(dev, NULL, 0, cb_info->user_data, error);
      return;
    }
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS(dev);
  FpiDeviceGoodixTlsPrivate *priv = fpi_device_goodixtls_get_instance_private(self);

  if (priv->last_pack_flags == GOODIX_FLAGS_MSG_DATA)
    {
      if (!goodix_image_frame_valid (dev, data, length))
        callback (dev, NULL, 0, cb_info->user_data,
                  g_error_new_literal (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                       "Invalid clear Goodix image frame"));
      else
        callback (dev, data, length, cb_info->user_data, NULL);
      return;
    }
  if (priv->last_pack_flags != GOODIX_FLAGS_TLS)
    {
      callback (dev, NULL, 0, cb_info->user_data,
                g_error_new_literal (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                     "Unexpected Goodix image packet flags"));
      return;
    }

  int sent = goodix_tls_client_write(priv->tls_hop, data, length);
  if (sent < 0)
    {
      callback (dev, NULL, 0, cb_info->user_data,
                g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
                             "TLS image write failed: %d", sent));
      return;
    }

  guint8 *buff = g_malloc(G_MAXUINT16);
  GError *err = NULL;
  int read_size = goodix_tls_server_read(priv->tls_hop, buff, G_MAXUINT16, &err);

  if (read_size <= 0)
    {
      g_free(buff);
      if (!err)
        err = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                   "Empty TLS image frame");
      callback(dev, NULL, 0, cb_info->user_data, err);
      return;
    }

  if (!goodix_image_frame_valid (dev, buff, read_size))
    callback (dev, NULL, 0, cb_info->user_data,
              g_error_new_literal (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                   "Invalid TLS Goodix image frame"));
  else
    callback(dev, buff, read_size, cb_info->user_data, NULL);
  g_free(buff);
}

void
goodix_tls_read_image(FpDevice *dev, GoodixImageCallback callback, gpointer user_data)
{
  g_assert (callback);

  goodix_send_mcu_get_image (dev, goodix_tls_ready_image_handler,
                             goodix_make_cb_info (G_CALLBACK (callback), user_data));
}

/* ---- TLS SECTION END ---- */

static void
fpi_device_goodixtls_init(FpiDeviceGoodixTls *self)
{
}

static void
fpi_device_goodixtls_class_init(FpiDeviceGoodixTlsClass *class)
{
}
