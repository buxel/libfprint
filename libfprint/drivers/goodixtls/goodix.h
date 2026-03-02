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

#include "drivers_api.h"

/* 1 second USB timeout */
#define GOODIX_TIMEOUT (1000)

G_DECLARE_DERIVABLE_TYPE(FpiDeviceGoodixTls, fpi_device_goodixtls, FPI, DEVICE_GOODIXTLS,
                         FpDevice)

#define FPI_TYPE_DEVICE_GOODIXTLS (fpi_device_goodixtls_get_type())

struct _FpiDeviceGoodixTlsClass
{
  FpDeviceClass parent;

  gint interface;
  guint8 ep_in;
  guint8 ep_out;
};

typedef struct _GoodixCallbackInfo
{
  GCallback callback;
  gpointer user_data;
} GoodixCallbackInfo;

typedef void (*GoodixCmdCallback)(FpDevice *dev, guint8 *data, guint16 length,
                                  gpointer user_data, GError *error);

typedef void (*GoodixFirmwareVersionCallback)(FpDevice *dev, gchar *firmware,
                                              gpointer user_data, GError *error);

typedef void (*GoodixPresetPskReadCallback)(FpDevice *dev, gboolean success,
                                            guint32 flags, guint8 *psk, guint16 length,
                                            gpointer user_data, GError *error);

typedef void (*GoodixSuccessCallback)(FpDevice *dev, gboolean success, gpointer user_data,
                                      GError *error);

typedef void (*GoodixResetCallback)(FpDevice *dev, gboolean success, guint16 number,
                                    gpointer user_data, GError *error);

typedef void (*GoodixNoneCallback)(FpDevice *dev, gpointer user_data, GError *error);

typedef void (*GoodixDefaultCallback)(FpDevice *dev, guint8 *data, guint16 length,
                                      gpointer user_data, GError *error);
typedef GoodixDefaultCallback GoodixTlsCallback;

typedef void (*GoodixImageCallback)(FpDevice *dev, guint8 *data, guint16 length,
                                    gpointer user_data, GError *error);

gchar *
data_to_str(guint8 *data, guint32 length);

/* ---- GOODIX RECEIVE SECTION START ---- */

/* Start the asynchronous read loop.  Call upon device activation. */
void
goodix_start_read_loop(FpDevice *dev);

/* ---- GOODIX RECEIVE SECTION END ---- */

/* ----------------------------------------------------------------------------- */

/* ---- GOODIX SEND SECTION START ---- */

/* Send a NOP command. */
void
goodix_send_nop(FpDevice *dev, GoodixNoneCallback callback, gpointer user_data);

/* Wait for the user to place their finger on the sensor. */
void
goodix_send_mcu_switch_to_fdt_down(FpDevice *dev, const guint8 *mode, guint16 length,
                                   GDestroyNotify free_func,
                                   GoodixDefaultCallback callback, gpointer user_data);

/* Wait for the user to lift their finger from the sensor. */
void
goodix_send_mcu_switch_to_fdt_up(FpDevice *dev, const guint8 *mode, guint16 length,
                                 GDestroyNotify free_func, GoodixDefaultCallback callback,
                                 gpointer user_data);

/* Prepare the device for FDT down/up commands. */
void
goodix_send_mcu_switch_to_fdt_mode(FpDevice *dev, const guint8 *mode, guint16 length,
                                   GDestroyNotify free_func,
                                   GoodixDefaultCallback callback, gpointer user_data);

void
goodix_send_nav_0(FpDevice *dev, GoodixDefaultCallback callback, gpointer user_data);

void
goodix_send_mcu_switch_to_idle_mode(FpDevice *dev, guint8 sleep_time,
                                    GoodixNoneCallback callback, gpointer user_data);

void
goodix_send_write_sensor_register(FpDevice *dev, guint16 address, guint16 value,
                                  GoodixNoneCallback callback, gpointer user_data);

void
goodix_send_read_sensor_register(FpDevice *dev, guint16 address, guint8 length,
                                 GoodixDefaultCallback callback, gpointer user_data);

/* Upload an MCU config to the device.  Config content varies by model. */
void
goodix_send_upload_config_mcu(FpDevice *dev, guint8 *config, guint16 length,
                              GDestroyNotify free_func, GoodixSuccessCallback callback,
                              gpointer user_data);

void
goodix_send_set_powerdown_scan_frequency(FpDevice *dev, guint16 powerdown_scan_frequency,
                                         GoodixSuccessCallback callback,
                                         gpointer user_data);

/* Enable or disable the sensor chip. */
void
goodix_send_enable_chip(FpDevice *dev, gboolean enable, GoodixNoneCallback callback,
                        gpointer user_data);

/* Send a reset command to the device. */
void
goodix_send_reset(FpDevice *dev, gboolean reset_sensor, guint8 sleep_time,
                  GoodixResetCallback callback, gpointer user_data);

/* Query the firmware version (returns a NUL-terminated string). */
void
goodix_send_query_firmware_version(FpDevice *dev, GoodixFirmwareVersionCallback callback,
                                   gpointer user_data);

/* Query the current MCU state. */
void
goodix_send_query_mcu_state(FpDevice *dev, GoodixDefaultCallback callback,
                            gpointer user_data);

/* Request a TLS connection with the device.
 * Prefer the goodix_tls_* helpers from driver code. */
void
goodix_send_request_tls_connection(FpDevice *dev, GoodixDefaultCallback callback,
                                   gpointer user_data);

/* Notify the device that TLS has been established.
 * Prefer the goodix_tls_* helpers from driver code. */
void
goodix_send_tls_successfully_established(FpDevice *dev, GoodixNoneCallback callback,
                                         gpointer user_data);

/* Write a preset PSK to the device.
 * May not work on all firmware versions. */
void
goodix_send_preset_psk_write(FpDevice *dev, guint32 flags, guint8 *psk, guint16 length,
                             GDestroyNotify free_func, GoodixSuccessCallback callback,
                             gpointer user_data);

/* Read the preset PSK from the device. */
void
goodix_send_preset_psk_read(FpDevice *dev, guint32 flags, guint16 length,
                            GoodixPresetPskReadCallback callback, gpointer user_data);

/* Request the OTP (One-Time Programmable) data from the device. */
void
goodix_send_read_otp(FpDevice *dev, GoodixDefaultCallback callback, gpointer user_data);

/* ---- GOODIX SEND SECTION END ---- */

/* ----------------------------------------------------------------------------- */

/* ---- DEV SECTION START ---- */

/* Claim USB resources for device communication. */
gboolean
goodix_dev_init(FpDevice *dev, GError **error);

/* Release USB resources. */
gboolean
goodix_dev_deinit(FpDevice *dev, GError **error);

/* Reset internal protocol state (e.g. on deactivation). */
void
goodix_reset_state(FpDevice *dev);

/* ---- DEV SECTION END ---- */

/* ----------------------------------------------------------------------------- */

/* ---- TLS SECTION START ---- */

/* Perform the TLS handshake with the device. */
void
goodix_tls_init(FpDevice *dev, GoodixNoneCallback callback, gpointer user_data);

/* Shut down the TLS session. */
gboolean
goodix_shutdown_tls(FpDevice *dev, GError **error);

/* Read and decrypt a TLS-encrypted image from the device. */
void
goodix_tls_read_image(FpDevice *dev, GoodixImageCallback callback, gpointer user_data);

/* ---- TLS SECTION END ---- */
