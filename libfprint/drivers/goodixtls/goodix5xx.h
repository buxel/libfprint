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
#include "fpi-ssm.h"
#include "goodix.h"

#define FPI_TYPE_DEVICE_GOODIXTLS5XX (fpi_device_goodixtls5xx_get_type())

G_DECLARE_DERIVABLE_TYPE(FpiDeviceGoodixTls5xx, fpi_device_goodixtls5xx, FPI,
                         DEVICE_GOODIXTLS5XX, FpiDeviceGoodixTls);

/*
 * Common state-machine helpers for Goodix TLS 5xx USB devices.
 *
 * At minimum a sub-driver must provide get_mcu_cfg, process_frame,
 * and the activate callback.  See goodix511.c for an example.
 */

typedef guint16 GoodixTls5xxPix;

typedef struct
{
  guint16 data_len;
  void (*free_fn)(void *);
  const guint8 *data;
} GoodixTls5xxMcuConfig;

typedef struct
{
  guint16 width;
  guint16 height;
  unsigned char *data;
} GoodixTls5xxImage;

typedef FpImage *(*GoodixTls5xxProcessFrameFn)(guint8 *pix);
typedef GoodixTls5xxMcuConfig (*GoodixTls5xxGetMcuFn)(void);
typedef void (*GoodixTls5xxResetStateFn)(FpDevice *);
typedef void (*GoodixTls5xxActivateFn)(FpDevice *dev, FpiSsm *parent_ssm);

struct _FpiDeviceGoodixTls5xxClass
{
  FpiDeviceGoodixTlsClass parent;

  GoodixTls5xxGetMcuFn get_mcu_cfg;       /* provide MCU config for FDT commands */
  GoodixTls5xxProcessFrameFn
      process_frame;                       /* post-decode frame processing (e.g. crop) */
  GoodixTls5xxResetStateFn reset_state;    /* optional state-reset callback */
  GoodixTls5xxActivateFn activate;         /* device-specific activation sub-SSM */

  guint16 scan_width;                      /* raw scanner image width */
  guint16 scan_height;                     /* raw scanner image height */

  const char
      *firmware_version;                   /* expected FW, for check_firmware_version() */

  int reset_number;                        /* expected reset number, for check_reset() */
};

/* Check the reply to a reset command. */
void
goodixtls5xx_check_reset(FpDevice *dev, gboolean success, guint16 number,
                         gpointer user_data, GError *error);

/* Verify the firmware version matches the configured string. */
void
goodixtls5xx_check_firmware_version(FpDevice *dev, gchar *firmware, gpointer user_data,
                                    GError *error);

/* Verify the preset PSK matches the configured key. */
void
goodixtls5xx_check_preset_psk_read(FpDevice *dev, gboolean success, guint32 flags,
                                   guint8 *psk, guint16 length, gpointer user_data,
                                   GError *error);

/* Check the reply to a config upload. */
void
goodixtls5xx_check_config_upload(FpDevice *dev, gboolean success, gpointer user_data,
                                 GError *error);

/* Check the reply to a powerdown-scan-frequency command. */
void
goodixtls5xx_check_powerdown_scan_freq(FpDevice *dev, gboolean success,
                                       gpointer user_data, GError *error);

/* Generic GoodixNoneCallback: advance the SSM passed as user_data. */
void
goodixtls5xx_check_none(FpDevice *dev, gpointer user_data, GError *error);

/* Generic GoodixDefaultCallback: advance the SSM passed as user_data. */
void
goodixtls5xx_check_none_cmd(FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                            GError *err);

/* Decode a raw frame from the 4/6-byte packing used by the sensor.
 * See https://blog.th0m.as/misc/fingerprint-reversing/ */
void
goodixtls5xx_decode_frame(GoodixTls5xxPix *frame, guint32 frame_size,
                          const guint8 *raw_frame);

/* Perform the TLS handshake.  Called after activation completes. */
void
goodixtls5xx_init_tls(FpDevice *dev, FpiSsm *ssm);

/* Clean up state after activation (called during deactivation). */
void
goodixtls5xx_cleanup(FpiDeviceGoodixTls5xx *dev);
