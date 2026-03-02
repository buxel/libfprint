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

#define FP_COMPONENT "goodixtls5xx"

#include "drivers/goodixtls/goodix5xx.h"
#include "drivers_api.h"
#include "fpi-print.h"
#include "fpi-ssm.h"
#include "goodix.h"
#include "sigfm.h"

#include <math.h>
#include <stdio.h>

typedef struct
{
  GoodixTls5xxPix *calibration_img;
  SigfmImgInfo    *last_sigfm_info;
  FpImage         *last_image;

  /* Enroll state */
  gint             enroll_stage;
  GPtrArray       *enroll_data;    /* array of GBytes* (serialized descriptors) */
  gboolean         last_scan;     /* TRUE on last enroll scan — skip FDT_UP wait */

  /* Task SSM (active enroll/verify/identify) */
  FpiSsm          *task_ssm;
} FpiDeviceGoodixTls5xxPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE(FpiDeviceGoodixTls5xx, fpi_device_goodixtls5xx,
                                    FPI_TYPE_DEVICE_GOODIXTLS)

enum CALIBRATION_STAGES
{
  CALIBRATION_STAGE_FDT_UP,
  CALIBRATION_STAGE_NAV0,
  CALIBRATION_STAGE_GET_IMG,

  CALIBRATION_STAGE_NUM,

};

enum SCAN_STAGES
{
  SCAN_STAGE_QUERY_MCU,
  SCAN_STAGE_SWITCH_TO_FDT_MODE,
  SCAN_STAGE_CALIBRATE,
  SCAN_STAGE_SWITCH_TO_FDT_DOWN,
  SCAN_STAGE_GET_IMG,
  SCAN_STAGE_SWITCH_TO_FTD_UP,
  SCAN_STAGE_SWITCH_TO_FTD_DONE,

  SCAN_STAGE_NUM,
};

static void
send_switch_mode(FpDevice *dev, gpointer ssm,
                 void (*mode_switch)(FpDevice *, const guint8 *, guint16, GDestroyNotify,
                                     GoodixDefaultCallback, gpointer))
{
  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(dev);
  GoodixTls5xxMcuConfig cfg = cls->get_mcu_cfg();

  mode_switch(dev, cfg.data, cfg.data_len, cfg.free_fn, goodixtls5xx_check_none_cmd, ssm);
}
static void
on_calibrate_scan(FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed(ssm, err);
      return;
    }
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX(dev);
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(self);
  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(self);
  if (!priv->calibration_img)
    {
      priv->calibration_img
          = g_malloc0(cls->scan_height * cls->scan_width * sizeof(GoodixTls5xxPix));
    }
  goodixtls5xx_decode_frame(priv->calibration_img, len, data);

  fpi_ssm_next_state(ssm);
}
static void
calibrate_run(FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state(ssm))
    {
    case CALIBRATION_STAGE_FDT_UP:
      send_switch_mode(dev, ssm, goodix_send_mcu_switch_to_fdt_up);
      break;
    case CALIBRATION_STAGE_NAV0:
      goodix_send_nav_0(dev, goodixtls5xx_check_none_cmd, ssm);
      break;
    case CALIBRATION_STAGE_GET_IMG:
      goodix_tls_read_image(dev, on_calibrate_scan, ssm);
    }
}

static void
do_calibration(FpDevice *dev, FpiSsm *parent)
{
  fpi_ssm_start_subsm(parent, fpi_ssm_new(dev, calibrate_run, CALIBRATION_STAGE_NUM));
}

void
goodixtls5xx_check_none(FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  fpi_ssm_next_state(user_data);
}

void
goodixtls5xx_check_none_cmd(FpDevice *dev, guint8 *data, guint16 len, gpointer ssm,
                            GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed(ssm, err);
      return;
    }
  fpi_ssm_next_state(ssm);
}

void
goodixtls5xx_check_firmware_version(FpDevice *dev, gchar *firmware, gpointer user_data,
                                    GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  fp_dbg("Device firmware: \"%s\"", firmware);
  FpiDeviceGoodixTls5xxClass *cls
      = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(FPI_DEVICE_GOODIXTLS5XX(dev));

  /* Accept any firmware in the same family (prefix match up to the
   * last underscore, e.g. "GF_ST411SEC_APP_121xx").  The exact
   * trailing digits may change across vendor firmware updates without
   * affecting protocol compatibility. */
  const gchar *expected = cls->firmware_version;
  const gchar *sep      = g_strrstr(expected, "_");
  gsize        prefix_len = sep ? (gsize)(sep - expected + 1) : strlen(expected);

  if (strncmp(firmware, expected, prefix_len) != 0)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Incompatible device firmware: \"%s\" (expected prefix \"%.*s\")",
                  firmware, (int)prefix_len, expected);
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  if (strcmp(firmware, expected) != 0)
    fp_dbg("Accepted firmware \"%s\" (expected \"%s\", prefix match)",
           firmware, expected);

  fpi_ssm_next_state(user_data);
}

void
goodixtls5xx_check_preset_psk_read(FpDevice *dev, gboolean success, guint32 flags,
                                   guint8 *psk, guint16 length, gpointer user_data,
                                   GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  if (!success)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_FAILED,
                  "Failed to read PSK from device");
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  if (length == 0 || length > 64)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Device PSK has invalid length: %u", length);
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  g_autofree gchar *psk_str = data_to_str(psk, length);
  fp_dbg("Device PSK: 0x%s (flags=0x%08x, len=%u)", psk_str, flags, length);

  fpi_ssm_next_state(user_data);
}

void
goodixtls5xx_check_idle(FpDevice *dev, gpointer user_data, GError *err)
{

  if (err)
    {
      fpi_ssm_mark_failed(user_data, err);
      return;
    }
  fpi_ssm_next_state(user_data);
}
void
goodixtls5xx_check_config_upload(FpDevice *dev, gboolean success, gpointer user_data,
                                 GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(user_data, error);
    }
  else if (!success)
    {
      fpi_ssm_mark_failed(user_data, g_error_new(FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                                 "failed to upload mcu config"));
    }
  else
    {
      fpi_ssm_next_state(user_data);
    }
}
void
goodixtls5xx_check_reset(FpDevice *dev, gboolean success, guint16 number,
                         gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  if (!success)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed to reset device");
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  fp_dbg("Device reset number: %d", number);

  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(dev);
  if (number != cls->reset_number)
    {
      g_set_error(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                  "Invalid device reset number: %d", number);
      fpi_ssm_mark_failed(user_data, error);
      return;
    }

  fpi_ssm_next_state(user_data);
}

void
goodixtls5xx_check_powerdown_scan_freq(FpDevice *dev, gboolean success,
                                       gpointer user_data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(user_data, error);
    }
  else if (!success)
    {
      fpi_ssm_mark_failed(user_data, g_error_new(FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                                 "failed to set powerdown freq"));
    }
  else
    {
      fpi_ssm_next_state(user_data);
    }
}

static void
goodixtls5xx_squash_frame_linear(GoodixTls5xxPix *frame, guint8 *squashed,
                                 guint16 frame_size)
{
  GoodixTls5xxPix min = 0xffff;
  GoodixTls5xxPix max = 0;

  for (int i = 0; i != frame_size; ++i)
    {
      const GoodixTls5xxPix pix = frame[i];
      if (pix < min)
        min = pix;
      if (pix > max)
        max = pix;
    }

  for (int i = 0; i != frame_size; ++i)
    {
      const GoodixTls5xxPix pix = frame[i];
      if (pix - min == 0 || max - min == 0)
        squashed[i] = 0;
      else
        squashed[i] = (pix - min) * 0xff / (max - min);
    }
}

/* -------------------------------------------------------------------------
 * goodixtls5xx_squash_frame_percentile:
 *
 * Percentile-based histogram stretch: find P0.1 (black level) and P99
 * (white level), then map [P0.1, P99] → [0, 255], clipping outliers.
 * Matches the PPLIB hist_equalization used by the Windows GFEngine driver.
 *
 * This produces much better dynamic range than the linear min-max stretch,
 * especially when a few saturated pixels would otherwise dominate the range.
 * ---------------------------------------------------------------------- */
static void
goodixtls5xx_squash_frame_percentile(GoodixTls5xxPix *frame, guint8 *squashed,
                                     guint16 frame_size)
{
  /* Build histogram of the 16-bit values (bucket into 256 bins) */
  guint32 hist[256] = { 0 };
  for (int i = 0; i < frame_size; i++)
    hist[frame[i] >> 8]++;

  /* Find P0.1 (black level) */
  guint32 target_lo = (guint32)(frame_size * 1u + 999u) / 1000u; /* ceil(0.1%) */
  guint32 count = 0;
  int bin_lo = 0;
  for (int b = 0; b < 256; b++)
    {
      count += hist[b];
      if (count >= target_lo)
        {
          bin_lo = b;
          break;
        }
    }

  /* Find P99 (white level) */
  guint32 target_hi = (guint32)(frame_size * 99u) / 100u;
  count = 0;
  int bin_hi = 255;
  for (int b = 255; b >= 0; b--)
    {
      count += hist[b];
      if ((guint32)frame_size - count <= target_hi)
        {
          bin_hi = b;
          break;
        }
    }

  if (bin_hi <= bin_lo)
    {
      /* Degenerate image - fall back to linear */
      goodixtls5xx_squash_frame_linear(frame, squashed, frame_size);
      return;
    }

  GoodixTls5xxPix plo = (GoodixTls5xxPix)(bin_lo << 8);
  GoodixTls5xxPix phi = (GoodixTls5xxPix)(bin_hi << 8);
  int range = (int)phi - (int)plo;

  for (int i = 0; i < frame_size; i++)
    {
      int v = (int)frame[i] - (int)plo;
      if (v <= 0)
        squashed[i] = 0;
      else if (v >= range)
        squashed[i] = 255;
      else
        squashed[i] = (guint8)(v * 255 / range);
    }
}

/* -------------------------------------------------------------------------
 * goodixtls5xx_unsharp_mask_inplace:
 *
 * Unsharp mask: out = clip(boost × in − (boost−1) × blur(in)) using a
 * 3×3 Gaussian kernel [1,2,1 / 2,4,2 / 1,2,1] / 16.  Sharpens ridge
 * detail after the histogram stretch, increasing BRIEF descriptor
 * discriminability.  Windows driver uses boost ≈ 10 with per-pixel factory
 * calibration; without calibration, boost > 4 amplifies fixed-pattern sensor
 * noise and destroys impostor rejection (tested: boost=6 → impostor max 23,
 * boost=8 → impostor max 33, vs boost=4 → impostor max 5).
 * ---------------------------------------------------------------------- */
#define UNSHARP_BOOST 4

static void
goodixtls5xx_unsharp_mask_inplace(guint8 *img, int w, int h)
{
  guint8 *blurred = g_malloc(w * h);

  for (int y = 0; y < h; y++)
    {
      for (int x = 0; x < w; x++)
        {
          /* 3×3 Gaussian weights: corner=1, edge=2, centre=4 */
          int sum = 0, weight = 0;
          for (int dy = -1; dy <= 1; dy++)
            {
              int ny = y + dy;
              if (ny < 0 || ny >= h)
                continue;
              for (int dx = -1; dx <= 1; dx++)
                {
                  int nx = x + dx;
                  if (nx < 0 || nx >= w)
                    continue;
                  int w_px = (dx == 0 ? 2 : 1) * (dy == 0 ? 2 : 1);
                  sum += w_px * img[ny * w + nx];
                  weight += w_px;
                }
            }
          blurred[y * w + x] = (guint8)(sum / weight);
        }
    }

  for (int i = 0; i < w * h; i++)
    {
      int v = UNSHARP_BOOST * (int)img[i] - (UNSHARP_BOOST - 1) * (int)blurred[i];
      img[i] = (guint8)CLAMP(v, 0, 255);
    }

  g_free(blurred);
}
static void
linear_subtract_inplace(GoodixTls5xxPix *src, GoodixTls5xxPix *by, guint16 len)
{
  const guint16 max = -1;
  for (guint16 n = 0; n != len; ++n)
    {
      src[n] = MAX(0, max - ((max - src[n]) - (max - by[n])));
    }
}

static void
scan_on_read_img(FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *err)
{
  if (err)
    {
      fpi_ssm_mark_failed(ssm, err);
      return;
    }

  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX(dev);
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(self);
  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(dev);

  GoodixTls5xxPix *raw_frame
      = g_malloc0(cls->scan_width * cls->scan_height * sizeof(GoodixTls5xxPix));
  goodixtls5xx_decode_frame(raw_frame, len, data);
  linear_subtract_inplace(raw_frame, priv->calibration_img,
                          cls->scan_width * cls->scan_height);

  /* Raw frame dump for offline A/B testing (debug builds only, env-gated).
   * Usage: FP_SAVE_RAW=/path/to/dir ./img-capture finger.pgm
   * Produces: calibration.bin (once) + raw_NNNN.bin per capture.
   * Each file is scan_width × scan_height × sizeof(uint16) bytes. */
#ifndef NDEBUG
  {
    const char *save_dir = g_getenv ("FP_SAVE_RAW");

    if (save_dir)
      {
        int npix = cls->scan_width * cls->scan_height;
        char path[256];

        /* Save calibration frame once */
        g_snprintf (path, sizeof (path), "%s/calibration.bin", save_dir);
        if (!g_file_test (path, G_FILE_TEST_EXISTS))
          {
            FILE *cf = fopen (path, "wb");

            if (cf)
              {
                fwrite (priv->calibration_img,
                        sizeof (GoodixTls5xxPix), npix, cf);
                fclose (cf);
                fp_dbg ("saved calibration frame to %s (%d pixels)",
                        path, npix);
              }
          }

        /* Pick next sequence number by scanning for an unused filename. */
        {
          int seq = 0;

          for (;;)
            {
              g_snprintf (path, sizeof (path),
                          "%s/raw_%04d.bin", save_dir, seq);
              if (!g_file_test (path, G_FILE_TEST_EXISTS))
                break;
              seq++;
            }

          /* Save raw frame (post-decode, post-cal-subtract,
           * pre-stretch/unsharp) */
          {
            FILE *rf = fopen (path, "wb");

            if (rf)
              {
                fwrite (raw_frame, sizeof (GoodixTls5xxPix), npix, rf);
                fclose (rf);
                fp_dbg ("saved raw frame to %s (%d pixels)", path, npix);
              }
          }
        }
      }
  }
#endif /* !NDEBUG */

  guint8 *squashed = g_malloc0(cls->scan_height * cls->scan_width);
  goodixtls5xx_squash_frame_percentile(raw_frame, squashed,
                                       cls->scan_height * cls->scan_width);
  g_free(raw_frame);
  goodixtls5xx_unsharp_mask_inplace(squashed, cls->scan_width, cls->scan_height);
  FpImage *img = cls->process_frame(squashed);
  g_free(squashed);

  /* Quality gate: reject frames with insufficient contrast (no finger,
   * partial touch, or wet/smeared contact).  Compute the standard
   * deviation of pixel intensities in the image — a flat frame (all
   * similar values) indicates no useful ridge detail.  This prevents
   * garbage frames from consuming fprintd retry attempts.
   *
   * Threshold calibrated from the 5-finger corpus: genuine frames have
   * stddev ≥ 40; background/air frames have stddev < 15. */
#define QUALITY_STDDEV_MIN 25
  {
    int npx = img->width * img->height;
    long sum = 0;
    for (int i = 0; i < npx; i++)
      sum += img->data[i];
    int mean = (int)(sum / npx);
    long var = 0;
    for (int i = 0; i < npx; i++)
      {
        int d = (int)img->data[i] - mean;
        var += d * d;
      }
    int stddev = (int)sqrt((double)var / npx);
    fp_dbg("frame quality: stddev=%d (min=%d)", stddev, QUALITY_STDDEV_MIN);
    if (stddev < QUALITY_STDDEV_MIN)
      {
        fp_dbg("rejecting low-quality frame (stddev %d < %d)", stddev,
               QUALITY_STDDEV_MIN);
        g_object_unref(img);
        g_clear_object(&priv->last_image);
        fpi_ssm_next_state(ssm);
        return;
      }
  }

  g_clear_object(&priv->last_image);
  priv->last_image = img;

  fpi_ssm_next_state(ssm);
}

static void
query_mcu_state_cb(FpDevice *dev, guchar *mcu_state, guint16 len, gpointer ssm,
                   GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed(ssm, error);
      return;
    }
  fpi_ssm_next_state(ssm);
}

static void
scan_get_img(FpDevice *dev, FpiSsm *ssm)
{
  goodix_tls_read_image(dev, scan_on_read_img, ssm);
}

static void
scan_run_state(FpiSsm *ssm, FpDevice *dev)
{
  switch (fpi_ssm_get_cur_state(ssm))
    {
    case SCAN_STAGE_QUERY_MCU:
      goodix_send_query_mcu_state(dev, query_mcu_state_cb, ssm);
      break;
    case SCAN_STAGE_SWITCH_TO_FDT_MODE:
      send_switch_mode(dev, ssm, goodix_send_mcu_switch_to_fdt_mode);
      break;

    case SCAN_STAGE_CALIBRATE:
      do_calibration(dev, ssm);
      break;
    case SCAN_STAGE_SWITCH_TO_FDT_DOWN:
      send_switch_mode(dev, ssm, goodix_send_mcu_switch_to_fdt_down);
      break;

    case SCAN_STAGE_GET_IMG:
      fpi_device_report_finger_status_changes(dev,
                                              FP_FINGER_STATUS_PRESENT,
                                              FP_FINGER_STATUS_NEEDED);
      scan_get_img(dev, ssm);
      break;

    case SCAN_STAGE_SWITCH_TO_FTD_UP:
      {
        FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
        FpiDeviceGoodixTls5xxPrivate *priv =
          fpi_device_goodixtls5xx_get_instance_private (self);

        if (priv->last_scan)
          {
            /* Fire-and-forget: send FDT_UP but don't wait for the
             * ACK/NOTIF. The original FpImageDevice driver's deactivation
             * called goodix_reset_state() before the response arrived,
             * then immediately started re-activation.  Reproduce that
             * sequence so the pcap replay matches. */
            FpiDeviceGoodixTls5xxClass *cls =
              FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);
            GoodixTls5xxMcuConfig cfg = cls->get_mcu_cfg ();
            goodix_send_mcu_switch_to_fdt_up (dev, cfg.data, cfg.data_len,
                                              cfg.free_fn, NULL, NULL);
            goodix_reset_state (dev);
            fpi_ssm_next_state (ssm);
          }
        else
          {
            send_switch_mode (dev, ssm, goodix_send_mcu_switch_to_fdt_up);
          }
        break;
      }

    case SCAN_STAGE_SWITCH_TO_FTD_DONE:
      fpi_device_report_finger_status_changes(dev,
                                              FP_FINGER_STATUS_NONE,
                                              FP_FINGER_STATUS_PRESENT);
      fpi_ssm_next_state(ssm);
      break;
    }
}

void
goodixtls5xx_decode_frame(GoodixTls5xxPix *frame, guint32 frame_size,
                          const guint8 *raw_frame)
{
  GoodixTls5xxPix *pix = frame;

  for (int i = 8; i != frame_size - 5; i += 6)
    {
      const guint8 *chunk = raw_frame + i;
      *pix++ = ((chunk[0] & 0xf) << 8) + chunk[1];
      *pix++ = (chunk[3] << 4) + (chunk[0] >> 4);
      *pix++ = ((chunk[5] & 0xf) << 8) + chunk[2];
      *pix++ = (chunk[4] << 4) + (chunk[5] >> 4);
    }
}

/* ---- Deactivation helper (called at end of enroll/verify) ---- */

static void
deactivate_device (FpDevice *dev)
{
  GError *error = NULL;

  goodix_reset_state (dev);

  goodix_shutdown_tls (dev, &error);
  if (error)
    {
      fp_err ("TLS shutdown error: %s", error->message);
      g_clear_error (&error);
    }

  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);

  /* Do NOT call goodixtls5xx_cleanup here — the SSM done callbacks
   * still need access to enroll_data / last_sigfm_info.  Cleanup is
   * done in the done callbacks after the results have been consumed. */

  if (cls->reset_state)
    cls->reset_state (dev);
}

/* ---- FpDevice open/close ---- */

static void
dev_open (FpDevice *dev)
{
  GError *error = NULL;

  if (!goodix_dev_init (dev, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  fpi_device_open_complete (dev, NULL);
}

static void
dev_close (FpDevice *dev)
{
  GError *error = NULL;

  goodixtls5xx_cleanup (FPI_DEVICE_GOODIXTLS5XX (dev));

  if (!goodix_dev_deinit (dev, &error))
    {
      fpi_device_close_complete (dev, error);
      return;
    }

  fpi_device_close_complete (dev, NULL);
}

/* ---- TLS init callback for SSM ---- */

static void
tls_init_done_cb(FpDevice *dev, gpointer user_data, GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_err("failed to complete tls activation: %s", error->message);
      fpi_ssm_mark_failed(ssm, error);
      return;
    }
  fpi_ssm_next_state(ssm);
}

void
goodixtls5xx_init_tls(FpDevice *dev, FpiSsm *ssm)
{
  goodix_tls_init(dev, tls_init_done_cb, ssm);
}

/* ---- SIGFM vfunc implementations ---- */

#define GOODIX_SIGFM_THRESHOLD    7
#define GOODIX_SIGFM_MIN_KEYPOINTS 25

typedef struct
{
  SigfmImgInfo *sigfm_info;
  guchar       *image_data;
  gint          width;
  gint          height;
} GoodixSigfmExtractData;

static void
goodix_sigfm_extract_data_free (GoodixSigfmExtractData *data)
{
  g_clear_pointer (&data->image_data, g_free);
  g_clear_pointer (&data->sigfm_info, sigfm_free_info);
  g_free (data);
}

static void
goodix_sigfm_extract_thread (GTask        *task,
                             gpointer      source_object,
                             gpointer      task_data,
                             GCancellable *cancellable)
{
  GoodixSigfmExtractData *data = task_data;
  GTimer *timer = g_timer_new ();

  data->sigfm_info = sigfm_extract (data->image_data, data->width, data->height);
  g_timer_stop (timer);
  fp_dbg ("sigfm extract completed in %f secs", g_timer_elapsed (timer, NULL));
  g_timer_destroy (timer);

  if (!data->sigfm_info)
    {
      g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_FAILED,
                               "SIGFM extraction failed");
      return;
    }

  fp_dbg ("sigfm keypoints: %d", sigfm_keypoints_count (data->sigfm_info));

  if (sigfm_keypoints_count (data->sigfm_info) < GOODIX_SIGFM_MIN_KEYPOINTS)
    {
      g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_FAILED,
                               "Not enough keypoints (%d < %d)",
                               sigfm_keypoints_count (data->sigfm_info),
                               GOODIX_SIGFM_MIN_KEYPOINTS);
      return;
    }

  g_task_return_boolean (task, TRUE);
}

static void
goodix_sigfm_extract_done (GObject      *source_object,
                           GAsyncResult *res,
                           gpointer      user_data)
{
  GTask *task = G_TASK (res);
  FpiSsm *ssm = user_data;
  FpDevice *dev = FP_DEVICE (source_object);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (FPI_DEVICE_GOODIXTLS5XX (dev));
  GoodixSigfmExtractData *data = g_task_get_task_data (task);
  GError *error = NULL;

  if (!g_task_propagate_boolean (task, &error))
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_warning ("SIGFM extraction failed: %s", error->message);
          g_clear_error (&error);
          /* Store NULL so the caller knows extraction failed */
          g_clear_pointer (&priv->last_sigfm_info, sigfm_free_info);
        }
      else
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
    }
  else
    {
      g_clear_pointer (&priv->last_sigfm_info, sigfm_free_info);
      priv->last_sigfm_info = g_steal_pointer (&data->sigfm_info);
    }

  fpi_ssm_next_state (ssm);
}

static void
goodix_sigfm_extract (FpDevice *dev, FpImage *image, FpiSsm *ssm)
{
  GTask *task;
  GoodixSigfmExtractData *data;

  data = g_new0 (GoodixSigfmExtractData, 1);
  data->width = image->width;
  data->height = image->height;
  data->image_data = g_memdup2 (image->data, image->width * image->height);

  task = g_task_new (dev,
                     fpi_device_get_cancellable (dev),
                     goodix_sigfm_extract_done,
                     ssm);
  g_task_set_task_data (task, data,
                        (GDestroyNotify) goodix_sigfm_extract_data_free);
  g_task_run_in_thread (task, goodix_sigfm_extract_thread);
  g_object_unref (task);
}

static gboolean
goodix_sigfm_build_print (FpDevice    *dev,
                          FpPrint     *print,
                          GPtrArray   *descriptors,
                          GError     **error)
{
  if (descriptors->len == 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "No SIGFM descriptors collected");
      return FALSE;
    }

  fpi_print_set_type (print, FPI_PRINT_RAW);

  GVariantBuilder builder;
  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aay"));

  for (guint i = 0; i < descriptors->len; i++)
    {
      GBytes *bytes = g_ptr_array_index (descriptors, i);
      g_variant_builder_add_value (&builder,
        g_variant_new_from_bytes (G_VARIANT_TYPE ("ay"), bytes, TRUE));
    }

  GVariant *data = g_variant_builder_end (&builder);
  g_object_set (print, "fpi-data", data, NULL);

  return TRUE;
}

static FpiMatchResult
goodix_sigfm_compare (FpDevice   *dev,
                      FpPrint    *enrolled,
                      FpPrint    *probe,
                      GError    **error)
{
  g_autoptr(GVariant) enrolled_data = NULL;
  g_autoptr(GVariant) probe_data = NULL;
  GVariantIter probe_iter;
  g_autoptr(GVariant) probe_entry = NULL;
  gsize probe_len;
  const guchar *probe_blob;
  SigfmImgInfo *probe_info;
  FpiMatchResult result = FPI_MATCH_FAIL;

  g_object_get (enrolled, "fpi-data", &enrolled_data, NULL);
  g_object_get (probe, "fpi-data", &probe_data, NULL);

  if (!enrolled_data || !probe_data)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                         "Print has no data");
      return FPI_MATCH_ERROR;
    }

  /* The probe should have at least one descriptor */
  g_variant_iter_init (&probe_iter, probe_data);
  probe_entry = g_variant_iter_next_value (&probe_iter);
  if (!probe_entry)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                         "Probe print has no descriptors");
      return FPI_MATCH_ERROR;
    }

  probe_blob = g_variant_get_fixed_array (probe_entry, &probe_len, 1);
  probe_info = sigfm_deserialize_binary (probe_blob, probe_len);
  if (!probe_info)
    {
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                         "Failed to deserialize probe");
      return FPI_MATCH_ERROR;
    }

  /* Check against all enrolled descriptors */
  {
    GVariantIter enrolled_iter;
    GVariant *entry;

    g_variant_iter_init (&enrolled_iter, enrolled_data);
    while ((entry = g_variant_iter_next_value (&enrolled_iter)) != NULL)
      {
        gsize elen;
        const guchar *eblob = g_variant_get_fixed_array (entry, &elen, 1);
        SigfmImgInfo *einfo = sigfm_deserialize_binary (eblob, elen);
        gint score;

        if (!einfo)
          {
            sigfm_free_info (probe_info);
            g_variant_unref (entry);
            *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                               "Failed to deserialize enrolled");
            return FPI_MATCH_ERROR;
          }

        score = sigfm_match_score (einfo, probe_info);
        sigfm_free_info (einfo);

        if (score < 0)
          {
            sigfm_free_info (probe_info);
            g_variant_unref (entry);
            *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                               "Error in sigfm_match_score");
            return FPI_MATCH_ERROR;
          }

        fp_dbg ("sigfm score %d/%d", score, GOODIX_SIGFM_THRESHOLD);
        if (score >= GOODIX_SIGFM_THRESHOLD)
          {
            result = FPI_MATCH_SUCCESS;
            g_variant_unref (entry);
            break;
          }
        g_variant_unref (entry);
      }
  }

  sigfm_free_info (probe_info);
  return result;
}

/* ---- Enroll state machine ---- */

enum enroll_states
{
  ENROLL_ACTIVATE,
  ENROLL_TLS_INIT,
  ENROLL_SCAN,
  ENROLL_EXTRACT,
  ENROLL_COLLECT,
  ENROLL_DEACTIVATE,

  ENROLL_NUM_STATES,
};

static void
enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (self);
  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ENROLL_ACTIVATE:
      cls->activate (dev, ssm);
      break;

    case ENROLL_TLS_INIT:
      goodixtls5xx_init_tls (dev, ssm);
      break;

    case ENROLL_SCAN:
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_NONE);
      g_clear_object (&priv->last_image);
      fpi_ssm_start_subsm (ssm,
                           fpi_ssm_new (dev, scan_run_state, SCAN_STAGE_NUM));
      break;

    case ENROLL_EXTRACT:
      if (!priv->last_image)
        {
          /* Low quality scan — report retry and loop back */
          fpi_device_enroll_progress (dev, priv->enroll_stage, NULL,
            fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          fpi_ssm_jump_to_state (ssm, ENROLL_SCAN);
          break;
        }
      goodix_sigfm_extract (dev, priv->last_image, ssm);
      break;

    case ENROLL_COLLECT:
      {
        if (!priv->last_sigfm_info)
          {
            /* SIGFM extraction failed — report retry and rescan */
            fpi_device_enroll_progress (dev, priv->enroll_stage, NULL,
              fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            fpi_ssm_jump_to_state (ssm, ENROLL_SCAN);
            break;
          }

        /* Serialize and store the SIGFM descriptor */
        int slen;
        unsigned char *blob = sigfm_serialize_binary (priv->last_sigfm_info,
                                                      &slen);
        GBytes *bytes = g_bytes_new_take (blob, slen);
        g_ptr_array_add (priv->enroll_data, bytes);
        priv->enroll_stage++;

        fp_dbg ("enroll stage %d/%d completed",
                priv->enroll_stage, fp_device_get_nr_enroll_stages (dev));

        FpPrint *print = NULL;
        fpi_device_get_enroll_data (dev, &print);
        fpi_device_enroll_progress (dev, priv->enroll_stage, print, NULL);

        if (priv->enroll_stage < fp_device_get_nr_enroll_stages (dev))
          {
            /* Mark the final iteration so the scan SSM can fire-and-forget
             * the FDT_UP command instead of waiting for a response that
             * will never arrive (the device is reset during deactivation
             * before it can reply). */
            if (priv->enroll_stage == fp_device_get_nr_enroll_stages (dev) - 1)
              priv->last_scan = TRUE;
            fpi_ssm_jump_to_state (ssm, ENROLL_SCAN);
          }
        else
          {
            fpi_ssm_next_state (ssm);
          }
        break;
      }

    case ENROLL_DEACTIVATE:
      deactivate_device (dev);
      fpi_ssm_next_state (ssm);
      break;

    }
}

static void
enroll_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (self);

  if (error)
    {
      deactivate_device (dev);
      fpi_device_enroll_complete (dev, NULL, error);
      g_clear_pointer (&priv->enroll_data, g_ptr_array_unref);
      goodixtls5xx_cleanup (self);
      priv->task_ssm = NULL;
      return;
    }

  /* Build the final print from collected descriptors */
  FpPrint *print = NULL;
  fpi_device_get_enroll_data (dev, &print);

  GError *build_err = NULL;
  if (!goodix_sigfm_build_print (dev, print, priv->enroll_data, &build_err))
    {
      fpi_device_enroll_complete (dev, NULL, build_err);
    }
  else
    {
      fp_info ("Enrollment complete with %d descriptors",
               priv->enroll_data->len);
      fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
    }

  g_clear_pointer (&priv->enroll_data, g_ptr_array_unref);
  goodixtls5xx_cleanup (self);
  priv->task_ssm = NULL;
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (self);

  priv->enroll_stage = 0;
  priv->last_scan = FALSE;
  priv->enroll_data =
    g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);

  priv->task_ssm = fpi_ssm_new (dev, enroll_run_state,
                                ENROLL_NUM_STATES);
  fpi_ssm_start (priv->task_ssm, enroll_ssm_done);
}

/* ---- Verify / Identify state machine ---- */

enum verify_states
{
  VERIFY_ACTIVATE,
  VERIFY_TLS_INIT,
  VERIFY_SCAN,
  VERIFY_EXTRACT,
  VERIFY_COMPARE,
  VERIFY_DEACTIVATE,

  VERIFY_NUM_STATES,
};

static void
verify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (self);
  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VERIFY_ACTIVATE:
      cls->activate (dev, ssm);
      break;

    case VERIFY_TLS_INIT:
      goodixtls5xx_init_tls (dev, ssm);
      break;

    case VERIFY_SCAN:
      fpi_device_report_finger_status_changes (dev,
                                               FP_FINGER_STATUS_NEEDED,
                                               FP_FINGER_STATUS_NONE);
      g_clear_object (&priv->last_image);
      fpi_ssm_start_subsm (ssm,
                           fpi_ssm_new (dev, scan_run_state, SCAN_STAGE_NUM));
      break;

    case VERIFY_EXTRACT:
      if (!priv->last_image)
        {
          /* Low quality scan — retry */
          if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
            fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
              fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          else
            fpi_device_identify_report (dev, NULL, NULL,
              fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          fpi_ssm_jump_to_state (ssm, VERIFY_SCAN);
          break;
        }
      goodix_sigfm_extract (dev, priv->last_image, ssm);
      break;

    case VERIFY_COMPARE:
      {
        if (!priv->last_sigfm_info)
          {
            /* SIGFM extraction failed — retry */
            if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
              fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            else
              fpi_device_identify_report (dev, NULL, NULL,
                fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
            fpi_ssm_jump_to_state (ssm, VERIFY_SCAN);
            break;
          }

        /* Build a temporary probe print from the single scan */
        g_autoptr(FpPrint) probe_print = fp_print_new (dev);
        {
          int slen;
          unsigned char *blob =
            sigfm_serialize_binary (priv->last_sigfm_info, &slen);
          g_autoptr(GBytes) bytes = g_bytes_new_take (blob, slen);
          g_autoptr(GPtrArray) probe_data =
            g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
          g_ptr_array_add (probe_data, g_bytes_ref (bytes));

          GError *build_err = NULL;
          if (!goodix_sigfm_build_print (dev, probe_print, probe_data,
                                         &build_err))
            {
              fpi_ssm_mark_failed (ssm, build_err);
              break;
            }
        }

        GError *cmp_err = NULL;

        if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
          {
            FpPrint *enrolled = NULL;
            fpi_device_get_verify_data (dev, &enrolled);

            FpiMatchResult match = goodix_sigfm_compare (dev, enrolled,
                                                         probe_print,
                                                         &cmp_err);
            fpi_device_verify_report (dev, match,
                                     g_steal_pointer (&probe_print), cmp_err);
          }
        else
          {
            /* Identify: check against all enrolled prints */
            GPtrArray *gallery = NULL;
            FpPrint *matching = NULL;
            fpi_device_get_identify_data (dev, &gallery);

            for (guint i = 0; i < gallery->len; i++)
              {
                FpPrint *enrolled = g_ptr_array_index (gallery, i);
                FpiMatchResult match = goodix_sigfm_compare (dev, enrolled,
                                                             probe_print,
                                                             &cmp_err);
                if (cmp_err)
                  break;
                if (match == FPI_MATCH_SUCCESS)
                  {
                    matching = enrolled;
                    break;
                  }
              }

            fpi_device_identify_report (dev, matching,
                                       g_steal_pointer (&probe_print), cmp_err);
          }

        fpi_ssm_next_state (ssm);
        break;
      }

    case VERIFY_DEACTIVATE:
      deactivate_device (dev);
      fpi_ssm_next_state (ssm);
      break;

    }
}

static void
verify_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (self);

  if (error)
    deactivate_device (dev);

  if (error && error->domain == FP_DEVICE_RETRY)
    {
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                                  g_steal_pointer (&error));
      else
        fpi_device_identify_report (dev, NULL, NULL,
                                    g_steal_pointer (&error));
    }

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);

  goodixtls5xx_cleanup (self);
  priv->task_ssm = NULL;
}

static void
dev_verify_identify (FpDevice *dev)
{
  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX (dev);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (self);

  priv->last_scan = FALSE;

  priv->task_ssm = fpi_ssm_new (dev, verify_run_state,
                                VERIFY_NUM_STATES);
  fpi_ssm_start (priv->task_ssm, verify_ssm_done);
}

/* ---- GObject class init ---- */

void
fpi_device_goodixtls5xx_class_init(FpiDeviceGoodixTls5xxClass *self)
{
  self->get_mcu_cfg = NULL;
  self->process_frame = NULL;
  self->scan_height = 0;
  self->scan_width = 0;
  self->reset_state = NULL;
  self->activate = NULL;

  FpDeviceClass *dev_cls = FP_DEVICE_CLASS(self);

  dev_cls->open     = dev_open;
  dev_cls->close    = dev_close;
  dev_cls->enroll   = dev_enroll;
  dev_cls->verify   = dev_verify_identify;
  dev_cls->identify = dev_verify_identify;
}

void
fpi_device_goodixtls5xx_init(FpiDeviceGoodixTls5xx *self)
{
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(self);
  priv->calibration_img = NULL;
  priv->last_sigfm_info = NULL;
  priv->last_image = NULL;
  priv->enroll_stage = 0;
  priv->enroll_data = NULL;
  priv->task_ssm = NULL;
}

void
goodixtls5xx_cleanup(FpiDeviceGoodixTls5xx *dev)
{
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(dev);
  g_free(priv->calibration_img);
  priv->calibration_img = NULL;
  g_clear_pointer(&priv->last_sigfm_info, sigfm_free_info);
  g_clear_object(&priv->last_image);
  g_clear_pointer(&priv->enroll_data, g_ptr_array_unref);
}
