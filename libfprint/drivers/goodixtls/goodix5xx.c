// Goodix Tls driver for libfprint

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <ashenglandelbro@protonmail.com>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
//
#include "fp-image-device.h"
#include "fpi-image-device.h"
#include "fpi-print.h"
#include "fpi-ssm.h"
#include "sigfm/sigfm.h"
#define FP_COMPONENT "goodixtls5xx"

#include "drivers/goodixtls/goodix5xx.h"
#include "drivers_api.h"
#include "goodix.h"
#include <math.h>
#include <stdio.h>

typedef struct
{
  guint8 *otp; // TODO: Remove
  GoodixTls5xxPix *calibration_img;
  SigfmImgInfo    *last_sigfm_info;
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
          = calloc(cls->scan_height * cls->scan_width, sizeof(GoodixTls5xxPix));
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

void
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

  FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);

  FpiDeviceGoodixTls5xx *self = FPI_DEVICE_GOODIXTLS5XX(dev);
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(self);
  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(dev);

  GoodixTls5xxPix *raw_frame
      = calloc(cls->scan_width * cls->scan_height, sizeof(GoodixTls5xxPix));
  goodixtls5xx_decode_frame(raw_frame, len, data);
  linear_subtract_inplace(raw_frame, priv->calibration_img,
                          cls->scan_width * cls->scan_height);

  /* Raw frame dump for offline A/B testing (env-gated, zero cost when unset).
   * Usage: FP_SAVE_RAW=/path/to/dir ./img-capture finger.pgm
   * Produces: calibration.bin (once) + raw_NNNN.bin per capture.
   * Each file is scan_width × scan_height × sizeof(uint16) bytes. */
  const char *save_dir = g_getenv("FP_SAVE_RAW");
  if (save_dir)
    {
      int npix = cls->scan_width * cls->scan_height;
      char path[256];

      /* Save calibration frame once */
      g_snprintf(path, sizeof(path), "%s/calibration.bin", save_dir);
      if (!g_file_test(path, G_FILE_TEST_EXISTS))
        {
          FILE *cf = fopen(path, "wb");
          if (cf)
            {
              fwrite(priv->calibration_img, sizeof(GoodixTls5xxPix), npix, cf);
              fclose(cf);
              fp_dbg("saved calibration frame to %s (%d pixels)", path, npix);
            }
        }

      /* Pick next sequence number: start from the static high-water mark
       * (fast in single-process loops), then scan forward if files from a
       * previous run already exist (correct across restarts). */
      static int seq_hwm = 0;
      int seq = seq_hwm;
      for (;;)
        {
          g_snprintf(path, sizeof(path), "%s/raw_%04d.bin", save_dir, seq);
          if (!g_file_test(path, G_FILE_TEST_EXISTS))
            break;
          seq++;
        }
      seq_hwm = seq + 1;

      /* Save raw frame (post-decode, post-cal-subtract, pre-stretch/unsharp) */
      FILE *rf = fopen(path, "wb");
      if (rf)
        {
          fwrite(raw_frame, sizeof(GoodixTls5xxPix), npix, rf);
          fclose(rf);
          fp_dbg("saved raw frame to %s (%d pixels)", path, npix);
        }
    }

  guint8 *squashed = calloc(cls->scan_height * cls->scan_width, 1);
  goodixtls5xx_squash_frame_percentile(raw_frame, squashed,
                                       cls->scan_height * cls->scan_width);
  free(raw_frame);
  goodixtls5xx_unsharp_mask_inplace(squashed, cls->scan_width, cls->scan_height);
  FpImage *img = cls->process_frame(squashed);
  free(squashed);

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
        fpi_image_device_retry_scan(img_dev, FP_DEVICE_RETRY_CENTER_FINGER);
        fpi_ssm_next_state(ssm);
        return;
      }
  }

  fpi_image_device_image_captured(img_dev, img);

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
  FpImageDevice *img_dev = FP_IMAGE_DEVICE(dev);

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
      fpi_image_device_report_finger_status(img_dev, TRUE);
      scan_get_img(dev, ssm);
      break;

    case SCAN_STAGE_SWITCH_TO_FTD_UP:
      send_switch_mode(dev, ssm, goodix_send_mcu_switch_to_fdt_up);
      break;

    case SCAN_STAGE_SWITCH_TO_FTD_DONE:
      fpi_image_device_report_finger_status(img_dev, FALSE);
      fpi_ssm_next_state(ssm);
      break;
    }
}

static void
scan_complete(FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      fp_err("failed to scan: %s (code: %d)", error->message, error->code);
      fpi_image_device_session_error(FP_IMAGE_DEVICE(dev), error);
      return;
    }
  fp_dbg("finished scan");
}

void
goodixtls5xx_scan_start(FpiDeviceGoodixTls5xx *dev)
{
  fpi_ssm_start(fpi_ssm_new(FP_DEVICE(dev), scan_run_state, SCAN_STAGE_NUM),
                scan_complete);
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

gboolean
goodixtls5xx_save_image_to_pgm(FpImage *img, const char *path)
{
  FILE *fd = fopen(path, "w");
  size_t write_size;
  const guchar *data = fp_image_get_data(img, &write_size);
  int r;

  if (!fd)
    {
      g_warning("could not open '%s' for writing: %d", path, errno);
      return FALSE;
    }

  r = fprintf(fd, "P5 %d %d 255\n", fp_image_get_width(img), fp_image_get_height(img));
  if (r < 0)
    {
      fclose(fd);
      g_critical("pgm header write failed, error %d", r);
      return FALSE;
    }

  r = fwrite(data, 1, write_size, fd);
  if (r < write_size)
    {
      fclose(fd);
      g_critical("short write (%d)", r);
      return FALSE;
    }

  fclose(fd);
  g_debug("written to '%s'", path);

  return TRUE;
}

static void
dev_change_state(FpImageDevice *img_dev, FpiImageDeviceState state)
{
  if (state == FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    goodixtls5xx_scan_start(FPI_DEVICE_GOODIXTLS5XX(img_dev));
}
static void
dev_deinit(FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE(img_dev);
  GError *error = NULL;

  if (goodix_dev_deinit(dev, &error))
    {
      fpi_image_device_close_complete(img_dev, error);
      return;
    }

  fpi_image_device_close_complete(img_dev, NULL);
}
static void
dev_init(FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE(img_dev);
  GError *error = NULL;

  if (goodix_dev_init(dev, &error))
    {
      fpi_image_device_open_complete(img_dev, error);
      return;
    }

  fpi_image_device_open_complete(img_dev, NULL);
}

static void
dev_deactivate(FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE(img_dev);

  goodix_reset_state(dev);
  GError *error = NULL;

  goodix_shutdown_tls(dev, &error);

  FpiDeviceGoodixTls5xxClass *cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS(dev);
  goodixtls5xx_cleanup(FPI_DEVICE_GOODIXTLS5XX(dev));

  if (cls->reset_state)
    cls->reset_state(dev);
  fpi_image_device_deactivate_complete(img_dev, error);
}

static void
tls_activation_complete(FpDevice *dev, gpointer user_data, GError *error)
{
  if (error)
    {
      fp_err("failed to complete tls activation: %s", error->message);
      return;
    }
  FpImageDevice *image_dev = FP_IMAGE_DEVICE(dev);

  fpi_image_device_activate_complete(image_dev, error);
}

void
goodixtls5xx_init_tls(FpDevice *dev)
{
  goodix_tls_init(dev, tls_activation_complete, NULL);
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
  FpImageDevice *self = FP_IMAGE_DEVICE (user_data);
  FpImage *image = FP_IMAGE (source_object);
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (FPI_DEVICE_GOODIXTLS5XX (self));
  GoodixSigfmExtractData *data = g_task_get_task_data (task);
  GError *error = NULL;

  if (!g_task_propagate_boolean (task, &error))
    {
      if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_warning ("SIGFM extraction failed: %s", error->message);
          g_clear_pointer (&error, g_error_free);
          error = fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                            "SIGFM extraction failed, please retry");
        }
    }
  else
    {
      g_clear_pointer (&priv->last_sigfm_info, sigfm_free_info);
      priv->last_sigfm_info = g_steal_pointer (&data->sigfm_info);
    }

  fpi_image_device_extract_complete (self, g_object_ref (image), error);
}

void
goodix_sigfm_extract (FpImageDevice *self, FpImage *image)
{
  GTask *task;
  GoodixSigfmExtractData *data;

  data = g_new0 (GoodixSigfmExtractData, 1);
  data->width = image->width;
  data->height = image->height;
  data->image_data = g_memdup2 (image->data, image->width * image->height);

  task = g_task_new (image,
                     fpi_device_get_cancellable (FP_DEVICE (self)),
                     goodix_sigfm_extract_done,
                     self);
  g_task_set_task_data (task, data,
                        (GDestroyNotify) goodix_sigfm_extract_data_free);
  g_task_run_in_thread (task, goodix_sigfm_extract_thread);
  g_object_unref (task);
}

gboolean
goodix_sigfm_build_print (FpImageDevice  *self,
                          FpPrint        *print,
                          FpImage        *image,
                          GError        **error)
{
  FpiDeviceGoodixTls5xxPrivate *priv =
    fpi_device_goodixtls5xx_get_instance_private (FPI_DEVICE_GOODIXTLS5XX (self));

  if (!priv->last_sigfm_info)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "No SIGFM data available");
      return FALSE;
    }

  fpi_print_set_type (print, FPI_PRINT_SIGFM);
  fpi_print_add_sigfm_data (print, priv->last_sigfm_info);

  return TRUE;
}

FpiMatchResult
goodix_sigfm_compare (FpImageDevice *self,
                      FpPrint       *enrolled,
                      FpPrint       *probe,
                      GError       **error)
{
  return fpi_print_sigfm_match (enrolled, probe, GOODIX_SIGFM_THRESHOLD, error);
}

/* ---- End SIGFM vfunc implementations ---- */

void
fpi_device_goodixtls5xx_class_init(FpiDeviceGoodixTls5xxClass *self)
{
  self->get_mcu_cfg = NULL;
  self->process_frame = NULL;
  self->scan_height = 0;
  self->scan_width = 0;
  self->reset_state = NULL;

  FpImageDeviceClass *img_cls = FP_IMAGE_DEVICE_CLASS(self);

  img_cls->change_state = dev_change_state;
  img_cls->deactivate = dev_deactivate;
  img_cls->img_close = dev_deinit;
  img_cls->img_open = dev_init;
}

void
fpi_device_goodixtls5xx_init(FpiDeviceGoodixTls5xx *self)
{
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(self);
  priv->calibration_img = NULL;
  priv->otp = NULL;
  priv->last_sigfm_info = NULL;
}

void
goodixtls5xx_cleanup(FpiDeviceGoodixTls5xx *dev)
{
  FpiDeviceGoodixTls5xxPrivate *priv = fpi_device_goodixtls5xx_get_instance_private(dev);
  g_free(priv->calibration_img);
  priv->calibration_img = NULL;
  g_clear_pointer(&priv->last_sigfm_info, sigfm_free_info);
}