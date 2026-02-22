// SIGFM algorithm for libfprint — pure-C ORB replacement
//
// Copyright (C) 2022 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (c) 2022 Natasha England-Elbro <ashenglandelbro@protonmail.com>
// Copyright (c) 2022 Timur Mangliev <tigrmango@gmail.com>
// Copyright (c) 2026 libfprint contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Algorithm: FAST-9 corner detection + unsteered BRIEF-256 descriptors.
// Fingerprint images from the GF511 sensor are presented in a consistent
// orientation (press sensor), so orientation-steered descriptors are not
// needed.  The matching and geometric-consistency scorer are identical to
// the original OpenCV SIFT-based implementation.

#include "sigfm.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Data structures
 * ---------------------------------------------------------------------- */

typedef struct
{
  float x, y;
  float response;
} OrbKeypoint;

struct SigfmImgInfo
{
  int n_kp;
  OrbKeypoint *kp;
  uint8_t *desc; /* n_kp × 32 bytes, 256-bit BRIEF descriptor per kp */
};

/* -------------------------------------------------------------------------
 * BRIEF-256 bit-test pattern
 * Pairs (x1,y1,x2,y2) in range ±PATCH_HALF, lazily initialised once.
 * -------------------------------------------------------------------- */

#define PATCH_HALF 7
#define PATCH_SIZE (PATCH_HALF * 2 + 1) /* 15 */
#define N_PAIRS 256
#define DESC_BYTES 32 /* 256 / 8 */

static int8_t brief_pattern[N_PAIRS][4];
static int brief_inited = 0;

static void
init_brief_pattern(void)
{
  if (brief_inited)
    return;

  /* Deterministic hash-based pairs; covers all four quadrants of the patch. */
  for (int i = 0; i < N_PAIRS; i++)
    {
      unsigned int s1 = (unsigned int)(i * 7741u + 1234567u);
      unsigned int s2 = (unsigned int)(i * 3571u + 9876543u);
      int r1 = (int)(s1 % (unsigned)(PATCH_SIZE * PATCH_SIZE));
      int r2 = (int)(s2 % (unsigned)(PATCH_SIZE * PATCH_SIZE));
      brief_pattern[i][0] = (int8_t)(r1 % PATCH_SIZE - PATCH_HALF); /* x1 */
      brief_pattern[i][1] = (int8_t)(r1 / PATCH_SIZE - PATCH_HALF); /* y1 */
      brief_pattern[i][2] = (int8_t)(r2 % PATCH_SIZE - PATCH_HALF); /* x2 */
      brief_pattern[i][3] = (int8_t)(r2 / PATCH_SIZE - PATCH_HALF); /* y2 */
    }
  brief_inited = 1;
}

/* -------------------------------------------------------------------------
 * 3×3 box blur (scratch buffer passed in to avoid allocation per-keypoint)
 * ---------------------------------------------------------------------- */

static void
box3_blur(const uint8_t *src, uint8_t *dst, int w, int h)
{
  for (int y = 0; y < h; y++)
    {
      for (int x = 0; x < w; x++)
        {
          int sum = 0, cnt = 0;
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
                  sum += src[ny * w + nx];
                  cnt++;
                }
            }
          dst[y * w + x] = (uint8_t)(sum / cnt);
        }
    }
}

/* -------------------------------------------------------------------------
 * FAST-9 corner detector
 * ---------------------------------------------------------------------- */

/* Bresenham circle radius-3 offsets (16 points) */
static const int fast_dx[16] = { 0, 1, 2, 3, 3, 3, 2, 1, 0, -1, -2, -3, -3, -3, -2, -1 };
static const int fast_dy[16] = { 3, 3, 2, 1, 0, -1, -2, -3, -3, -3, -2, -1, 0, 1, 2, 3 };

/* Returns a score > 0 if (x,y) is a FAST-9 corner, 0 otherwise. */
static int
fast9_score(const uint8_t *img, int w, int x, int y, int threshold)
{
  int cx = img[y * w + x];
  int v[16];

  for (int i = 0; i < 16; i++)
    v[i] = img[(y + fast_dy[i]) * w + (x + fast_dx[i])] - cx;

  /* Compass quick-reject: need at least 2 of the 4 cardinal points
   * to exceed the threshold in the same direction. */
  int nb = 0, nd = 0;
  for (int i = 0; i < 4; i++)
    {
      if (v[i * 4] > threshold)
        nb++;
      if (v[i * 4] < -threshold)
        nd++;
    }
  if (nb < 2 && nd < 2)
    return 0;

  /* Full test: look for 9 consecutive pixels all brighter or darker. */
  for (int start = 0; start < 16; start++)
    {
      int b = 1, d = 1;
      for (int k = 0; k < 9; k++)
        {
          int val = v[(start + k) % 16];
          if (val <= threshold)
            b = 0;
          if (val >= -threshold)
            d = 0;
        }
      if (!b && !d)
        continue;

      /* Score = sum of absolute deviations (higher → stronger corner). */
      int score = 0;
      for (int i = 0; i < 16; i++)
        score += abs(v[i]);
      return score;
    }
  return 0;
}

/* -------------------------------------------------------------------------
 * Detect keypoints: FAST-9 + 3×3 non-maximum suppression
 * ---------------------------------------------------------------------- */

#define FAST_THRESHOLD 10
#define FAST_BORDER (3 + PATCH_HALF) /* avoid circle + patch OOB */
#define MAX_KP 128

static int
detect_keypoints(const uint8_t *img, int w, int h, OrbKeypoint *kp_out, int max_kp)
{
  /* Score map: 0 = not a corner */
  int *scores = calloc((size_t)(w * h), sizeof(int));
  if (!scores)
    return 0;

  /* Pass 1: compute FAST scores */
  for (int y = FAST_BORDER; y < h - FAST_BORDER; y++)
    {
      for (int x = FAST_BORDER; x < w - FAST_BORDER; x++)
        scores[y * w + x] = fast9_score(img, w, x, y, FAST_THRESHOLD);
    }

  /* Pass 2: 3×3 NMS — keep only local maxima */
  int n = 0;
  for (int y = FAST_BORDER; y < h - FAST_BORDER && n < max_kp; y++)
    {
      for (int x = FAST_BORDER; x < w - FAST_BORDER && n < max_kp; x++)
        {
          int s = scores[y * w + x];
          if (s == 0)
            continue;
          int is_max = 1;
          for (int dy = -1; dy <= 1 && is_max; dy++)
            for (int dx = -1; dx <= 1 && is_max; dx++)
              if (!(dx == 0 && dy == 0) && scores[(y + dy) * w + (x + dx)] > s)
                is_max = 0;
          if (is_max)
            {
              kp_out[n].x = (float)x;
              kp_out[n].y = (float)y;
              kp_out[n].response = (float)s;
              n++;
            }
        }
    }

  free(scores);
  return n;
}

/* -------------------------------------------------------------------------
 * BRIEF-256 descriptor computation (no orientation steering)
 * ---------------------------------------------------------------------- */

static void
compute_descriptor(const uint8_t *img, int w, const OrbKeypoint *kp,
                   uint8_t *desc /* 32 bytes out */)
{
  int cx = (int)kp->x;
  int cy = (int)kp->y;

  memset(desc, 0, DESC_BYTES);
  for (int i = 0; i < N_PAIRS; i++)
    {
      int x1 = cx + brief_pattern[i][0];
      int y1 = cy + brief_pattern[i][1];
      int x2 = cx + brief_pattern[i][2];
      int y2 = cy + brief_pattern[i][3];
      if (img[y1 * w + x1] < img[y2 * w + x2])
        desc[i / 8] |= (uint8_t)(1u << (i % 8));
    }
}

/* -------------------------------------------------------------------------
 * Hamming distance between two 32-byte descriptors
 * ---------------------------------------------------------------------- */

static int
hamming_dist(const uint8_t *a, const uint8_t *b)
{
  int dist = 0;
  for (int i = 0; i < DESC_BYTES; i++)
    {
      uint8_t x = a[i] ^ b[i];
      /* Brian Kernighan bit-count */
      while (x)
        {
          dist++;
          x &= (uint8_t)(x - 1u);
        }
    }
  return dist;
}

/* -------------------------------------------------------------------------
 * KNN matching (k=2) with Lowe ratio test
 * ---------------------------------------------------------------------- */

#define RATIO_TEST 0.90f
#define MIN_MATCH 5

typedef struct
{
  int qi, ti;
  int dist;
} Match;

static int
knn_match(const SigfmImgInfo *query, const SigfmImgInfo *train, Match *matches_out,
          int max_matches)
{
  int n = 0;
  for (int q = 0; q < query->n_kp && n < max_matches; q++)
    {
      const uint8_t *qd = query->desc + q * DESC_BYTES;
      int best1 = 256, best2 = 256, best1_idx = -1;

      for (int t = 0; t < train->n_kp; t++)
        {
          int d = hamming_dist(qd, train->desc + t * DESC_BYTES);
          if (d < best1)
            {
              best2 = best1;
              best1 = d;
              best1_idx = t;
            }
          else if (d < best2)
            {
              best2 = d;
            }
        }

      if (best1_idx >= 0 && best2 > 0 && (float)best1 < RATIO_TEST * (float)best2)
        {
          matches_out[n].qi = q;
          matches_out[n].ti = best1_idx;
          matches_out[n].dist = best1;
          n++;
        }
    }
  return n;
}

/* -------------------------------------------------------------------------
 * Geometric consistency scorer — identical algorithm to sigfm.cpp
 * ---------------------------------------------------------------------- */

#define LENGTH_MATCH 0.05f
#define ANGLE_MATCH 0.05f

typedef struct
{
  float p1x, p1y, p2x, p2y;
} MatchPair;
typedef struct
{
  double cos_v, sin_v;
} AngleEntry;

static int
geometric_score(const SigfmImgInfo *frame, const SigfmImgInfo *enrolled,
                const Match *matches, int n_matches)
{
  if (n_matches < MIN_MATCH)
    return 0;

  /* Build point-pair list (de-duplicate by rounding to integer coords) */
  MatchPair *mp = malloc((size_t)n_matches * sizeof(MatchPair));
  if (!mp)
    return 0;

  int nm = 0;
  for (int i = 0; i < n_matches; i++)
    {
      MatchPair p = { frame->kp[matches[i].qi].x, frame->kp[matches[i].qi].y,
                      enrolled->kp[matches[i].ti].x, enrolled->kp[matches[i].ti].y };
      /* Simple de-duplicate: skip if same integer coords as an earlier entry */
      int dup = 0;
      for (int j = 0; j < nm && !dup; j++)
        if ((int)mp[j].p1x == (int)p.p1x && (int)mp[j].p1y == (int)p.p1y)
          dup = 1;
      if (!dup)
        mp[nm++] = p;
    }

  if (nm < MIN_MATCH)
    {
      free(mp);
      return 0;
    }

  /* Build angle table: for each pair of match-pairs, record relative angle */
  int max_angles = nm * nm;
  AngleEntry *angles = malloc((size_t)max_angles * sizeof(AngleEntry));
  if (!angles)
    {
      free(mp);
      return 0;
    }
  int na = 0;

  for (int j = 0; j < nm; j++)
    {
      for (int k = j + 1; k < nm; k++)
        {
          float v1x = mp[j].p1x - mp[k].p1x;
          float v1y = mp[j].p1y - mp[k].p1y;
          float v2x = mp[j].p2x - mp[k].p2x;
          float v2y = mp[j].p2y - mp[k].p2y;

          double len1 = sqrt((double)(v1x * v1x + v1y * v1y));
          double len2 = sqrt((double)(v2x * v2x + v2y * v2y));

          if (len1 < 1e-6 || len2 < 1e-6)
            continue;

          double lmin = len1 < len2 ? len1 : len2;
          double lmax = len1 > len2 ? len1 : len2;
          if (1.0 - lmin / lmax > (double)LENGTH_MATCH)
            continue;

          double product = len1 * len2;
          double dot = (double)(v1x * v2x + v1y * v2y);
          double cross = (double)(v1x * v2y - v1y * v2x);

          double arg_sin = dot / product;
          double arg_cos = cross / product;

          /* Clamp to [-1,1] to guard against float rounding */
          if (arg_sin > 1.0)
            arg_sin = 1.0;
          if (arg_sin < -1.0)
            arg_sin = -1.0;
          if (arg_cos > 1.0)
            arg_cos = 1.0;
          if (arg_cos < -1.0)
            arg_cos = -1.0;

          angles[na].sin_v = asin(arg_sin);
          angles[na].cos_v = acos(arg_cos);
          na++;
        }
    }

  free(mp);

  if (na < MIN_MATCH)
    {
      free(angles);
      return 0;
    }

  /* Count angle-pairs that agree within ANGLE_MATCH */
  int count = 0;
  for (int j = 0; j < na; j++)
    {
      for (int k = j + 1; k < na; k++)
        {
          double s1 = angles[j].sin_v, s2 = angles[k].sin_v;
          double c1 = angles[j].cos_v, c2 = angles[k].cos_v;
          double smin = s1 < s2 ? s1 : s2, smax = s1 > s2 ? s1 : s2;
          double cmin = c1 < c2 ? c1 : c2, cmax = c1 > c2 ? c1 : c2;

          if (smax > 1e-9 && cmax > 1e-9 && 1.0 - smin / smax <= (double)ANGLE_MATCH
              && 1.0 - cmin / cmax <= (double)ANGLE_MATCH)
            count++;
        }
    }

  free(angles);
  return count;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

SigfmImgInfo *
sigfm_extract(const SigfmPix *pix, int width, int height)
{
  init_brief_pattern();

  /* Blur for stable keypoint detection, but compute descriptors on the
   * original (unblurred) image to preserve discriminative pixel detail. */
  uint8_t *blurred = malloc((size_t)(width * height));
  if (!blurred)
    return NULL;
  box3_blur(pix, blurred, width, height);

  OrbKeypoint raw_kp[MAX_KP];
  int n = detect_keypoints(blurred, width, height, raw_kp, MAX_KP);

  free(blurred);

  if (n == 0)
    return NULL;

  SigfmImgInfo *info = malloc(sizeof(SigfmImgInfo));
  if (!info)
    return NULL;

  info->n_kp = n;
  info->kp = malloc((size_t)n * sizeof(OrbKeypoint));
  info->desc = malloc((size_t)n * DESC_BYTES);

  if (!info->kp || !info->desc)
    {
      free(info->kp);
      free(info->desc);
      free(info);
      return NULL;
    }

  memcpy(info->kp, raw_kp, (size_t)n * sizeof(OrbKeypoint));

  /* Compute BRIEF descriptors on original image — the driver's unsharp
   * mask has already enhanced ridge contrast; re-blurring would undo it. */
  for (int i = 0; i < n; i++)
    compute_descriptor(pix, width, &info->kp[i], info->desc + i * DESC_BYTES);

  return info;
}

int
sigfm_match_score(SigfmImgInfo *frame, SigfmImgInfo *enrolled)
{
  if (!frame || !enrolled || frame->n_kp == 0 || enrolled->n_kp == 0)
    return 0;

  int max_m = frame->n_kp;
  Match *matches = malloc((size_t)max_m * sizeof(Match));
  if (!matches)
    return -1;

  int n = knn_match(frame, enrolled, matches, max_m);
  if (n < MIN_MATCH)
    {
      free(matches);
      return 0;
    }

  int score = geometric_score(frame, enrolled, matches, n);
  free(matches);
  return score;
}

void
sigfm_free_info(SigfmImgInfo *info)
{
  if (!info)
    return;
  free(info->kp);
  free(info->desc);
  free(info);
}

SigfmImgInfo *
sigfm_copy_info(SigfmImgInfo *info)
{
  if (!info)
    return NULL;

  SigfmImgInfo *copy = malloc(sizeof(SigfmImgInfo));
  if (!copy)
    return NULL;

  copy->n_kp = info->n_kp;
  copy->kp = malloc((size_t)info->n_kp * sizeof(OrbKeypoint));
  copy->desc = malloc((size_t)info->n_kp * DESC_BYTES);

  if (!copy->kp || !copy->desc)
    {
      free(copy->kp);
      free(copy->desc);
      free(copy);
      return NULL;
    }

  memcpy(copy->kp, info->kp, (size_t)info->n_kp * sizeof(OrbKeypoint));
  memcpy(copy->desc, info->desc, (size_t)info->n_kp * DESC_BYTES);
  return copy;
}

int
sigfm_keypoints_count(SigfmImgInfo *info)
{
  return info ? info->n_kp : 0;
}

/* -------------------------------------------------------------------------
 * Binary serialisation
 *
 * Format (little-endian):
 *   [4]  magic  0x4D474653  ("SIGM")
 *   [4]  version = 2  (1 was the C++ binary format)
 *   [4]  n_kp
 *   [n_kp * 12]  keypoints: float x, float y, float response
 *   [n_kp * 32]  descriptors
 * ---------------------------------------------------------------------- */

#define SIGFM_MAGIC 0x4D474653u
#define SIGFM_VERSION 2u

static void
write_u32_le(uint8_t *p, uint32_t v)
{
  p[0] = (uint8_t)(v & 0xffu);
  p[1] = (uint8_t)((v >> 8) & 0xffu);
  p[2] = (uint8_t)((v >> 16) & 0xffu);
  p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static uint32_t
read_u32_le(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

unsigned char *
sigfm_serialize_binary(SigfmImgInfo *info, int *outlen)
{
  if (!info)
    return NULL;

  int kp_bytes = info->n_kp * (int)(3 * sizeof(float));
  int desc_bytes = info->n_kp * DESC_BYTES;
  int total = 12 + kp_bytes + desc_bytes; /* 3 × u32 header */

  uint8_t *buf = malloc((size_t)total);
  if (!buf)
    return NULL;

  write_u32_le(buf + 0, SIGFM_MAGIC);
  write_u32_le(buf + 4, SIGFM_VERSION);
  write_u32_le(buf + 8, (uint32_t)info->n_kp);

  uint8_t *p = buf + 12;
  for (int i = 0; i < info->n_kp; i++)
    {
      memcpy(p, &info->kp[i].x, sizeof(float));
      p += sizeof(float);
      memcpy(p, &info->kp[i].y, sizeof(float));
      p += sizeof(float);
      memcpy(p, &info->kp[i].response, sizeof(float));
      p += sizeof(float);
    }
  memcpy(p, info->desc, (size_t)desc_bytes);

  *outlen = total;
  return buf;
}

SigfmImgInfo *
sigfm_deserialize_binary(const unsigned char *bytes, int len)
{
  if (!bytes || len < 12)
    return NULL;

  if (read_u32_le(bytes) != SIGFM_MAGIC || read_u32_le(bytes + 4) != SIGFM_VERSION)
    return NULL;

  int n_kp = (int)read_u32_le(bytes + 8);
  if (n_kp <= 0 || n_kp > MAX_KP)
    return NULL;

  int kp_bytes = n_kp * (int)(3 * sizeof(float));
  int desc_bytes = n_kp * DESC_BYTES;
  if (len < 12 + kp_bytes + desc_bytes)
    return NULL;

  SigfmImgInfo *info = malloc(sizeof(SigfmImgInfo));
  if (!info)
    return NULL;

  info->n_kp = n_kp;
  info->kp = malloc((size_t)n_kp * sizeof(OrbKeypoint));
  info->desc = malloc((size_t)desc_bytes);

  if (!info->kp || !info->desc)
    {
      free(info->kp);
      free(info->desc);
      free(info);
      return NULL;
    }

  const uint8_t *p = bytes + 12;
  for (int i = 0; i < n_kp; i++)
    {
      memcpy(&info->kp[i].x, p, sizeof(float));
      p += sizeof(float);
      memcpy(&info->kp[i].y, p, sizeof(float));
      p += sizeof(float);
      memcpy(&info->kp[i].response, p, sizeof(float));
      p += sizeof(float);
    }
  memcpy(info->desc, p, (size_t)desc_bytes);

  return info;
}
