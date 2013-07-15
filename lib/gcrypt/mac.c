/*
 * Copyright (C) 2008-2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* This file provides is the backend hash/mac API for libgcrypt.
 */

#include <gnutls_int.h>
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>
#include <gcrypt.h>

static int
wrap_gcry_mac_exists (gnutls_mac_algorithm_t algo)
{
  switch (algo)
    {
    case GNUTLS_MAC_MD5:
    case GNUTLS_MAC_SHA1:
    case GNUTLS_MAC_RMD160:
    case GNUTLS_MAC_MD2:
    case GNUTLS_MAC_SHA224:
    case GNUTLS_MAC_SHA256:
    case GNUTLS_MAC_SHA384:
    case GNUTLS_MAC_SHA512:
      return 1;
    default:
      return 0;
    }
}

static int
wrap_gcry_mac_init (gnutls_mac_algorithm_t algo, void **ctx)
{
  int err;
  unsigned int flags = GCRY_MD_FLAG_HMAC;

  switch (algo)
    {
    case GNUTLS_MAC_MD5:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_MD5, flags);
      break;
    case GNUTLS_MAC_SHA1:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA1, flags);
      break;
    case GNUTLS_MAC_RMD160:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_RMD160, flags);
      break;
    case GNUTLS_MAC_MD2:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_MD2, flags);
      break;
    case GNUTLS_MAC_SHA224:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA224, flags);
      break;
    case GNUTLS_MAC_SHA256:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA256, flags);
      break;
    case GNUTLS_MAC_SHA384:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA384, flags);
      break;
    case GNUTLS_MAC_SHA512:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA512, flags);
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (err == 0)
    return 0;

  gnutls_assert ();
  return GNUTLS_E_ENCRYPTION_FAILED;
}

static int
wrap_gcry_md_setkey (void *ctx, const void *key, size_t keylen)
{
  return gcry_md_setkey ((gcry_md_hd_t) ctx, key, keylen);
}

static int
wrap_gcry_md_write (void *ctx, const void *text, size_t textsize)
{
  gcry_md_write (ctx, text, textsize);
  return GNUTLS_E_SUCCESS;
}

static void
wrap_gcry_md_close (void *hd)
{
  gcry_md_close (hd);
}

static int
wrap_gcry_hash_exists (gnutls_digest_algorithm_t algo)
{
  switch (algo)
    {
    case GNUTLS_DIG_MD5:
    case GNUTLS_DIG_SHA1:
    case GNUTLS_DIG_RMD160:
    case GNUTLS_DIG_MD2:
    case GNUTLS_DIG_SHA224:
    case GNUTLS_DIG_SHA256:
    case GNUTLS_DIG_SHA384:
    case GNUTLS_DIG_SHA512:
      return 1;
    default:
      return 0;
    }
}

static int
wrap_gcry_hash_init (gnutls_digest_algorithm_t algo, void **ctx)
{
  int err;
  unsigned int flags = 0;

  switch (algo)
    {
    case GNUTLS_DIG_MD5:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_MD5, flags);
      break;
    case GNUTLS_DIG_SHA1:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA1, flags);
      break;
    case GNUTLS_DIG_RMD160:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_RMD160, flags);
      break;
    case GNUTLS_DIG_MD2:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_MD2, flags);
      break;
    case GNUTLS_DIG_SHA256:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA256, flags);
      break;
    case GNUTLS_DIG_SHA224:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA224, flags);
      break;
    case GNUTLS_DIG_SHA384:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA384, flags);
      break;
    case GNUTLS_DIG_SHA512:
      err = gcry_md_open ((gcry_md_hd_t *) ctx, GCRY_MD_SHA512, flags);
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (err == 0)
    return 0;

  gnutls_assert ();
  return GNUTLS_E_ENCRYPTION_FAILED;
}

static int
wrap_gcry_mac_output (void *src_ctx, void *digest, size_t digestsize)
{
  unsigned char *_digest = gcry_md_read (src_ctx, 0);

  if (_digest != NULL)
    {
      unsigned int len = gcry_md_get_algo_dlen (gcry_md_get_algo (src_ctx));

      if (len <= digestsize && digest != NULL)
        memcpy (digest, _digest, len);

      return 0;
    }

  gnutls_assert ();
  return GNUTLS_E_HASH_FAILED;
}

static int wrap_gcry_mac_fast(gnutls_mac_algorithm_t algo,
  const void* nonce, size_t nonce_size,
  const void *key, size_t key_size,
  const void* text, size_t text_size,
  void* digest)
{
  gcry_md_hd_t ctx;
  int ret;
  unsigned char *_digest;
  unsigned int len;

  ret = wrap_gcry_mac_init (algo, (void **)&ctx);
  if (ret < 0)
    return gnutls_assert_val(ret);
  gcry_md_setkey (ctx, key, key_size);
  gcry_md_write (ctx, text, text_size);
  _digest = gcry_md_read (ctx, 0);
  len = gcry_md_get_algo_dlen (gcry_md_get_algo (ctx));
  if (_digest != NULL)
    memcpy (digest, _digest, len);
  gcry_md_close (ctx);

  return _digest ? 0 : gnutls_assert_val(GNUTLS_E_HASH_FAILED);
}

static int wrap_gcry_hash_fast(gnutls_digest_algorithm_t algo,
  const void* text, size_t text_size,
  void* digest)
{
  gcry_md_hd_t ctx;
  int ret;
  unsigned char *_digest;
  unsigned int len;

  ret = wrap_gcry_hash_init (algo, (void **)&ctx);
  if (ret < 0)
    return gnutls_assert_val(ret);
  gcry_md_write (ctx, text, text_size);
  _digest = gcry_md_read (ctx, 0);
  len = gcry_md_get_algo_dlen (gcry_md_get_algo (ctx));
  if (_digest != NULL)
    memcpy (digest, _digest, len);
  gcry_md_close (ctx);

  return _digest ? 0 : gnutls_assert_val(GNUTLS_E_HASH_FAILED);
}



gnutls_crypto_mac_st _gnutls_mac_ops = {
  .init = wrap_gcry_mac_init,
  .setkey = wrap_gcry_md_setkey,
  .hash = wrap_gcry_md_write,
  .output = wrap_gcry_mac_output,
  .deinit = wrap_gcry_md_close,
  .fast = wrap_gcry_mac_fast,
  .exists = wrap_gcry_mac_exists,
};

gnutls_crypto_digest_st _gnutls_digest_ops = {
  .init = wrap_gcry_hash_init,
  .hash = wrap_gcry_md_write,
  .output = wrap_gcry_mac_output,
  .deinit = wrap_gcry_md_close,
  .fast = wrap_gcry_hash_fast,
  .exists = wrap_gcry_hash_exists,
};
