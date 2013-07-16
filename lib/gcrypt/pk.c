/*
 * Copyright (C) 2001-2011 Free Software Foundation, Inc.
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

/* This file contains the functions needed for RSA/DSA/EC public key
 * encryption and signatures.
 */


#include <gnutls_int.h>
#include <gnutls_mpi.h>
#include <gnutls_pk.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_num.h>
#include <x509/x509_int.h>
#include <x509/common.h>
#include <random.h>
#include <gnutls_pk.h>
#include <gcrypt.h>

/* this is based on code from old versions of libgcrypt (centuries ago)
 */

int (*generate) (gnutls_pk_algorithm_t, unsigned int level /*bits */ ,
                 gnutls_pk_params_st *);

static inline const char *get_supported_curve(int curve)
{
  switch (curve)
    {
      case GNUTLS_ECC_CURVE_SECP192R1:
        return "secp192r1";
      case GNUTLS_ECC_CURVE_SECP224R1:
        return "secp224r1";
      case GNUTLS_ECC_CURVE_SECP256R1:
        return "secp256r1";
      case GNUTLS_ECC_CURVE_SECP384R1:
        return "secp384r1";
      case GNUTLS_ECC_CURVE_SECP521R1:
        return "secp521r1";
      default:
        return NULL;
    }
}

static bigint_t
_ecc_compute_point (int curve, bigint_t x, bigint_t y)
{
  int pbytes = gnutls_ecc_curve_get_size (curve);
  bigint_t result;
  bigint_t tmp;

  result = gcry_mpi_set_ui (NULL, 04); /* uncompressed point */
  if (!result)
    return NULL;

  tmp = gcry_mpi_new (pbytes * 8 + 8);
  if (!tmp)
    {
      _gnutls_mpi_release (&result);
      return NULL;
    }

  gcry_mpi_lshift (tmp, result, pbytes * 8);
  _gnutls_mpi_add (result, tmp, x);

  gcry_mpi_lshift (tmp, result, pbytes * 8);
  _gnutls_mpi_add (result, tmp, y);

  _gnutls_mpi_release (&tmp);
  return result;
}

static int
_wrap_gcry_pk_encrypt (gnutls_pk_algorithm_t algo,
                       gnutls_datum_t * ciphertext,
                       const gnutls_datum_t * plaintext,
                       const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_ciph = NULL, s_data = NULL, s_pkey = NULL;
  int rc = -1;
  int ret;
  bigint_t data, res;
  gcry_sexp_t list;

  if (_gnutls_mpi_scan_nz (&data, plaintext->data, plaintext->size) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_RSA:
      if (pk_params->params_nr >= 2)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(rsa(n%m)(e%m)))",
                              pk_params->params[0], pk_params->params[1]);
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "%m", data))
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_PK_ENCRYPTION_FAILED;
      goto cleanup;
    }

  list = gcry_sexp_find_token (s_ciph, "a", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  res = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);
  if (res == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = _gnutls_mpi_dprint_size (res, ciphertext, plaintext->size);
  _gnutls_mpi_release (&res);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;

cleanup:
  _gnutls_mpi_release (&data);
  if (s_ciph)
    gcry_sexp_release (s_ciph);
  if (s_data)
    gcry_sexp_release (s_data);
  if (s_pkey)
    gcry_sexp_release (s_pkey);

  return ret;
}

static int
_wrap_gcry_pk_decrypt (gnutls_pk_algorithm_t algo,
                       gnutls_datum_t * plaintext,
                       const gnutls_datum_t * ciphertext,
                       const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_plain = NULL, s_data = NULL, s_pkey = NULL;
  int rc = -1;
  int ret;
  bigint_t data, res;

  if (_gnutls_mpi_scan_nz (&data, ciphertext->data, ciphertext->size) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_RSA:
      if (pk_params->params_nr >= 6)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
                              pk_params->params[0], pk_params->params[1],
                              pk_params->params[2], pk_params->params[3],
                              pk_params->params[4], pk_params->params[5]);
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  /* put the data into a simple list */
  if (gcry_sexp_build (&s_data, NULL, "(enc-val(rsa(a%m)))", data))
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_decrypt (&s_plain, s_data, s_pkey);
  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_PK_DECRYPTION_FAILED;
      goto cleanup;
    }

  res = gcry_sexp_nth_mpi (s_plain, 0, GCRYMPI_FMT_USG);
  if (res == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = _gnutls_mpi_dprint (res, plaintext);
  _gnutls_mpi_release (&res);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;

cleanup:
  _gnutls_mpi_release (&data);
  if (s_plain)
    gcry_sexp_release (s_plain);
  if (s_data)
    gcry_sexp_release (s_data);
  if (s_pkey)
    gcry_sexp_release (s_pkey);

  return ret;

}


/* in case of DSA puts into data, r,s
 */
static int
_wrap_gcry_pk_sign (gnutls_pk_algorithm_t algo, gnutls_datum_t * signature,
                    const gnutls_datum_t * vdata,
                    const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
  gcry_sexp_t list = NULL;
  int rc = -1, ret;
  bigint_t hash;
  bigint_t res[2] = { NULL, NULL };
  int curve_id = pk_params->flags;
  bigint_t point;
  const char *curve;

  if (_gnutls_mpi_scan_nz (&hash, vdata->data, vdata->size) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_EC: /* we do ECDSA */
      curve = get_supported_curve(curve_id);
      if (curve == NULL)
        return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);

      if (pk_params->params_nr >= 3)
        {
          point = _ecc_compute_point (curve_id,
                                      pk_params->params[0],
                                      pk_params->params[1]);
          if (point == NULL)
            {
              gnutls_assert ();
              ret = GNUTLS_E_INTERNAL_ERROR;
              goto cleanup;
            }
          rc = gcry_sexp_build (&s_key, NULL,
                                "(private-key(ecc(curve%s)(q%m)(d%m)))",
                                curve,
                                point,
                                pk_params->params[2]);
          _gnutls_mpi_release (&point);
        }
      else
        {
          gnutls_assert ();
        }

      if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }

      break;
    case GNUTLS_PK_DSA:
      if (pk_params->params_nr >= 5)
        rc = gcry_sexp_build (&s_key, NULL,
                              "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
                              pk_params->params[0], pk_params->params[1],
                              pk_params->params[2], pk_params->params[3],
                              pk_params->params[4]);
      else
        {
          gnutls_assert ();
        }

      if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }

      break;
    case GNUTLS_PK_RSA:
      if (pk_params->params_nr >= 6)
        rc = gcry_sexp_build (&s_key, NULL,
                              "(private-key(rsa((n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
                              pk_params->params[0], pk_params->params[1],
                              pk_params->params[2], pk_params->params[3],
                              pk_params->params[4], pk_params->params[5]);
      else
        {
          gnutls_assert ();
        }

      if (gcry_sexp_build (&s_hash, NULL, "(data (flags pkcs1) (value %m))", hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  /* pass it to libgcrypt */
  rc = gcry_pk_sign (&s_sig, s_hash, s_key);
  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_PK_SIGN_FAILED;
      goto cleanup;
    }

  ret = GNUTLS_E_INTERNAL_ERROR;

  switch (algo)
    {
    case GNUTLS_PK_EC:
    case GNUTLS_PK_DSA:
      {
        list = gcry_sexp_find_token (s_sig, "r", 0);
        if (list == NULL)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto cleanup;
          }

        res[0] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release (list);

        list = gcry_sexp_find_token (s_sig, "s", 0);
        if (list == NULL)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto cleanup;
          }

        res[1] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release (list);

        ret = _gnutls_encode_ber_rs (signature, res[0], res[1]);
        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }
      }
      break;

    case GNUTLS_PK_RSA:
      {
        list = gcry_sexp_find_token (s_sig, "s", 0);
        if (list == NULL)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto cleanup;
          }

        res[0] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release (list);

        ret = _gnutls_mpi_dprint (res[0], signature);
        if (ret < 0)
          {
            gnutls_assert ();
            goto cleanup;
          }
      }
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = 0;

cleanup:
  _gnutls_mpi_release (&hash);
  if (res[0])
    _gnutls_mpi_release (&res[0]);
  if (res[1])
    _gnutls_mpi_release (&res[1]);
  if (s_sig)
    gcry_sexp_release (s_sig);
  if (s_hash)
    gcry_sexp_release (s_hash);
  if (s_key)
    gcry_sexp_release (s_key);

  return ret;
}

static int
_wrap_gcry_pk_verify (gnutls_pk_algorithm_t algo,
                      const gnutls_datum_t * vdata,
                      const gnutls_datum_t * signature,
                      const gnutls_pk_params_st * pk_params)
{
  gcry_sexp_t s_sig = NULL, s_hash = NULL, s_pkey = NULL;
  int rc = -1, ret;
  bigint_t hash;
  bigint_t tmp[2] = { NULL, NULL };
  int curve_id = pk_params->flags;
  const char *curve;
  bigint_t point;

  if (_gnutls_mpi_scan_nz (&hash, vdata->data, vdata->size) != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_MPI_SCAN_FAILED;
    }

  /* make a sexp from pkey */
  switch (algo)
    {
    case GNUTLS_PK_EC:
      curve = get_supported_curve(curve_id);
      if (curve == NULL)
        return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);

      if (pk_params->params_nr >= 2)
        {
          point = _ecc_compute_point (curve_id,
                                      pk_params->params[0],
                                      pk_params->params[1]);
          if (point == NULL)
            {
              gnutls_assert ();
              ret = GNUTLS_E_INTERNAL_ERROR;
              goto cleanup;
            }
          rc = gcry_sexp_build (&s_pkey, NULL,
                                "(public-key(ecc(curve%s)(q%m)))",
                                curve,
                                point);
          _gnutls_mpi_release (&point);
        }
      else
        {
          gnutls_assert ();
        }

      break;
    case GNUTLS_PK_DSA:
      if (pk_params->params_nr >= 4)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                              pk_params->params[0], pk_params->params[1],
                              pk_params->params[2], pk_params->params[3]);
      break;
    case GNUTLS_PK_RSA:
      if (pk_params->params_nr >= 2)
        rc = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(rsa(n%m)(e%m)))",
                              pk_params->params[0], pk_params->params[1]);
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  switch (algo)
    {
    case GNUTLS_PK_EC:
      /* put the data into a simple list */
      if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }

      ret = _gnutls_decode_ber_rs (signature, &tmp[0], &tmp[1]);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
      rc = gcry_sexp_build (&s_sig, NULL,
                            "(sig-val(ecdsa(r%m)(s%m)))", tmp[0], tmp[1]);
      _gnutls_mpi_release (&tmp[0]);
      _gnutls_mpi_release (&tmp[1]);
      break;

    case GNUTLS_PK_DSA:
      /* put the data into a simple list */
      if (gcry_sexp_build (&s_hash, NULL, "%m", hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }

      ret = _gnutls_decode_ber_rs (signature, &tmp[0], &tmp[1]);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
      rc = gcry_sexp_build (&s_sig, NULL,
                            "(sig-val(dsa(r%m)(s%m)))", tmp[0], tmp[1]);
      _gnutls_mpi_release (&tmp[0]);
      _gnutls_mpi_release (&tmp[1]);
      break;

    case GNUTLS_PK_RSA:
      if (gcry_sexp_build (&s_hash, NULL, "(data (flags pkcs1) (value %m))", hash))
        {
          gnutls_assert ();
          ret = GNUTLS_E_INTERNAL_ERROR;
          goto cleanup;
        }

      ret = _gnutls_mpi_scan_nz (&tmp[0], signature->data, signature->size);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }
      rc = gcry_sexp_build (&s_sig, NULL, "(sig-val(rsa(s%m)))", tmp[0]);
      _gnutls_mpi_release (&tmp[0]);
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  rc = gcry_pk_verify (s_sig, s_hash, s_pkey);

  if (rc != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
      goto cleanup;
    }

  ret = 0;

cleanup:
  _gnutls_mpi_release (&hash);
  if (s_sig)
    gcry_sexp_release (s_sig);
  if (s_hash)
    gcry_sexp_release (s_hash);
  if (s_pkey)
    gcry_sexp_release (s_pkey);

  return ret;
}

static int
_ecc_generate_params (gnutls_pk_params_st * params, int curve_id)
{

  int ret;
  gcry_sexp_t parms, key, list;
  const char *curve = get_supported_curve (curve_id);
  int bits = gnutls_ecc_curve_get_size (curve_id) * 8;

  ret = gcry_sexp_build (&parms, NULL, "(genkey(ecc(curve %s)))", curve);
  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the ECC key
   */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "d", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[2] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[1] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  params->params[0] = _gnutls_mpi_new (bits);

  gcry_mpi_rshift(params->params[0], params->params[1], bits);
  gcry_mpi_clear_highbit(params->params[0], bits);
  gcry_mpi_clear_highbit(params->params[1], bits);
  gcry_sexp_release (list);
  gcry_sexp_release (key);

  _gnutls_mpi_log ("x: ", params->params[0]);
  _gnutls_mpi_log ("y: ", params->params[1]);
  _gnutls_mpi_log ("d: ", params->params[2]);

  params->flags = curve_id;
  params->params_nr = 3;

  return 0;

}


static int
_dsa_generate_params (gnutls_pk_params_st * params, int bits)
{

  int ret;
  gcry_sexp_t parms, key, list;

  /* FIXME: Remove me once we depend on 1.3.1 */
  if (bits > 1024 && gcry_check_version ("1.3.1") == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (bits < 512)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret = gcry_sexp_build (&parms, NULL, "(genkey(dsa(nbits %d)))", bits);
  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the DSA key 
   */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "p", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[0] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[1] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "g", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[2] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "y", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[3] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "x", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[4] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);

  gcry_sexp_release (list);
  gcry_sexp_release (key);

  _gnutls_mpi_log ("p: ", params->params[0]);
  _gnutls_mpi_log ("q: ", params->params[1]);
  _gnutls_mpi_log ("g: ", params->params[2]);
  _gnutls_mpi_log ("y: ", params->params[3]);
  _gnutls_mpi_log ("x: ", params->params[4]);

  params->params_nr = 5;

  return 0;

}

static int calc_rsa_exp (gnutls_pk_params_st* params)
{
  bigint_t tmp = _gnutls_mpi_alloc_like (params->params[0]);

  if (params->params_nr < RSA_PRIVATE_PARAMS - 2)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (tmp == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* [6] = d % p-1, [7] = d % q-1 */
  _gnutls_mpi_sub_ui (tmp, params->params[3], 1);
  params->params[6] = _gnutls_mpi_mod (params->params[2] /*d */ , tmp);

  _gnutls_mpi_sub_ui (tmp, params->params[4], 1);
  params->params[7] = _gnutls_mpi_mod (params->params[2] /*d */ , tmp);

  _gnutls_mpi_release (&tmp);

  if (params->params[7] == NULL || params->params[6] == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  return 0;
}

static int
_rsa_generate_params (gnutls_pk_params_st * params, int bits)
{

  int ret;
  unsigned int i;
  gcry_sexp_t parms, key, list;

  if (params->params_nr < RSA_PRIVATE_PARAMS)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  ret = gcry_sexp_build (&parms, NULL, "(genkey(rsa(nbits %d)))", bits);
  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* generate the RSA key */
  ret = gcry_pk_genkey (&key, parms);
  gcry_sexp_release (parms);

  if (ret != 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  list = gcry_sexp_find_token (key, "n", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[0] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "e", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[1] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "d", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[2] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);

  list = gcry_sexp_find_token (key, "p", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[3] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "q", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[4] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);


  list = gcry_sexp_find_token (key, "u", 0);
  if (list == NULL)
    {
      gnutls_assert ();
      gcry_sexp_release (key);
      return GNUTLS_E_INTERNAL_ERROR;
    }

  params->params[5] = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);

  gcry_sexp_release (list);
  gcry_sexp_release (key);

  _gnutls_mpi_log ("n: ", params->params[0]);
  _gnutls_mpi_log ("e: ", params->params[1]);
  _gnutls_mpi_log ("d: ", params->params[2]);
  _gnutls_mpi_log ("p: ", params->params[3]);
  _gnutls_mpi_log ("q: ", params->params[4]);
  _gnutls_mpi_log ("u: ", params->params[5]);

  /* generate e1 and e2 */

  params->params_nr = 6;

  ret = calc_rsa_exp (params);
  if (ret < 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }

  params->params_nr += 2;

  return 0;

cleanup:
  for (i = 0; i < params->params_nr; i++)
    _gnutls_mpi_release (&params->params[i]);

  return ret;
}


static int
wrap_gcry_pk_generate_params (gnutls_pk_algorithm_t algo,
                              unsigned int level /*bits */ ,
                              gnutls_pk_params_st * params)
{

  switch (algo)
    {

    case GNUTLS_PK_EC:
      params->params_nr = ECC_PRIVATE_PARAMS;
      if (params->params_nr > GNUTLS_MAX_PK_PARAMS)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
      return _ecc_generate_params (params, level);

    case GNUTLS_PK_DSA:
      params->params_nr = DSA_PRIVATE_PARAMS;
      if (params->params_nr > GNUTLS_MAX_PK_PARAMS)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
      return _dsa_generate_params (params, level);

    case GNUTLS_PK_RSA:
      params->params_nr = RSA_PRIVATE_PARAMS;
      if (params->params_nr > GNUTLS_MAX_PK_PARAMS)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
      return _rsa_generate_params (params, level);

    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
}

static int
wrap_gcry_pk_verify_params (gnutls_pk_algorithm_t algo,
                            const gnutls_pk_params_st * params)
{
  return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
}

static int
wrap_gcry_pk_fixup (gnutls_pk_algorithm_t algo,
                    gnutls_direction_t direction,
                    gnutls_pk_params_st * params)
{
  int ret, result;

  /* only for RSA we invert the coefficient --pgp type */

  if (algo != GNUTLS_PK_RSA)
    return 0;

  if (params->params[5] == NULL)
    params->params[5] =
      _gnutls_mpi_new (_gnutls_mpi_get_nbits (params->params[0]));

  if (params->params[5] == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = 1;
  if (direction == GNUTLS_IMPORT)
    {
      /* calculate exp1 [6] and exp2 [7] */
      _gnutls_mpi_release (&params->params[6]);
      _gnutls_mpi_release (&params->params[7]);
      result = calc_rsa_exp (params);
      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }

      ret =
        gcry_mpi_invm (params->params[5], params->params[3],
                       params->params[4]);

      params->params_nr = RSA_PRIVATE_PARAMS;
    }
  else if (direction == GNUTLS_EXPORT)
    ret =
      gcry_mpi_invm (params->params[5], params->params[4], params->params[3]);
  if (ret == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;
}

static int
extract_digest_info (gcry_sexp_t key,
                     gnutls_datum_t *di, uint8_t** rdi,
                     gcry_sexp_t signature)
{
  unsigned i;
  int ret;
  gcry_error_t err;
  gcry_sexp_t out, list;
  bigint_t res;
  size_t keysize = (gcry_pk_get_nbits (key) + 7)/ 8;

  if (keysize == 0)
    return 0;

  err = gcry_pk_encrypt (&out, signature, key);
  if (err != 0)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  list = gcry_sexp_find_token (out, "a", 0);
  gcry_sexp_release (out);
  if (list == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  res = gcry_sexp_nth_mpi (list, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (list);
  if (res == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = _gnutls_mpi_dprint_size (res, di, keysize);
  _gnutls_mpi_release (&res);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }
  *rdi = di->data;

  if (di->data[0] != 0 || di->data[1] != 1)
    {
      ret = 0;
      goto cleanup2;
    }

  for (i = 2; i < keysize; i++)
    {
      if (di->data[i] == 0 && i > 2)
        break;

      if (di->data[i] != 0xff)
        {
          ret = 0;
          goto cleanup2;
        }
    }

  i++;

  di->data += i;
  di->size -= i;

  return 1;

cleanup2:
  gnutls_free(*rdi);
cleanup:

  return ret;
}

/* Given a signature and parameters, it should return
 * the hash algorithm used in the signature. This is a kludge
 * but until we deprecate gnutls_pubkey_get_verify_algorithm()
 * we depend on it.
 */
static int wrap_gcry_hash_algorithm (gnutls_pk_algorithm_t pk,
    const gnutls_datum_t * sig, gnutls_pk_params_st * issuer_params,
    gnutls_digest_algorithm_t* hash_algo)
{
  uint8_t digest[MAX_HASH_SIZE];
  uint8_t* rdi = NULL;
  gnutls_datum_t di;
  bigint_t s;
  unsigned digest_size;
  gcry_sexp_t s_pkey = NULL, s_data = NULL;
  const mac_entry_st* me;
  int ret;

  switch (pk)
    {
    case GNUTLS_PK_DSA:
    case GNUTLS_PK_EC:

      me = _gnutls_dsa_q_to_hash (pk, issuer_params, NULL);
      if (hash_algo)
        *hash_algo = me->id;

      ret = 0;
      break;
    case GNUTLS_PK_RSA:
      if (sig == NULL)
        {                       /* return a sensible algorithm */
          if (hash_algo)
            *hash_algo = GNUTLS_DIG_SHA256;
          return 0;
        }

      if (issuer_params->params_nr >= 2)
        ret = gcry_sexp_build (&s_pkey, NULL,
                              "(public-key(rsa(n%m)(e%m)))",
                              issuer_params->params[0],
                              issuer_params->params[1]);
      else
        return gnutls_assert_val(GNUTLS_E_PK_SIG_VERIFY_FAILED);

      digest_size = sizeof(digest);

      if (_gnutls_mpi_scan_nz (&s, sig->data, sig->size) != 0)
        {
          gnutls_assert ();
          return GNUTLS_E_MPI_SCAN_FAILED;
        }

      /* put the data into a simple list */
      ret = gcry_sexp_build (&s_data, NULL, "%m", s);
      _gnutls_mpi_release (&s);
      if (ret)
        {
          gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto cleanup;
        }

      ret = extract_digest_info (s_pkey, &di, &rdi, s_data);
      if (ret == 0)
        {
          ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
          gnutls_assert ();
          goto cleanup;
        }

      digest_size = sizeof(digest);
      if ((ret =
           decode_ber_digest_info (&di, hash_algo, digest,
                                   &digest_size)) < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }

      if (digest_size != _gnutls_hash_get_algo_len (mac_to_entry(*hash_algo)))
        {
          gnutls_assert ();
          ret = GNUTLS_E_PK_SIG_VERIFY_FAILED;
          goto cleanup;
        }

      ret = 0;
      break;

    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
    }

cleanup:
  gcry_sexp_release (s_pkey);
  gcry_sexp_release (s_data);
  gnutls_free(rdi);
  return ret;

}

static int _wrap_gcry_pk_derive(gnutls_pk_algorithm_t algo, gnutls_datum_t * out,
                                  const gnutls_pk_params_st * priv,
                                  const gnutls_pk_params_st * pub)
{
  int ret;

  switch (algo)
    {
    case GNUTLS_PK_EC:
      {
        const char * curve;
        int rc;
        gcry_ctx_t ctx;
        gcry_mpi_t z1;
        gcry_mpi_point_t point, point2;

        out->data = NULL;

        curve = get_supported_curve(priv->flags);
        if (curve == NULL)
          return gnutls_assert_val(GNUTLS_E_ECC_UNSUPPORTED_CURVE);

        rc = gcry_mpi_ec_new (&ctx, NULL, curve);
        if (rc != 0)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto cleanup;
          }

        z1 = gcry_mpi_set_ui (NULL, 1);
        if (z1 == NULL)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto ecc_cleanup;
          }

        point = gcry_mpi_point_set (NULL, pub->params[0], pub->params[1], z1);
        if (point == NULL)
          {
            gnutls_assert ();
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto ecc_cleanup;
          }

        point2 = gcry_mpi_point_new (0);
        if (point2 == NULL)
          {
            gnutls_assert ();
            gcry_mpi_point_release(point);
            ret = GNUTLS_E_INTERNAL_ERROR;
            goto ecc_cleanup;
          }

        gcry_mpi_ec_mul (point2, priv->params[2], point, ctx);
        gcry_mpi_point_release(point);

        gcry_mpi_ec_get_affine (z1, NULL, point2, ctx);
        gcry_mpi_point_release(point2);

        ret = _gnutls_mpi_dprint_size (z1, out,
                                       gnutls_ecc_curve_get_size(priv->flags));

ecc_cleanup:
        if (z1 != NULL)
          gcry_mpi_release(z1);
        gcry_ctx_release (ctx);
        if (ret < 0) goto cleanup;
        break;
      }
    default:
      gnutls_assert ();
      ret = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  ret = 0;

cleanup:

  return ret;
}

int crypto_pk_prio = INT_MAX;

gnutls_crypto_pk_st _gnutls_pk_ops = {
  .hash_algorithm = wrap_gcry_hash_algorithm,
  .encrypt = _wrap_gcry_pk_encrypt,
  .decrypt = _wrap_gcry_pk_decrypt,
  .sign = _wrap_gcry_pk_sign,
  .verify = _wrap_gcry_pk_verify,
  .generate = wrap_gcry_pk_generate_params,
  .verify_params = wrap_gcry_pk_verify_params,
  .pk_fixup_private_params = wrap_gcry_pk_fixup,
  .derive = _wrap_gcry_pk_derive,
};
