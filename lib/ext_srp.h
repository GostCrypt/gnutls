/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos <nmav@hellug.gr>
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#ifdef ENABLE_SRP

#define IS_SRP_KX(kx) ((kx == GNUTLS_KX_SRP || (kx == GNUTLS_KX_SRP_RSA) || \
          kx == GNUTLS_KX_SRP_DSS)?1:0)

int _gnutls_srp_recv_params(gnutls_session_t state, const opaque * data,
			    size_t data_size);
int _gnutls_srp_send_params(gnutls_session_t state, opaque * data, size_t);

#endif
