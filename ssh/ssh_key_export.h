/**
 * @file ssh_key_export.h
 * @brief SSH key file export functions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2022 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneSSH Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.1.6
 **/

#ifndef _SSH_KEY_EXPORT_H
#define _SSH_KEY_EXPORT_H

//Dependencies
#include "ssh_types.h"
#include "pkc/rsa.h"
#include "pkc/dsa.h"
#include "ecc/ec.h"
#include "ecc/eddsa.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief SSH public key formats
 **/

typedef enum
{
   SSH_PUBLIC_KEY_FORMAT_SSH2    = 1, ///<SSH2 public key format
   SSH_PUBLIC_KEY_FORMAT_OPENSSH = 2  ///<OpenSSH public key format
} SshPublicKeyFormat;


//SSH key file export functions
error_t sshExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format);

error_t sshExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format);

error_t sshExportEcdsaPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, char_t *output, size_t *written,
   SshPublicKeyFormat format);

error_t sshExportEd25519PublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format);

error_t sshExportEd448PublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format);

error_t sshEncodePublicKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen, SshPublicKeyFormat format);

error_t sshEncodeSsh2PublicKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen);

error_t sshEncodeOpenSshPublicKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
