/**
 * @file ssh_key_decrypt.h
 * @brief SSH private key decryption
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2025 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.5.2
 **/

#ifndef _SSH_KEY_DECRYPT_H
#define _SSH_KEY_DECRYPT_H

//Dependencies
#include "ssh.h"
#include "ssh_key_parse.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief KDF options
 **/

typedef struct
{
   SshBinaryString salt;
   uint32_t rounds;
} SshKdfOptions;


//SSH private key decryption related functions
error_t sshDecryptPrivateKey(const char_t *input, size_t inputLen,
   const char_t *password, char_t *output, size_t *outputLen);

error_t sshDecryptOpenSshPrivateKey(const SshPrivateKeyHeader *privateKeyHeader,
   const char_t *password, const uint8_t *ciphertext, uint8_t *plaintext,
   size_t length);

error_t sshParseKdfOptions(const uint8_t *data, size_t length,
   SshKdfOptions *kdfOptions);

error_t sshKdf(const char *password, size_t passwordLen, const uint8_t *salt,
   size_t saltLen, uint_t rounds, uint8_t *key, size_t keyLen);

error_t sshKdfHash(uint8_t *password, uint8_t *salt, uint8_t *output);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
