/**
 * @file ssh_sign_verify.h
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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

#ifndef _SSH_SIGN_VERIFY_H
#define _SSH_SIGN_VERIFY_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshVerifySignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   const SshBinaryString *signature);

error_t sshVerifyRsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyDsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyEcdsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyEd25519Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

error_t sshVerifyEd448Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
