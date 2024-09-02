/**
 * @file ssh_kex_hybrid.h
 * @brief Post-quantum hybrid key exchange
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2024 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.4.4
 **/

#ifndef _SSH_KEX_HYBRID_H
#define _SSH_KEX_HYBRID_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshSendKexHybridInit(SshConnection *connection);
error_t sshSendKexHybridReply(SshConnection *connection);

error_t sshFormatKexHybridReply(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatKexHybridInit(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshParseKexHybridInit(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseKexHybridReply(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseKexHybridMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length);

error_t sshSelectKemAlgo(SshConnection *connection);

error_t sshLoadKexClassicalEcdhParams(const char_t *kexAlgo,
   EcDomainParameters *params);

error_t sshGenerateClassicalEcdhKeyPair(SshConnection *connection);
error_t sshComputeClassicalEcdhSharedSecret(SshConnection *connection);

error_t sshDigestClientInit(SshConnection *connection);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
