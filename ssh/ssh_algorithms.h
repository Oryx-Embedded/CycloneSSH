/**
 * @file ssh_algorithms.h
 * @brief SSH algorithm negotiation
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
 * @version 2.1.4
 **/

#ifndef _SSH_ALGORITHMS_H
#define _SSH_ALGORITHMS_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SSH related functions
error_t sshFormatKexAlgoList(SshContext *context, uint8_t *p, size_t *written);

error_t sshFormatHostKeyAlgoList(SshContext *context, uint8_t *p,
   size_t *written);

error_t sshFormatEncAlgoList(SshContext *context, uint8_t *p, size_t *written);
error_t sshFormatMacAlgoList(SshContext *context, uint8_t *p, size_t *written);

error_t sshFormatCompressionAlgoList(SshContext *context, uint8_t *p,
   size_t *written);

const char_t *sshSelectAlgo(SshContext *context, const SshNameList *peerAlgoList,
   const char_t **supportedAlgoList, uint_t supportedAlgoListLen);

const char_t *sshSelectKexAlgo(SshContext *context,
   const SshNameList *peerAlgoList);

const char_t *sshSelectHostKeyAlgo(SshContext *context,
   const SshNameList *peerAlgoList);

const char_t *sshSelectEncAlgo(SshContext *context,
   const SshNameList *peerAlgoList);

const char_t *sshSelectMacAlgo(SshContext *context,
   const SshNameList *peerAlgoList);

const char_t *sshSelectCompressionAlgo(SshContext *context,
   const SshNameList *peerAlgoList);

const char_t *sshSelectPublicKeyAlgo(const char_t *keyFormatId);

bool_t sshIsGuessCorrect(SshContext *context, const SshNameList *kexAlgoList,
   const SshNameList *hostKeyAlgoList);

bool_t sshIsDhKexAlgo(const char_t *kexAlgo);
bool_t sshIsEcdhKexAlgo(const char_t *kexAlgo);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
