/**
 * @file ssh_sign_misc.c
 * @brief Helper functions for signature generation and verification
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_sign_misc.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Format an ECDSA signature
 * @param[in] signature ECDSA signature
 * @param[out] p  Output stream where to write the ECDSA signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatEcdsaSignature(const SshEcdsaSignature *signature,
   uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t rLen;
   size_t sLen;

   //Encode integer R
   error = sshConvertArrayToMpint(signature->r.value, signature->r.length,
      p + 4, &rLen);

   //Check status code
   if(!error)
   {
      //Encode integer S
      error = sshConvertArrayToMpint(signature->s.value, signature->s.length,
         p + rLen + 4, &sLen);
   }

   //Check status code
   if(!error)
   {
      //The resulting ECDSA signature blob is encoded as a string
      STORE32BE(rLen + sLen, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + rLen + sLen;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an ECDSA signature
 * @param[in] data Pointer to the ECDSA signature structure
 * @param[in] length Length of the ECDSA signature structure, in bytes
 * @param[out] signature Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEcdsaSignature(const uint8_t *data, size_t length,
   SshEcdsaSignature *signature)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;

   //Decode integer R
   error = sshParseBinaryString(data, length, &signature->r);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + signature->r.length;
   length -= sizeof(uint32_t) + signature->r.length;

   //Decode integer S
   error = sshParseBinaryString(data, length, &signature->s);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + signature->s.length;
   length -= sizeof(uint32_t) + signature->s.length;

   //Malformed signature?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
