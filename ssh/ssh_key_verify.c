/**
 * @file ssh_key_verify.c
 * @brief SSH host key verification
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_verify.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Check if a host key is trusted
 * @param[in] hostKey Host key to be checked
 * @param[in] hostKeyLen Length of the host key, in bytes
 * @param[in] trustedKey Trusted host key (PEM, SSH2 or OpenSSH format)
 * @param[in] trustedKeyLen Length of the trusted host key
 * @return Error code
 **/

error_t sshVerifyHostKey(const uint8_t *hostKey, size_t hostKeyLen,
   const char_t *trustedKey, size_t trustedKeyLen)
{
   error_t error;
   size_t n;
   uint8_t *buffer;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(trustedKey, trustedKeyLen, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(trustedKey, trustedKeyLen, buffer, &n);

         //Compare host keys
         if(hostKeyLen == n && !osMemcmp(hostKey, buffer, n))
         {
            //The host key is trusted
            error = NO_ERROR;
         }
         else
         {
            //The host key is unknown
            error = ERROR_INVALID_KEY;
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }

   //Return status code
   return error;
}

#endif
