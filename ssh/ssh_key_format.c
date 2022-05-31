/**
 * @file ssh_key_format.c
 * @brief SSH key formatting
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_key_format.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Format an RSA public host key
 * @param[in] publicKey Pointer to the RSA public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatRsaPublicKey(const RsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-rsa", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format RSA public exponent
   error = sshFormatMpint(&publicKey->e, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format RSA modulus
   error = sshFormatMpint(&publicKey->n, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format a DSA public host key
 * @param[in] publicKey Pointer to the DSA public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatDsaPublicKey(const DsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-dss", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA prime modulus
   error = sshFormatMpint(&publicKey->params.p, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA group order
   error = sshFormatMpint(&publicKey->params.q, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA group generator
   error = sshFormatMpint(&publicKey->params.g, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format DSA public key value
   error = sshFormatMpint(&publicKey->y, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an ECDSA public host key
 * @param[in] params EC domain parameters
 * @param[in] publicKey Pointer to the ECDSA public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatEcdsaPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *keyFormatId;
   const char_t *curveName;

   //Total length of the public host key structure
   *written = 0;

   //Check elliptic curve
   if(!osStrcmp(params->name, "secp256r1"))
   {
      //Select NIST P-256 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp256";
      curveName = "nistp256";
   }
   else if(!osStrcmp(params->name, "secp384r1"))
   {
      //Select NIST P-384 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp384";
      curveName = "nistp384";
   }
   else if(!osStrcmp(params->name, "secp521r1"))
   {
      //Select NIST P-521 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp521";
      curveName = "nistp521";
   }
   else
   {
      //Unknown host key algorithm
      return ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Format public key format identifier
   error = sshFormatString(keyFormatId, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format the elliptic curve domain parameter identifier
   error = sshFormatString(curveName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Format EC public key
   error = ecExport(params, &publicKey->q, p + 4, &n);
   //Any error to report?
   if(error)
      return error;

   //The public key is encoded as a string
   STORE32BE(n, p);
   //Total number of bytes that have been written
   *written += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an Ed25519 public host key
 * @param[in] publicKey Pointer to the Ed25519 public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatEd25519PublicKey(const EddsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-ed25519", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The public key shall consist of 32 octets
   n = ED25519_PUBLIC_KEY_LEN;

   //Format Ed25519 public key
   error = mpiExport(&publicKey->q, p + 4, n, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The public key is encoded as a string
   STORE32BE(n, p);
   //Total number of bytes that have been written
   *written += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format an Ed448 public host key
 * @param[in] publicKey Pointer to the Ed448 public key
 * @param[out] p Buffer where to store the host key structure
 * @param[out] written Length of the resulting host key structure
 * @return Error code
 **/

error_t sshFormatEd448PublicKey(const EddsaPublicKey *publicKey,
   uint8_t *p, size_t *written)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Total length of the public host key structure
   *written = 0;

   //Format public key format identifier
   error = sshFormatString("ssh-ed448", p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The public key shall consist of 57 octets
   n = ED448_PUBLIC_KEY_LEN;

   //Format Ed448 public key
   error = mpiExport(&publicKey->q, p + 4, n, MPI_FORMAT_LITTLE_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //The public key is encoded as a string
   STORE32BE(n, p);
   //Total number of bytes that have been written
   *written += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
