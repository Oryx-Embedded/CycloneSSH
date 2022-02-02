/**
 * @file ssh_key_import.c
 * @brief SSH public key file import functions
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
#include "ssh/ssh_misc.h"
#include "encoding/base64.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Decode an SSH public key file containing an RSA public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey RSA public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportRsaPublicKey(const char_t *input, size_t length,
   RsaPublicKey *publicKey)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshRsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse RSA host key structure
            error = sshParseRsaHostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import RSA public key
            error = sshImportRsaHostKey(&hostKey, publicKey);
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

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      rsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing a DSA public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey DSA public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportDsaPublicKey(const char_t *input, size_t length,
   DsaPublicKey *publicKey)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshDsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse DSA host key structure
            error = sshParseDsaHostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import DSA public key
            error = sshImportDsaHostKey(&hostKey, publicKey);
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

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      dsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing an ECDSA public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] params EC domain parameters resulting from the parsing process
 * @param[out] publicKey ECDSA public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEcdsaPublicKey(const char_t *input, size_t length,
   EcDomainParameters *params, EcPublicKey *publicKey)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshEcdsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse ECDSA host key structure
            error = sshParseEcdsaHostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import ECDSA public key
            error = sshImportEcdsaHostKey(&hostKey, params, publicKey);
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

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      ecFreeDomainParameters(params);
      ecFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing an Ed25519 public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey Ed25519 public key resulting from the parsing process
 * @return Error code
 **/

error_t sshImportEd25519PublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshEddsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse Ed25519 host key structure
            error = sshParseEd25519HostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import Ed25519 public key
            error = sshImportEd25519HostKey(&hostKey, publicKey);
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

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode an SSH public key file containing an Ed448 public key
 * @param[in] input Pointer to the SSH public key file
 * @param[in] length Length of the SSH public key file
 * @param[out] publicKey Ed448 public key resulting from the parsing process
 * @return Error code
 **/
error_t sshImportEd448PublicKey(const char_t *input, size_t length,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   uint8_t *buffer;
   SshEddsaHostKey hostKey;

   //Check parameters
   if(input == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;
   if(publicKey == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the public key structure
   error = sshDecodePublicKeyFile(input, length, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the public key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the SSH public key file
         error = sshDecodePublicKeyFile(input, length, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse Ed448 host key structure
            error = sshParseEd448HostKey(buffer, n, &hostKey);
         }

         //Check status code
         if(!error)
         {
            //Import Ed448 public key
            error = sshImportEd448HostKey(&hostKey, publicKey);
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

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      eddsaFreePublicKey(publicKey);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an RSA host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the RSA public key
 * @return Error code
 **/

error_t sshImportRsaHostKey(const SshRsaHostKey *hostKey,
   RsaPublicKey *publicKey)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;
   uint_t k;

   //Import RSA public exponent
   error = mpiImport(&publicKey->e, hostKey->e.value, hostKey->e.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import RSA modulus
   error = mpiImport(&publicKey->n, hostKey->n.value, hostKey->n.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the modulus, in bits
   k = mpiGetBitLength(&publicKey->n);

   //Applications should enforce minimum and maximum key sizes
   if(k < SSH_MIN_RSA_MODULUS_SIZE || k > SSH_MAX_RSA_MODULUS_SIZE)
      return ERROR_INVALID_KEY_LENGTH;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a DSA host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the DSA public key
 * @return Error code
 **/

error_t sshImportDsaHostKey(const SshDsaHostKey *hostKey,
   DsaPublicKey *publicKey)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;
   size_t k;

   //Import DSA prime
   error = mpiImport(&publicKey->params.p, hostKey->p.value, hostKey->p.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA group order
   error = mpiImport(&publicKey->params.q, hostKey->q.value, hostKey->q.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA group generator
   error = mpiImport(&publicKey->params.g, hostKey->g.value, hostKey->g.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Import DSA public key value
   error = mpiImport(&publicKey->y, hostKey->y.value, hostKey->y.length,
      MPI_FORMAT_BIG_ENDIAN);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the modulus, in bits
   k = mpiGetBitLength(&publicKey->params.p);

   //Applications should enforce minimum and maximum key sizes
   if(k < SSH_MIN_DSA_MODULUS_SIZE || k > SSH_MAX_DSA_MODULUS_SIZE)
      return ERROR_INVALID_KEY_LENGTH;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import a ECDSA host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] params EC domain parameters
 * @param[out] publicKey Pointer to the ECDSA public key
 * @return Error code
 **/

error_t sshImportEcdsaHostKey(const SshEcdsaHostKey *hostKey,
   EcDomainParameters *params, EcPublicKey *publicKey)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;

#if (SSH_NISTP256_SUPPORT == ENABLED)
   //NIST P-256 elliptic curve?
   if(sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp256") &&
      sshCompareString(&hostKey->curveName, "nistp256"))
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(params, SECP256R1_CURVE);
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED)
   //NIST P-384 elliptic curve?
   if(sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp384") &&
      sshCompareString(&hostKey->curveName, "nistp384"))
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(params, SECP384R1_CURVE);
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED)
   //NIST P-521 elliptic curve?
   if(sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp521") &&
      sshCompareString(&hostKey->curveName, "nistp521"))
   {
      //Load EC domain parameters
      error = ecLoadDomainParameters(params, SECP521R1_CURVE);
   }
   else
#endif
   //Unknown elliptic curve?
   {
      //Report an error
      error = ERROR_WRONG_IDENTIFIER;
   }

   //Any error to report?
   if(error)
      return error;

   //Import EC public key
   error = ecImport(params, &publicKey->q, hostKey->q.value, hostKey->q.length);
   //Any error to report?
   if(error)
      return error;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an Ed25519 host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the Ed25519 public key
 * @return Error code
 **/

error_t sshImportEd25519HostKey(const SshEddsaHostKey *hostKey,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;

   //Import Ed25519 public key
   error = mpiImport(&publicKey->q, hostKey->q.value, hostKey->q.length,
      MPI_FORMAT_LITTLE_ENDIAN);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Import an Ed448 host key
 * @param[in] hostKey Pointer to the host key structure
 * @param[out] publicKey Pointer to the Ed448 public key
 * @return Error code
 **/

error_t sshImportEd448HostKey(const SshEddsaHostKey *hostKey,
   EddsaPublicKey *publicKey)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;

   //Import Ed448 public key
   error = mpiImport(&publicKey->q, hostKey->q.value, hostKey->q.length,
      MPI_FORMAT_LITTLE_ENDIAN);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an RSA host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseRsaHostKey(const uint8_t *data, size_t length,
   SshRsaHostKey *hostKey)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-rsa"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse RSA public exponent
   error = sshParseBinaryString(data, length, &hostKey->e);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->e.length;
   length -= sizeof(uint32_t) + hostKey->e.length;

   //Parse RSA modulus
   error = sshParseBinaryString(data, length, &hostKey->n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->n.length;
   length -= sizeof(uint32_t) + hostKey->n.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse a DSA host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseDsaHostKey(const uint8_t *data, size_t length,
   SshDsaHostKey *hostKey)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-dss"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse DSA prime
   error = sshParseBinaryString(data, length, &hostKey->p);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->p.length;
   length -= sizeof(uint32_t) + hostKey->p.length;

   //Parse DSA group order
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Parse DSA group generator
   error = sshParseBinaryString(data, length, &hostKey->g);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->g.length;
   length -= sizeof(uint32_t) + hostKey->g.length;

   //Parse DSA public key value
   error = sshParseBinaryString(data, length, &hostKey->y);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->y.length;
   length -= sizeof(uint32_t) + hostKey->y.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an ECDSA host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEcdsaHostKey(const uint8_t *data, size_t length,
   SshEcdsaHostKey *hostKey)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp256") &&
      !sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp384") &&
      !sshCompareString(&hostKey->keyFormatId, "ecdsa-sha2-nistp521"))
   {
      return ERROR_WRONG_IDENTIFIER;
   }

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse elliptic curve domain parameter identifier
   error = sshParseString(data, length, &hostKey->curveName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->curveName.length;
   length -= sizeof(uint32_t) + hostKey->curveName.length;

   //Parse public key
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an Ed25519 host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEd25519HostKey(const uint8_t *data, size_t length,
   SshEddsaHostKey *hostKey)
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-ed25519"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse Ed25519 public key
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //The public key consists of 32 octets
   if(hostKey->q.length != ED25519_PUBLIC_KEY_LEN)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse an Ed448 host key structure
 * @param[in] data Pointer to the host key structure
 * @param[in] length Length of the host key structure, in bytes
 * @param[out] hostKey Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseEd448HostKey(const uint8_t *data, size_t length,
   SshEddsaHostKey *hostKey)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;

   //Decode key format identifier
   error = sshParseString(data, length, &hostKey->keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Unexpected key format identifier?
   if(!sshCompareString(&hostKey->keyFormatId, "ssh-ed448"))
      return ERROR_WRONG_IDENTIFIER;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->keyFormatId.length;
   length -= sizeof(uint32_t) + hostKey->keyFormatId.length;

   //Parse Ed448 public key
   error = sshParseBinaryString(data, length, &hostKey->q);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + hostKey->q.length;
   length -= sizeof(uint32_t) + hostKey->q.length;

   //Malformed host key?
   if(length != 0)
      return ERROR_INVALID_SYNTAX;

   //The public key consists of 57 octets
   if(hostKey->q.length != ED448_PUBLIC_KEY_LEN)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Decode SSH public key file (SSH2 or OpenSSH format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH public key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodePublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;

   //Decode SSH public key file (SSH2 format)
   error = sshDecodeSsh2PublicKeyFile(input, inputLen, output, outputLen);

   //Check status code
   if(error)
   {
      //Decode SSH public key file (OpenSSH format)
      error = sshDecodeOpenSshPublicKeyFile(input, inputLen, output, outputLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Decode SSH public key file (SSH2 format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH public key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodeSsh2PublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;
   int_t i;
   int_t n;
   bool_t separatorChar;
   bool_t backslashChar;
   bool_t continuationLine;
   const char_t *p;

   //The first line of a conforming key file must be a begin marker (refer to
   //RFC 4716, section 3.2)
   i = sshSearchMarker(input, inputLen, "---- BEGIN SSH2 PUBLIC KEY ----", 31);
   //Begin marker not found?
   if(i < 0)
      return ERROR_INVALID_SYNTAX;

   //Advance the pointer over the marker
   i += 31;

   //The last line of a conforming key file must be an end marker (refer to
   //RFC 4716, section 3.2)
   n = sshSearchMarker(input + i, inputLen - i, "---- END SSH2 PUBLIC KEY ----", 29);
   //End marker not found?
   if(n < 0)
      return ERROR_INVALID_SYNTAX;

   //Point to the key file header
   p = input + i;
   i = 0;

   //Initialize flags
   separatorChar = FALSE;
   backslashChar = FALSE;
   continuationLine = FALSE;

   //The key file header section consists of multiple lines
   while(i < n)
   {
      //End of line detected?
      if(p[i] == '\n' || (i + 1) == n)
      {
         //A line that is not a continuation line and that has no ':' in it
         //is the first line of the Base64-encoded body (refer to RFC 4716,
         //section 3.3)
         if(!continuationLine && !separatorChar)
         {
            break;
         }

         //A line is continued if the last character in the line is a '\'
         continuationLine = backslashChar;

         //Reset flags
         separatorChar = FALSE;
         backslashChar = FALSE;

         //Point to the next line
         p += i + 1;
         n -= i + 1;
         i = 0;
      }
      else
      {
         //Check current character
         if(p[i] == ':')
         {
            //A ':' character is used to separate header name and value
            separatorChar = TRUE;
            backslashChar = FALSE;
         }
         else if(p[i] == '\\')
         {
            //A backslash is used at the end of a continued line
            backslashChar = TRUE;
         }
         else if(p[i] == '\r')
         {
            //Discard current character
         }
         else
         {
            //The current line is not a continued line
            backslashChar = FALSE;
         }

         //Next character
         i++;
      }
   }

   //The body of the SSH public key file is Base64-encoded
   error = base64Decode(p, n, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Decode SSH public key file (OpenSSH format)
 * @param[in] input SSH public key file to decode
 * @param[in] inputLen Length of the SSH public key file to decode
 * @param[out] output Pointer to the decoded data (optional parameter)
 * @param[out] outputLen Length of the decoded data
 **/

error_t sshDecodeOpenSshPublicKeyFile(const char_t *input, size_t inputLen,
   uint8_t *output, size_t *outputLen)
{
   error_t error;
   uint_t i;
   uint_t n;
   const char_t *p;

   //OpenSSH public key files use a proprietary format
   if(inputLen > 7 && !osStrncmp(input, "ssh-rsa", 7))
   {
      //RSA host key
      i = 7;
   }
   else if(inputLen > 7 && !osStrncmp(input, "ssh-dss", 7))
   {
      //DSA host key
      i = 7;
   }
   else if(inputLen > 19 && !osStrncmp(input, "ecdsa-sha2-nistp256", 19))
   {
      //ECDSA with NIST P-256 host key
      i = 19;
   }
   else if(inputLen > 19 && !osStrncmp(input, "ecdsa-sha2-nistp384", 19))
   {
      //ECDSA with NIST P-384 host key
      i = 19;
   }
   else if(inputLen > 19 && !osStrncmp(input, "ecdsa-sha2-nistp521", 19))
   {
      //ECDSA with NIST P-521 host key
      i = 19;
   }
   else if(inputLen > 11 && !osStrncmp(input, "ssh-ed25519", 11))
   {
      //Ed25519 host key
      i = 11;
   }
   else if(inputLen > 9 && !osStrncmp(input, "ssh-ed448", 9))
   {
      //Ed448 host key
      i = 9;
   }
   else
   {
      //Invalid host key
      return ERROR_INVALID_SYNTAX;
   }

   //The public key identifier must be followed by a whitespace character
   if(input[i] != ' ' && input[i] != '\t')
      return ERROR_INVALID_SYNTAX;

   //Skip whitespace characters
   while(i < inputLen && (input[i] == ' ' || input[i] == '\t'))
   {
      i++;
   }

   //Point to the public key
   p = input + i;
   n = inputLen - i;
   i = 0;

   //The public key may be followed by a whitespace character and a comment
   while(i < n && (p[i] != ' ' && p[i] != '\t'))
   {
      i++;
   }

   //The public key is Base64-encoded
   error = base64Decode(p, i, output, outputLen);
   //Failed to decode the file?
   if(error)
      return error;

   //Sanity check
   if(*outputLen == 0)
      return ERROR_INVALID_SYNTAX;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Search a string for a given marker
 * @param[in] s String to search
 * @param[in] sLen Length of the string to search
 * @param[in] marker String containing the marker to search for
 * @param[in] markerLen Length of the marker
 * @return The index of the first occurrence of the marker in the string,
 *   or -1 if the marker does not appear in the string
 **/

int_t sshSearchMarker(const char_t *s, size_t sLen, const char_t *marker,
   size_t markerLen)
{
   size_t i;
   size_t j;

   //Loop through input string
   for(i = 0; (i + markerLen) <= sLen; i++)
   {
      //Compare current substring with the given marker
      for(j = 0; j < markerLen; j++)
      {
         if(s[i + j] != marker[j])
            break;
      }

      //Check whether the marker has been found
      if(j == markerLen)
         return i;
   }

   //The marker does not appear in the string
   return -1;
}

#endif
