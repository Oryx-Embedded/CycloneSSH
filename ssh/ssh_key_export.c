/**
 * @file ssh_key_export.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_key_export.h"
#include "ssh/ssh_key_parse.h"
#include "ssh/ssh_key_format.h"
#include "ssh/ssh_misc.h"
#include "encoding/base64.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Export an RSA public key to SSH public key file format
 * @param[in] publicKey RSA public key
 * @param[out] output Buffer where to store the SSH public key file
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH)
 * @return Error code
 **/

error_t sshExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format RSA host key structure
   error = sshFormatRsaPublicKey(publicKey, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Convert the host key structure to the desired format
   error = sshEncodePublicKeyFile(output, n, output, &n, format);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a DSA public key to SSH public key file format
 * @param[in] publicKey DSA public key
 * @param[out] output Buffer where to store the SSH public key file
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH)
 * @return Error code
 **/

error_t sshExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format DSA host key structure
   error = sshFormatDsaPublicKey(publicKey, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Convert the host key structure to the desired format
   error = sshEncodePublicKeyFile(output, n, output, &n, format);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export an ECDSA public key to SSH public key file format
 * @param[in] params EC domain parameters
 * @param[in] publicKey ECDSA public key
 * @param[out] output Buffer where to store the SSH public key file
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH)
 * @return Error code
 **/

error_t sshExportEcdsaPublicKey(const EcDomainParameters *params,
   const EcPublicKey *publicKey, char_t *output, size_t *written,
   SshPublicKeyFormat format)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format ECDSA host key structure
   error = sshFormatEcdsaPublicKey(params, publicKey, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Convert the host key structure to the desired format
   error = sshEncodePublicKeyFile(output, n, output, &n, format);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a Ed25519 public key to SSH public key file format
 * @param[in] publicKey Ed25519 public key
 * @param[out] output Buffer where to store the SSH public key file
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH)
 * @return Error code
 **/

error_t sshExportEd25519PublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)

{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format Ed25519 host key structure
   error = sshFormatEd25519PublicKey(publicKey, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Convert the host key structure to the desired format
   error = sshEncodePublicKeyFile(output, n, output, &n, format);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Export a Ed448 public key to SSH public key file format
 * @param[in] publicKey Ed448 public key
 * @param[out] output Buffer where to store the SSH public key file
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH)
 * @return Error code
 **/

error_t sshExportEd448PublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Format Ed448 host key structure
   error = sshFormatEd448PublicKey(publicKey, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Convert the host key structure to the desired format
   error = sshEncodePublicKeyFile(output, n, output, &n, format);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Encode SSH public key file (SSH2 or OpenSSH format)
 * @param[in] input Host key structure to encode
 * @param[in] inputLen Length of the host key structure to encode
 * @param[out] output SSH public key file (optional parameter)
 * @param[out] outputLen Length of the SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH)
 **/

error_t sshEncodePublicKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen, SshPublicKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PUBLIC_KEY_FORMAT_SSH2)
   {
      //Encode SSH public key file (SSH2 format)
      error = sshEncodeSsh2PublicKeyFile(input, inputLen, output, outputLen);
   }
   else if(format == SSH_PUBLIC_KEY_FORMAT_OPENSSH)
   {
      //Encode SSH public key file (OpenSSH format)
      error = sshEncodeOpenSshPublicKeyFile(input, inputLen, output, outputLen);
   }
   else
   {
      //Invalid format
      error = ERROR_INVALID_PARAMETER;
   }

   //Return error code
   return error;
}


/**
 * @brief Encode SSH public key file (SSH2 format)
 * @param[in] input Host key structure to encode
 * @param[in] inputLen Length of the host key structure to encode
 * @param[out] output SSH public key file (optional parameter)
 * @param[out] outputLen Length of the SSH public key file
 **/

error_t sshEncodeSsh2PublicKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen)
{
   size_t n;

   //Check parameters
   if(input == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Encode the host key structure using Base64
   base64Encode(input, inputLen, output, &n);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting SSH public key file without copying any data
   if(output != NULL)
   {
      //Make room for the begin marker
      osMemmove(output + 33, output, n);

      //The first line of a conforming key file must be a begin marker (refer
      //to RFC 4716, section 3.2)
      osMemcpy(output, "---- BEGIN SSH2 PUBLIC KEY ----\r\n", 33);

      //The last line of a conforming key file must be an end marker (refer to
      //RFC 4716, section 3.2)
      osStrcpy(output + n + 33, "\r\n---- END SSH2 PUBLIC KEY ----\r\n");
   }

   //Consider the length of the markers
   n += osStrlen("---- BEGIN SSH2 PUBLIC KEY ----\r\n");
   n += osStrlen("\r\n---- END SSH2 PUBLIC KEY ----\r\n");

   //Total number of bytes that have been written
   *outputLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Encode SSH public key file (OpenSSH format)
 * @param[in] input Host key structure to encode
 * @param[in] inputLen Length of the host key structure to encode
 * @param[out] output SSH public key file (optional parameter)
 * @param[out] outputLen Length of the SSH public key file
 **/

error_t sshEncodeOpenSshPublicKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen)
{
   error_t error;
   size_t n;
   SshString keyFormatId;
   uint8_t identifier[40];

   //Check parameters
   if(input == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Parse host key structure
   error = sshParseHostKey(input, inputLen, &keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Sanity check
   if(keyFormatId.length > sizeof(identifier))
      return ERROR_WRONG_IDENTIFIER;

   //Save key format identifier
   osMemcpy(identifier, keyFormatId.value, keyFormatId.length);

   //Encode the host key structure using Base64
   base64Encode(input, inputLen, output, &n);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting certificate file without copying any data
   if(output != NULL)
   {
      //Make room for the identifier string
      osMemmove(output + keyFormatId.length + 1, output, n + 1);
      //Copy identifier string
      osMemcpy(output, identifier, keyFormatId.length);
      //The identifier must be followed by a whitespace character
      output[keyFormatId.length] = ' ';
   }

   //Consider the length of the identifier string
   n += keyFormatId.length + 1;

   //Total number of bytes that have been written
   *outputLen = n;

   //Successful processing
   return NO_ERROR;
}

#endif
