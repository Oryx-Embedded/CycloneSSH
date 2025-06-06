/**
 * @file ssh_key_export.c
 * @brief SSH key file export functions
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
 * @param[out] output Buffer where to store the SSH public key file (optional parameter)
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH format)
 * @return Error code
 **/

error_t sshExportRsaPublicKey(const RsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
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
   error = sshEncodePublicKeyFile("ssh-rsa", output, n, output, &n, format);
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
 * @param[out] output Buffer where to store the SSH public key file (optional parameter)
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH format)
 * @return Error code
 **/

error_t sshExportDsaPublicKey(const DsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
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
   error = sshEncodePublicKeyFile("ssh-dss", output, n, output, &n, format);
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
 * @param[in] publicKey ECDSA public key
 * @param[out] output Buffer where to store the SSH public key file (optional parameter)
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH format)
 * @return Error code
 **/

error_t sshExportEcdsaPublicKey(const EcPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const char_t *keyFormatId;

   //Check parameters
   if(publicKey == NULL || written == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid ECDSA public key?
   if(publicKey->curve == NULL)
      return ERROR_UNSUPPORTED_ELLIPTIC_CURVE;

   //Check elliptic curve
   if(osStrcmp(publicKey->curve->name, "secp256r1") == 0)
   {
      //Select NIST P-256 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp256";
   }
   else if(osStrcmp(publicKey->curve->name, "secp384r1") == 0)
   {
      //Select NIST P-384 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp384";
   }
   else if(osStrcmp(publicKey->curve->name, "secp521r1") == 0)
   {
      //Select NIST P-521 elliptic curve
      keyFormatId = "ecdsa-sha2-nistp521";
   }
   else
   {
      //Unknown host key algorithm
      return ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Format ECDSA host key structure
   error = sshFormatEcdsaPublicKey(publicKey, (uint8_t *) output, &n);
   //Any error to report?
   if(error)
      return error;

   //Convert the host key structure to the desired format
   error = sshEncodePublicKeyFile(keyFormatId, output, n, output, &n, format);
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
 * @param[out] output Buffer where to store the SSH public key file (optional parameter)
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH format)
 * @return Error code
 **/

error_t sshExportEd25519PublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)

{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
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
   error = sshEncodePublicKeyFile("ssh-ed25519", output, n, output, &n, format);
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
 * @param[out] output Buffer where to store the SSH public key file (optional parameter)
 * @param[out] written Length of the resulting SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH format)
 * @return Error code
 **/

error_t sshExportEd448PublicKey(const EddsaPublicKey *publicKey,
   char_t *output, size_t *written, SshPublicKeyFormat format)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
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
   error = sshEncodePublicKeyFile("ssh-ed448", output, n, output, &n, format);
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
 * @brief Export an RSA private key to SSH private key file format
 * @param[in] privateKey RSA private key
 * @param[out] output Buffer where to store the SSH private key file
 * @param[out] written Length of the resulting SSH private key file
 * @param[in] format Desired output format (OpenSSH format only)
 * @return Error code
 **/

error_t sshExportRsaPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written, SshPrivateKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PRIVATE_KEY_FORMAT_OPENSSH ||
      format == SSH_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      //Export RSA private key file (OpenSSH format)
      error = sshExportOpenSshRsaPrivateKey(privateKey, output, written);
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
 * @brief Export a DSA private key to SSH private key file format
 * @param[in] privateKey DSA private key
 * @param[out] output Buffer where to store the SSH private key file
 * @param[out] written Length of the resulting SSH private key file
 * @param[in] format Desired output format (OpenSSH format only)
 * @return Error code
 **/

error_t sshExportDsaPrivateKey(const DsaPrivateKey *privateKey,
   char_t *output, size_t *written, SshPrivateKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PRIVATE_KEY_FORMAT_OPENSSH ||
      format == SSH_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      //Export DSA private key file (OpenSSH format)
      error = sshExportOpenSshDsaPrivateKey(privateKey, output, written);
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
 * @brief Export an ECDSA private key to SSH private key file format
 * @param[in] privateKey ECDSA private key
 * @param[out] output Buffer where to store the SSH private key file
 * @param[out] written Length of the resulting SSH private key file
 * @param[in] format Desired output format (OpenSSH format only)
 * @return Error code
 **/

error_t sshExportEcdsaPrivateKey(const EcPrivateKey *privateKey,
   char_t *output, size_t *written, SshPrivateKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PRIVATE_KEY_FORMAT_OPENSSH ||
      format == SSH_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      //Export ECDSA private key file (OpenSSH format)
      error = sshExportOpenSshEcdsaPrivateKey(privateKey, output, written);
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
 * @brief Export an Ed25519 private key to SSH private key file format
 * @param[in] privateKey Ed25519 private key
 * @param[out] output Buffer where to store the SSH private key file
 * @param[out] written Length of the resulting SSH private key file
 * @param[in] format Desired output format (OpenSSH format only)
 * @return Error code
 **/

error_t sshExportEd25519PrivateKey(const EddsaPrivateKey *privateKey,
   char_t *output, size_t *written, SshPrivateKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PRIVATE_KEY_FORMAT_OPENSSH ||
      format == SSH_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      //Export Ed25519 private key file (OpenSSH format)
      error = sshExportOpenSshEd25519PrivateKey(privateKey, output, written);
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
 * @brief Export an Ed448 private key to SSH private key file format
 * @param[in] privateKey Ed448 private key
 * @param[out] output Buffer where to store the SSH private key file
 * @param[out] written Length of the resulting SSH private key file
 * @param[in] format Desired output format (OpenSSH format only)
 * @return Error code
 **/

error_t sshExportEd448PrivateKey(const EddsaPrivateKey *privateKey,
   char_t *output, size_t *written, SshPrivateKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PRIVATE_KEY_FORMAT_OPENSSH ||
      format == SSH_PRIVATE_KEY_FORMAT_DEFAULT)
   {
      //Export Ed448 private key file (OpenSSH format)
      error = sshExportOpenSshEd448PrivateKey(privateKey, output, written);
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
 * @brief Export an RSA private key to OpenSSH private key file format
 * @param[in] privateKey RSA private key
 * @param[out] output Buffer where to store the OpenSSH private key file
 * @param[out] written Length of the resulting OpenSSH private key file
 * @return Error code
 **/

error_t sshExportOpenSshRsaPrivateKey(const RsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   RsaPublicKey publicKey;

   //Initialize variables
   p = (uint8_t *) output;
   length = 0;

   //Format private key header
   error = sshFormatOpenSshPrivateKeyHeader(p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p = SSH_INC_POINTER(p, n);
   length += n;

   //The pair of numbers (n, e) form the RSA public key
   publicKey.n = privateKey->n;
   publicKey.e = privateKey->e;

   //Format 'publickey' field
   error = sshFormatRsaPublicKey(&publicKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Point to the next field
   p = SSH_INC_POINTER(p, sizeof(uint32_t) + n);
   length += sizeof(uint32_t) + n;

   //Format 'encrypted' field
   error = sshFormatOpenSshRsaPrivateKey(privateKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Total length of the private key structure
   length += sizeof(uint32_t) + n;

   //Convert the private key structure to OpenSSH format
   error = sshEncodeOpenSshPrivateKeyFile(output, length, output, &n);
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
 * @brief Export a DSA private key to OpenSSH private key file format
 * @param[in] privateKey DSA private key
 * @param[out] output Buffer where to store the OpenSSH private key file
 * @param[out] written Length of the resulting OpenSSH private key file
 * @return Error code
 **/

error_t sshExportOpenSshDsaPrivateKey(const DsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   DsaPublicKey publicKey;

   //Initialize variables
   p = (uint8_t *) output;
   length = 0;

   //Format private key header
   error = sshFormatOpenSshPrivateKeyHeader(p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p = SSH_INC_POINTER(p, n);
   length += n;

   //These four parameters (p, q, g and y) form the DSA public key
   publicKey.params = privateKey->params;
   publicKey.y = privateKey->y;

   //Format 'publickey' field
   error = sshFormatDsaPublicKey(&publicKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Point to the next field
   p = SSH_INC_POINTER(p, sizeof(uint32_t) + n);
   length += sizeof(uint32_t) + n;

   //Format 'encrypted' field
   error = sshFormatOpenSshDsaPrivateKey(privateKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Total length of the private key structure
   length += sizeof(uint32_t) + n;

   //Convert the private key structure to OpenSSH format
   error = sshEncodeOpenSshPrivateKeyFile(output, length, output, &n);
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
 * @brief Export an ECDSA private key to OpenSSH private key file format
 * @param[in] privateKey ECDSA private key
 * @param[out] output Buffer where to store the OpenSSH private key file
 * @param[out] written Length of the resulting OpenSSH private key file
 * @return Error code
 **/

error_t sshExportOpenSshEcdsaPrivateKey(const EcPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;

   //Initialize variables
   p = (uint8_t *) output;
   length = 0;

   //Format private key header
   error = sshFormatOpenSshPrivateKeyHeader(p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p = SSH_INC_POINTER(p, n);
   length += n;

   //Format 'publickey' field
   error = sshFormatEcdsaPublicKey(&privateKey->q,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Point to the next field
   p = SSH_INC_POINTER(p, sizeof(uint32_t) + n);
   length += sizeof(uint32_t) + n;

   //Format 'encrypted' field
   error = sshFormatOpenSshEcdsaPrivateKey(privateKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Total length of the private key structure
   length += sizeof(uint32_t) + n;

   //Convert the private key structure to OpenSSH format
   error = sshEncodeOpenSshPrivateKeyFile(output, length, output, &n);
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
 * @brief Export an Ed25519 private key to OpenSSH private key file format
 * @param[in] privateKey Ed25519 private key
 * @param[out] output Buffer where to store the OpenSSH private key file
 * @param[out] written Length of the resulting OpenSSH private key file
 * @return Error code
 **/

error_t sshExportOpenSshEd25519PrivateKey(const EddsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;

   //Initialize variables
   p = (uint8_t *) output;
   length = 0;

   //Format private key header
   error = sshFormatOpenSshPrivateKeyHeader(p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p = SSH_INC_POINTER(p, n);
   length += n;

   //Format 'publickey' field
   error = sshFormatEd25519PublicKey(&privateKey->q,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Point to the next field
   p = SSH_INC_POINTER(p, sizeof(uint32_t) + n);
   length += sizeof(uint32_t) + n;

   //Format 'encrypted' field
   error = sshFormatOpenSshEd25519PrivateKey(privateKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Total length of the private key structure
   length += sizeof(uint32_t) + n;

   //Convert the private key structure to OpenSSH format
   error = sshEncodeOpenSshPrivateKeyFile(output, length, output, &n);
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
 * @brief Export an Ed448 private key to OpenSSH private key file format
 * @param[in] privateKey Ed448 private key
 * @param[out] output Buffer where to store the OpenSSH private key file
 * @param[out] written Length of the resulting OpenSSH private key file
 * @return Error code
 **/

error_t sshExportOpenSshEd448PrivateKey(const EddsaPrivateKey *privateKey,
   char_t *output, size_t *written)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;

   //Initialize variables
   p = (uint8_t *) output;
   length = 0;

   //Format private key header
   error = sshFormatOpenSshPrivateKeyHeader(p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p = SSH_INC_POINTER(p, n);
   length += n;

   //Format 'publickey' field
   error = sshFormatEd448PublicKey(&privateKey->q,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Point to the next field
   p = SSH_INC_POINTER(p, sizeof(uint32_t) + n);
   length += sizeof(uint32_t) + n;

   //Format 'encrypted' field
   error = sshFormatOpenSshEd448PrivateKey(privateKey,
      SSH_INC_POINTER(p, sizeof(uint32_t)), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   if(p != NULL)
   {
      STORE32BE(n, p);
   }

   //Total length of the private key structure
   length += sizeof(uint32_t) + n;

   //Convert the private key structure to OpenSSH format
   error = sshEncodeOpenSshPrivateKeyFile(output, length, output, &n);
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
 * @param[in] keyFormatId Key format identifier
 * @param[in] input Host key structure to encode
 * @param[in] inputLen Length of the host key structure to encode
 * @param[out] output SSH public key file (optional parameter)
 * @param[out] outputLen Length of the SSH public key file
 * @param[in] format Desired output format (SSH2 or OpenSSH format)
 **/

error_t sshEncodePublicKeyFile(const char_t *keyFormatId, const void *input,
   size_t inputLen, char_t *output, size_t *outputLen, SshPublicKeyFormat format)
{
   error_t error;

   //Check output format
   if(format == SSH_PUBLIC_KEY_FORMAT_SSH2)
   {
      //Encode SSH public key file (SSH2 format)
      error = sshEncodeSsh2PublicKeyFile(input, inputLen, output, outputLen);
   }
   else if(format == SSH_PUBLIC_KEY_FORMAT_OPENSSH ||
      format == SSH_PUBLIC_KEY_FORMAT_DEFAULT)
   {
      //Encode SSH public key file (OpenSSH format)
      error = sshEncodeOpenSshPublicKeyFile(keyFormatId, input, inputLen,
         output, outputLen);
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
   if(outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(input == NULL && output != NULL)
      return ERROR_INVALID_PARAMETER;

   //Each line in the body must not be longer than 72 8-bit bytes excluding
   //line termination characters (refer to RFC 4716, section 3.4)
   base64EncodeMultiline(input, inputLen, output, &n, 70);

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
 * @param[in] keyFormatId Key format identifier
 * @param[in] input Host key structure to encode
 * @param[in] inputLen Length of the host key structure to encode
 * @param[out] output SSH public key file (optional parameter)
 * @param[out] outputLen Length of the SSH public key file
 **/

error_t sshEncodeOpenSshPublicKeyFile(const char_t *keyFormatId,
   const void *input, size_t inputLen, char_t *output, size_t *outputLen)
{
   size_t n;
   size_t keyFormatIdLen;

   //Check parameters
   if(keyFormatId == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(input == NULL && output != NULL)
      return ERROR_INVALID_PARAMETER;

   //Get the length of the key format identifier
   keyFormatIdLen = osStrlen(keyFormatId);

   //Encode the host key structure using Base64
   base64Encode(input, inputLen, output, &n);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting certificate file without copying any data
   if(output != NULL)
   {
      //Make room for the identifier string
      osMemmove(output + keyFormatIdLen + 1, output, n + 1);
      //Copy identifier string
      osMemcpy(output, keyFormatId, keyFormatIdLen);
      //The identifier must be followed by a whitespace character
      output[keyFormatIdLen] = ' ';
   }

   //Consider the length of the identifier string
   n += keyFormatIdLen + 1;

   //Total number of bytes that have been written
   *outputLen = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Encode SSH private key file (OpenSSH format)
 * @param[in] input Private key structure to encode
 * @param[in] inputLen Length of the private key structure to encode
 * @param[out] output SSH private key file (optional parameter)
 * @param[out] outputLen Length of the SSH private key file
 **/

error_t sshEncodeOpenSshPrivateKeyFile(const void *input, size_t inputLen,
   char_t *output, size_t *outputLen)
{
   size_t n;

   //Check parameters
   if(outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Sanity check
   if(input == NULL && output != NULL)
      return ERROR_INVALID_PARAMETER;

   //Encode the private key structure using Base64
   base64EncodeMultiline(input, inputLen, output, &n, 70);

   //If the output parameter is NULL, then the function calculates the length
   //of the resulting SSH private key file without copying any data
   if(output != NULL)
   {
      //Make room for the begin marker
      osMemmove(output + 37, output, n);

      //The first line of the private key file must be a begin marker
      osMemcpy(output, "-----BEGIN OPENSSH PRIVATE KEY-----\r\n", 37);

      //The last line of the private key file must be an end marker
      osStrcpy(output + n + 37, "\r\n-----END OPENSSH PRIVATE KEY-----\r\n");
   }

   //Consider the length of the markers
   n += osStrlen("-----BEGIN OPENSSH PRIVATE KEY-----\r\n");
   n += osStrlen("\r\n-----END OPENSSH PRIVATE KEY-----\r\n");

   //Total number of bytes that have been written
   *outputLen = n;

   //Successful processing
   return NO_ERROR;
}

#endif
