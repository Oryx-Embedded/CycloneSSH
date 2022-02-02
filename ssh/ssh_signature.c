/**
 * @file ssh_signature.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation and verification
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
#include "ssh/ssh_signature.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_misc.h"
#include "pkix/pem_import.h"
#include "ecc/ecdsa.h"
#include "ecc/eddsa.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const void *message, size_t messageLen, uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Total length of the signature encoding
   *written = 0;

   //Format public key format identifier
   error = sshFormatString(publicKeyAlgo, p, &n);

   //Check status code
   if(!error)
   {
      //Point to the signature blob
      p += n;
      *written += n;

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
      //Valid signature generation callback function?
      if(connection->context->signGenCallback != NULL)
      {
         //Invoke user-defined callback
         error = connection->context->signGenCallback(connection,
            publicKeyAlgo, hostKey, message, messageLen, p, &n);
      }
      else
#endif
      {
         //No callback function registered
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO ||
      error == ERROR_UNKOWN_KEY)
   {
#if (SSH_RSA_SUPPORT == ENABLED)
      //RSA public key algorithm?
      if(sshCompareAlgo(publicKeyAlgo, "ssh-rsa") ||
         sshCompareAlgo(publicKeyAlgo, "rsa-sha2-256") ||
         sshCompareAlgo(publicKeyAlgo, "rsa-sha2-512"))
      {
         //Generate an RSA signature using the host private key
         error = sshGenerateRsaSignature(connection, publicKeyAlgo, hostKey,
            message, messageLen, p, &n);
      }
      else
#endif
#if (SSH_DSA_SUPPORT == ENABLED)
      //DSA public key algorithm?
      if(sshCompareAlgo(publicKeyAlgo, "ssh-dss"))
      {
         //Generate a DSA signature using the host private key
         error = sshGenerateDsaSignature(connection, publicKeyAlgo, hostKey,
            message, messageLen, p, &n);
      }
      else
#endif
#if (SSH_ECDSA_SUPPORT == ENABLED)
      //ECDSA public key algorithm?
      if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp256") ||
         sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp384") ||
         sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp521"))
      {
         //Generate an ECDSA signature using the host private key
         error = sshGenerateEcdsaSignature(connection, publicKeyAlgo, hostKey,
            message, messageLen, p, &n);
      }
      else
#endif
#if (SSH_ED25519_SUPPORT == ENABLED)
      //Ed22519 public key algorithm?
      if(sshCompareAlgo(publicKeyAlgo, "ssh-ed25519"))
      {
         //Generate an EdDSA signature using the host private key
         error = sshGenerateEd25519Signature(connection, publicKeyAlgo, hostKey,
            message, messageLen, p, &n);
      }
      else
#endif
#if (SSH_ED448_SUPPORT == ENABLED)
      //Ed448 public key algorithm?
      if(sshCompareAlgo(publicKeyAlgo, "ssh-ed448"))
      {
         //Generate an EdDSA signature using the host private key
         error = sshGenerateEd448Signature(connection, publicKeyAlgo, hostKey,
            message, messageLen, p, &n);
      }
      else
#endif
      //Unknown host key type?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Check status code
   if(!error)
   {
      //Total number of bytes that have been written
      *written += n;
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateRsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const void *message, size_t messageLen, uint8_t *p, size_t *written)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const HashAlgo *hashAlgo;
   uint8_t digest[SSH_MAX_HASH_DIGEST_SIZE];

#if (SSH_SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ssh-rsa"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "rsa-sha2-256"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "rsa-sha2-512"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown host key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      RsaPrivateKey rsaPrivateKey;

      //Initialize RSA private key
      rsaInitPrivateKey(&rsaPrivateKey);

      //Initialize hash context
      hashAlgo->init(&connection->hashContext);

      //Client operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Digest the length field
         hashAlgo->update(&connection->hashContext, temp, sizeof(temp));

         //Digest the session identifier
         hashAlgo->update(&connection->hashContext, connection->sessionId,
            connection->sessionIdLen);
      }

      //Digest the message
      hashAlgo->update(&connection->hashContext, message, messageLen);
      hashAlgo->final(&connection->hashContext, digest);

      //Import RSA private key
      error = pemImportRsaPrivateKey(hostKey->privateKey,
         hostKey->privateKeyLen, &rsaPrivateKey);

      //Check status code
      if(!error)
      {
         //Generate RSA signature
         error = rsassaPkcs1v15Sign(&rsaPrivateKey, hashAlgo, digest, p + 4, &n);
      }

      //Check status code
      if(!error)
      {
         //The resulting RSA signature blob is encoded as a string
         STORE32BE(n, p);
         //Total number of bytes that have been written
         *written = sizeof(uint32_t) + n;
      }

      //Free previously allocated memory
      rsaFreePrivateKey(&rsaPrivateKey);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateDsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const void *message, size_t messageLen, uint8_t *p, size_t *written)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   DsaPrivateKey dsaPrivateKey;
   DsaSignature dsaSignature;
   SshContext *context;
   Sha1Context *hashContext;
   uint8_t digest[SHA1_DIGEST_SIZE];

   //Point to the SSH context
   context = connection->context;
   //Point to the hash context
   hashContext = &connection->hashContext.sha1Context;

   //Initialize DSA private key
   dsaInitPrivateKey(&dsaPrivateKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Initialize hash context
   sha1Init(hashContext);

   //Client operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      uint8_t temp[4];

      //Encode the length of the session identifier as a 32-bit
      //big-endian integer
      STORE32BE(connection->sessionIdLen, temp);

      //Digest the length field
      sha1Update(hashContext, temp, sizeof(temp));

      //Digest the session identifier
      sha1Update(hashContext, connection->sessionId,
         connection->sessionIdLen);
   }

   //Digest the message
   sha1Update(hashContext, message, messageLen);
   sha1Final(hashContext, digest);

   //Import DSA private key
   error = pemImportDsaPrivateKey(hostKey->privateKey, hostKey->privateKeyLen,
      &dsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Generate DSA signature
      error = dsaGenerateSignature(context->prngAlgo, context->prngContext,
         &dsaPrivateKey, digest, SHA1_DIGEST_SIZE, &dsaSignature);
   }

   //Check status code
   if(!error)
   {
      //The DSA signature blob contains R followed by S (which are 160-bit
      //integers)
      n = mpiGetByteLength(&dsaPrivateKey.params.q);

      //Encode integer R
      error = mpiExport(&dsaSignature.r, p + 4, n, MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Encode integer S
      error = mpiExport(&dsaSignature.s, p + n + 4, n, MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //The resulting DSA signature blob is encoded as a string
      STORE32BE(2 * n, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + 2 * n;
   }

   //Free previously allocated resources
   dsaFreePrivateKey(&dsaPrivateKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEcdsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const void *message, size_t messageLen, uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;
   size_t rLen;
   size_t sLen;
   const HashAlgo *hashAlgo;
   SshContext *context;
   uint8_t digest[SSH_MAX_HASH_DIGEST_SIZE];

   //Point to the SSH context
   context = connection->context;

#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp256"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp384"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp521"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      EcDomainParameters ecParams;
      EcPrivateKey ecPrivateKey;
      EcdsaSignature ecdsaSignature;

      //Initialize EC domain parameters
      ecInitDomainParameters(&ecParams);
      //Initialize EC private key
      ecInitPrivateKey(&ecPrivateKey);
      //Initialize ECDSA signature
      ecdsaInitSignature(&ecdsaSignature);

      //Initialize hash context
      hashAlgo->init(&connection->hashContext);

      //Client operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Digest the length field
         hashAlgo->update(&connection->hashContext, temp, sizeof(temp));

         //Digest the session identifier
         hashAlgo->update(&connection->hashContext, connection->sessionId,
            connection->sessionIdLen);
      }

      //Digest the message
      hashAlgo->update(&connection->hashContext, message, messageLen);
      hashAlgo->final(&connection->hashContext, digest);

      //Import EC domain parameters
      error = pemImportEcParameters(hostKey->privateKey, hostKey->privateKeyLen,
         &ecParams);

      //Check status code
      if(!error)
      {
         //Import EC private key
         error = pemImportEcPrivateKey(hostKey->privateKey,
            hostKey->privateKeyLen, &ecPrivateKey);
      }

      //Check status code
      if(!error)
      {
         //Generate ECDSA signature
         error = ecdsaGenerateSignature(context->prngAlgo,
            context->prngContext, &ecParams, &ecPrivateKey, digest,
            hashAlgo->digestSize, &ecdsaSignature);
      }

      //Check status code
      if(!error)
      {
         //Encode integer R
         error = sshFormatMpint(&ecdsaSignature.r, p + 4, &rLen);
      }

      //Check status code
      if(!error)
      {
         //Encode integer S
         error = sshFormatMpint(&ecdsaSignature.s, p + rLen + 4, &sLen);
      }

      //Check status code
      if(!error)
      {
         //The resulting ECDSA signature blob is encoded as a string
         STORE32BE(rLen + sLen, p);
         //Total number of bytes that have been written
         *written = sizeof(uint32_t) + rLen + sLen;
      }

      //Free previously allocated resources
      ecFreeDomainParameters(&ecParams);
      ecFreePrivateKey(&ecPrivateKey);
      ecdsaFreeSignature(&ecdsaSignature);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEd25519Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const void *message, size_t messageLen, uint8_t *p, size_t *written)
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EddsaPrivateKey eddsaPrivateKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];
   uint8_t d[ED25519_PRIVATE_KEY_LEN];

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&eddsaPrivateKey);

   //Import EdDSA private key
   error = pemImportEddsaPrivateKey(hostKey->privateKey, hostKey->privateKeyLen,
      &eddsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Retrieve private key
      error = mpiExport(&eddsaPrivateKey.d, d, ED25519_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Client operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = connection->sessionId;
         messageChunks[1].length = connection->sessionIdLen;
         messageChunks[2].buffer = message;
         messageChunks[2].length = messageLen;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message;
         messageChunks[0].length = messageLen;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Generate Ed25519 signature (PureEdDSA mode)
      error = ed25519GenerateSignatureEx(d, NULL, messageChunks, NULL, 0, 0,
         p + 4);

      //The Ed25519 signature consists of 32 octets
      n = ED25519_SIGNATURE_LEN;
   }

   //Check status code
   if(!error)
   {
      //The resulting EdDSA signature is encoded as a string
      STORE32BE(n, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + n;
   }

   //Free previously allocated resources
   eddsaFreePrivateKey(&eddsaPrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] message Pointer to the message to be signed
 * @param[in] messageLen Length of the message, in bytes
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEd448Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const void *message, size_t messageLen, uint8_t *p, size_t *written)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EddsaPrivateKey eddsaPrivateKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];
   uint8_t d[ED448_PRIVATE_KEY_LEN];

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&eddsaPrivateKey);

   //Import EdDSA private key
   error = pemImportEddsaPrivateKey(hostKey->privateKey, hostKey->privateKeyLen,
      &eddsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Retrieve private key
      error = mpiExport(&eddsaPrivateKey.d, d, ED448_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Client operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
      {
         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = connection->sessionId;
         messageChunks[1].length = connection->sessionIdLen;
         messageChunks[2].buffer = message;
         messageChunks[2].length = messageLen;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message;
         messageChunks[0].length = messageLen;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Generate Ed448 signature (PureEdDSA mode)
      error = ed448GenerateSignatureEx(d, NULL, messageChunks, NULL, 0, 0,
         p + 4);

      //The Ed448 signature consists of 57 octets
      n = ED448_SIGNATURE_LEN;
   }

   //Check status code
   if(!error)
   {
      //The resulting EdDSA signature is encoded as a string
      STORE32BE(n, p);
      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + n;
   }

   //Free previously allocated resources
   eddsaFreePrivateKey(&eddsaPrivateKey);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t sshVerifySignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const uint8_t *message, size_t messageLen,
   const SshBinaryString *signature)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   SshString keyFormatId;
   SshBinaryString signatureBlob;

   //Point to the first field of the signature
   p = signature->value;
   n = signature->length;

   //Decode key format identifier
   error = sshParseString(p, n, &keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + keyFormatId.length;
   n -= sizeof(uint32_t) + keyFormatId.length;

   //Decode signature blob
   error = sshParseBinaryString(p, n, &signatureBlob);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + signatureBlob.length;
   n -= sizeof(uint32_t) + signatureBlob.length;

   //Malformed signature?
   if(n != 0)
      return ERROR_INVALID_MESSAGE;

   //Unexpected key format identifier?
   if(!sshCompareStrings(&keyFormatId, publicKeyAlgo))
      return ERROR_INVALID_SIGNATURE;

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature verification callback function?
   if(connection->context->signVerifyCallback != NULL)
   {
      //Invoke user-defined callback
      error = connection->context->signVerifyCallback(connection,
         publicKeyAlgo, publicKeyBlob, message, messageLen, &signatureBlob);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO)
   {
#if (SSH_RSA_SUPPORT == ENABLED)
      //RSA public key algorithm?
      if(sshCompareString(publicKeyAlgo, "ssh-rsa") ||
         sshCompareString(publicKeyAlgo, "rsa-sha2-256") ||
         sshCompareString(publicKeyAlgo, "rsa-sha2-512"))
      {
         //RSA signature verification
         error = sshVerifyRsaSignature(connection, publicKeyAlgo,
            publicKeyBlob, message, messageLen, &signatureBlob);
      }
      else
#endif
#if (SSH_DSA_SUPPORT == ENABLED)
      //DSA public key algorithm?
      if(sshCompareString(publicKeyAlgo, "ssh-dss"))
      {
         //DSA signature verification
         error = sshVerifyDsaSignature(connection, publicKeyAlgo,
            publicKeyBlob, message, messageLen, &signatureBlob);
      }
      else
#endif
#if (SSH_ECDSA_SUPPORT == ENABLED)
      //ECDSA public key algorithm?
      if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256") ||
         sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384") ||
         sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521"))
      {
         //ECDSA signature verification
         error = sshVerifyEcdsaSignature(connection, publicKeyAlgo,
            publicKeyBlob, message, messageLen, &signatureBlob);
      }
      else
#endif
#if (SSH_ED25519_SUPPORT == ENABLED)
      //Ed22519 public key algorithm?
      if(sshCompareString(publicKeyAlgo, "ssh-ed25519"))
      {
         //Ed25519 signature verification
         error = sshVerifyEd25519Signature(connection, publicKeyAlgo,
            publicKeyBlob, message, messageLen, &signatureBlob);
      }
      else
#endif
#if (SSH_ED448_SUPPORT == ENABLED)
      //Ed448 public key algorithm?
      if(sshCompareString(publicKeyAlgo, "ssh-ed448"))
      {
         //Ed448 signature verification
         error = sshVerifyEd448Signature(connection, publicKeyAlgo,
            publicKeyBlob, message, messageLen, &signatureBlob);
      }
      else
#endif
      //Unknown public key algorithm?
      {
         //Report an error
         error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyRsaSignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const uint8_t *message, size_t messageLen,
   const SshBinaryString *signatureBlob)
{
#if (SSH_RSA_SUPPORT == ENABLED)
   error_t error;
   const HashAlgo *hashAlgo;
   uint8_t digest[SSH_MAX_HASH_DIGEST_SIZE];

#if (SSH_SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ssh-rsa"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "rsa-sha2-256"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "rsa-sha2-512"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      SshRsaHostKey hostKey;
      RsaPublicKey rsaPublicKey;

      //Initialize RSA public key
      rsaInitPublicKey(&rsaPublicKey);

      //Initialize hash context
      hashAlgo->init(&connection->hashContext);

      //Server operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Digest the length field
         hashAlgo->update(&connection->hashContext, temp, sizeof(temp));

         //Digest the session identifier
         hashAlgo->update(&connection->hashContext, connection->sessionId,
            connection->sessionIdLen);
      }

      //Digest the message
      hashAlgo->update(&connection->hashContext, message, messageLen);
      hashAlgo->final(&connection->hashContext, digest);

      //Parse RSA host key structure
      error = sshParseRsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
         &hostKey);

      //Check status code
      if(!error)
      {
         //Import RSA public key
         error = sshImportRsaHostKey(&hostKey, &rsaPublicKey);
      }

      //Check status code
      if(!error)
      {
         //Verify RSA signature
         error = rsassaPkcs1v15Verify(&rsaPublicKey, hashAlgo, digest,
            signatureBlob->value, signatureBlob->length);
      }

      //Free previously allocated resources
      rsaFreePublicKey(&rsaPublicKey);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief DSA signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyDsaSignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const uint8_t *message, size_t messageLen,
   const SshBinaryString *signatureBlob)
{
#if (SSH_DSA_SUPPORT == ENABLED)
   error_t error;
   SshDsaHostKey hostKey;
   DsaPublicKey dsaPublicKey;
   DsaSignature dsaSignature;
   Sha1Context *hashContext;
   uint8_t digest[SHA1_DIGEST_SIZE];

   //Point to the hash context
   hashContext = &connection->hashContext.sha1Context;

   //The DSA signature blob contains R followed by S (which are 160-bit
   //integers)
   if(signatureBlob->length != 40)
      return ERROR_INVALID_MESSAGE;

   //Initialize DSA public key
   dsaInitPublicKey(&dsaPublicKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Initialize hash context
   sha1Init(hashContext);

   //Server operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
   {
      uint8_t temp[4];

      //Encode the length of the session identifier as a 32-bit
      //big-endian integer
      STORE32BE(connection->sessionIdLen, temp);

      //Digest the length field
      sha1Update(hashContext, temp, sizeof(temp));

      //Digest the session identifier
      sha1Update(hashContext, connection->sessionId,
         connection->sessionIdLen);
   }

   //Digest the message
   sha1Update(hashContext, message, messageLen);
   sha1Final(hashContext, digest);

   //Parse DSA host key structure
   error = sshParseDsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
      &hostKey);

   //Check status code
   if(!error)
   {
      //Import DSA public key
      error = sshImportDsaHostKey(&hostKey, &dsaPublicKey);
   }

   //Check status code
   if(!error)
   {
      //Import integer R
      error = mpiImport(&dsaSignature.r, signatureBlob->value, 20,
         MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Import integer S
      error = mpiImport(&dsaSignature.s, signatureBlob->value + 20, 20,
         MPI_FORMAT_BIG_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Verify DSA signature
      error = dsaVerifySignature(&dsaPublicKey, digest, SHA1_DIGEST_SIZE,
         &dsaSignature);
   }

   //Free previously allocated resources
   dsaFreePublicKey(&dsaPublicKey);
   dsaFreeSignature(&dsaSignature);

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEcdsaSignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const uint8_t *message, size_t messageLen,
   const SshBinaryString *signatureBlob)
{
#if (SSH_ECDSA_SUPPORT == ENABLED)
   error_t error;
   SshEcdsaSignature signature;
   const HashAlgo *hashAlgo;
   uint8_t digest[SSH_MAX_HASH_DIGEST_SIZE];

#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      hashAlgo = NULL;
   }

   //Make sure the hash algorithm is supported
   if(hashAlgo != NULL)
   {
      SshEcdsaHostKey hostKey;
      EcDomainParameters ecParams;
      EcPublicKey ecPublicKey;
      EcdsaSignature ecdsaSignature;

      //Initialize EC domain parameters
      ecInitDomainParameters(&ecParams);
      //Initialize EC public key
      ecInitPublicKey(&ecPublicKey);
      //Initialize ECDSA signature
      ecdsaInitSignature(&ecdsaSignature);

      //Initialize hash context
      hashAlgo->init(&connection->hashContext);

      //Server operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Digest the length field
         hashAlgo->update(&connection->hashContext, temp, sizeof(temp));

         //Digest the session identifier
         hashAlgo->update(&connection->hashContext, connection->sessionId,
            connection->sessionIdLen);
      }

      //Digest the message
      hashAlgo->update(&connection->hashContext, message, messageLen);
      hashAlgo->final(&connection->hashContext, digest);

      //Parse ECDSA host key structure
      error = sshParseEcdsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
         &hostKey);

      //Check status code
      if(!error)
      {
         //Import ECDSA public key
         error = sshImportEcdsaHostKey(&hostKey, &ecParams, &ecPublicKey);
      }

      //Check status code
      if(!error)
      {
         //Parse ECDSA signature structure
         error = sshParseEcdsaSignature(signatureBlob->value,
            signatureBlob->length, &signature);
      }

      //Check status code
      if(!error)
      {
         //Import integer R
         error = mpiImport(&ecdsaSignature.r, signature.r.value,
            signature.r.length, MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Import integer S
         error = mpiImport(&ecdsaSignature.s, signature.s.value,
            signature.s.length, MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Verify ECDSA signature
         error = ecdsaVerifySignature(&ecParams, &ecPublicKey, digest,
            hashAlgo->digestSize, &ecdsaSignature);
      }

      //Free previously allocated resources
      ecFreeDomainParameters(&ecParams);
      ecFreePublicKey(&ecPublicKey);
      ecdsaFreeSignature(&ecdsaSignature);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed25519 signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEd25519Signature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const uint8_t *message, size_t messageLen,
   const SshBinaryString *signatureBlob)
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   error_t error;
   SshEddsaHostKey hostKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];

   //The Ed25519 signature consists of 32 octets
   if(signatureBlob->length != ED25519_SIGNATURE_LEN)
      return ERROR_INVALID_SIGNATURE;

   //Parse Ed25519 host key structure
   error = sshParseEd25519HostKey(publicKeyBlob->value, publicKeyBlob->length,
      &hostKey);

   //Check status
   if(!error)
   {
      //Server operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
      {
         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = connection->sessionId;
         messageChunks[1].length = connection->sessionIdLen;
         messageChunks[2].buffer = message;
         messageChunks[2].length = messageLen;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message;
         messageChunks[0].length = messageLen;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Verify Ed25519 signature (PureEdDSA mode)
      error = ed25519VerifySignatureEx(hostKey.q.value, messageChunks, NULL,
         0, 0, signatureBlob->value);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Ed448 signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] message Message whose signature is to be verified
 * @param[in] messageLen Length of the message, in bytes
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEd448Signature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const uint8_t *message, size_t messageLen,
   const SshBinaryString *signatureBlob)
{
#if (SSH_ED448_SUPPORT == ENABLED)
   error_t error;
   SshEddsaHostKey hostKey;
   EddsaMessageChunk messageChunks[4];
   uint8_t temp[4];

   //The Ed448 signature consists of 57 octets
   if(signatureBlob->length != ED448_SIGNATURE_LEN)
      return ERROR_INVALID_SIGNATURE;

   //Parse Ed448 host key structure
   error = sshParseEd448HostKey(publicKeyBlob->value, publicKeyBlob->length,
      &hostKey);

   //Check status
   if(!error)
   {
      //Server operation mode?
      if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
      {
         //Encode the length of the session identifier as a 32-bit
         //big-endian integer
         STORE32BE(connection->sessionIdLen, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = connection->sessionId;
         messageChunks[1].length = connection->sessionIdLen;
         messageChunks[2].buffer = message;
         messageChunks[2].length = messageLen;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message;
         messageChunks[0].length = messageLen;
         messageChunks[1].buffer = NULL;
         messageChunks[1].length = 0;
      }

      //Verify Ed448 signature (PureEdDSA mode)
      error = ed448VerifySignatureEx(hostKey.q.value, messageChunks, NULL,
         0, 0, signatureBlob->value);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


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
#if (SSH_ECDSA_SUPPORT == ENABLED)
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
#if (SSH_ECDSA_SUPPORT == ENABLED)
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
