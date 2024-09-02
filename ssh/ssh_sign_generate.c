/**
 * @file ssh_sign_generate.c
 * @brief RSA/DSA/ECDSA/EdDSA signature generation
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_sign_generate.h"
#include "ssh/ssh_sign_misc.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;
   SshString name;
   const char_t *signFormatId;

   //Total length of the signature encoding
   *written = 0;

   //Get the name of the public key algorithm
   name.value = publicKeyAlgo;
   name.length = osStrlen(publicKeyAlgo);

   //Public key/certificate formats that do not explicitly specify a signature
   //format identifier must use the public key/certificate format identifier
   //as the signature identifier (refer to RFC 4253, section 6.6)
   signFormatId = sshGetSignFormatId(&name);

   //Valid signature format identifier?
   if(signFormatId != NULL)
   {
      //Format signature format identifier
      error = sshFormatString(signFormatId, p, &n);

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
               signFormatId, hostKey, sessionId, message, p, &n);
         }
         else
#endif
         {
            //No callback function registered
            error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
         }

         //Check status code
         if(error == ERROR_UNSUPPORTED_SIGNATURE_ALGO ||
            error == ERROR_UNKOWN_KEY)
         {
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
            //RSA signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-rsa") ||
               sshCompareAlgo(signFormatId, "rsa-sha2-256") ||
               sshCompareAlgo(signFormatId, "rsa-sha2-512"))
            {
               //Generate an RSA signature using the host private key
               error = sshGenerateRsaSignature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
            //DSA signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-dss"))
            {
               //Generate a DSA signature using the host private key
               error = sshGenerateDsaSignature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
            //ECDSA signature algorithm?
            if(sshCompareAlgo(signFormatId, "ecdsa-sha2-nistp256") ||
               sshCompareAlgo(signFormatId, "ecdsa-sha2-nistp384") ||
               sshCompareAlgo(signFormatId, "ecdsa-sha2-nistp521"))
            {
               //Generate an ECDSA signature using the host private key
               error = sshGenerateEcdsaSignature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
            //Ed25519 signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-ed25519"))
            {
               //Generate an EdDSA signature using the host private key
               error = sshGenerateEd25519Signature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
            //Ed448 signature algorithm?
            if(sshCompareAlgo(signFormatId, "ssh-ed448"))
            {
               //Generate an EdDSA signature using the host private key
               error = sshGenerateEd448Signature(connection, signFormatId,
                  hostKey, sessionId, message, p, &n);
            }
            else
#endif
            //Unknown signature algorithm?
            {
               //Report an error
               error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
            }
         }
      }

      //Check status code
      if(!error)
      {
         //Total number of bytes that have been written
         *written += n;
      }
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_SIGNATURE_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief RSA signature generation
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] hostKey Pointer to the signer's host key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateRsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const HashAlgo *hashAlgo;
   HashContext hashContext;

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
      hashAlgo->init(&hashContext);

      //Valid session identifier?
      if(sessionId != NULL)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Digest the length field
         hashAlgo->update(&hashContext, temp, sizeof(temp));
         //Digest the session identifier
         hashAlgo->update(&hashContext, sessionId->value, sessionId->length);
      }

      //Digest the message
      hashAlgo->update(&hashContext, message->value, message->length);
      hashAlgo->final(&hashContext, NULL);

      //Import RSA private key
      error = sshImportRsaPrivateKey(hostKey->privateKey,
         hostKey->privateKeyLen, hostKey->password, &rsaPrivateKey);

      //Check status code
      if(!error)
      {
         //Generate RSA signature
         error = rsassaPkcs1v15Sign(&rsaPrivateKey, hashAlgo,
            hashContext.digest, p + 4, &n);
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
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateDsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   SshContext *context;
   DsaPrivateKey dsaPrivateKey;
   DsaSignature dsaSignature;
   Sha1Context sha1Context;

   //Initialize variable
   n = 0;

   //Point to the SSH context
   context = connection->context;

   //Initialize DSA private key
   dsaInitPrivateKey(&dsaPrivateKey);
   //Initialize DSA signature
   dsaInitSignature(&dsaSignature);

   //Initialize hash context
   sha1Init(&sha1Context);

   //Valid session identifier?
   if(sessionId != NULL)
   {
      uint8_t temp[4];

      //Encode the length of the session identifier as a 32-bit big-endian
      //integer
      STORE32BE(sessionId->length, temp);

      //Digest the length field
      sha1Update(&sha1Context, temp, sizeof(temp));
      //Digest the session identifier
      sha1Update(&sha1Context, sessionId->value, sessionId->length);
   }

   //Digest the message
   sha1Update(&sha1Context, message->value, message->length);
   sha1Final(&sha1Context, NULL);

   //Import DSA private key
   error = sshImportDsaPrivateKey(hostKey->privateKey,
      hostKey->privateKeyLen, hostKey->password, &dsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Generate DSA signature
      error = dsaGenerateSignature(context->prngAlgo, context->prngContext,
         &dsaPrivateKey, sha1Context.digest, SHA1_DIGEST_SIZE, &dsaSignature);
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
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEcdsaSignature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t rLen;
   size_t sLen;
   SshContext *context;
   const HashAlgo *hashAlgo;
   const EcCurveInfo *curveInfo;
   HashContext hashContext;

   //Point to the SSH context
   context = connection->context;

#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp256"))
   {
      //Select the relevant curve and hash algorithm
      curveInfo = SECP256R1_CURVE;
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp384"))
   {
      //Select the relevant curve and hash algorithm
      curveInfo = SECP384R1_CURVE;
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 public key algorithm?
   if(sshCompareAlgo(publicKeyAlgo, "ecdsa-sha2-nistp521"))
   {
      //Select the relevant curve and hash algorithm
      curveInfo = SECP521R1_CURVE;
      hashAlgo = SHA512_HASH_ALGO;
   }
   else
#endif
   //Unknown public key algorithm?
   {
      //Just for sanity
      curveInfo = NULL;
      hashAlgo = NULL;
   }

   //Valid parameters?
   if(curveInfo != NULL && hashAlgo != NULL)
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
      hashAlgo->init(&hashContext);

      //Valid session identifier?
      if(sessionId != NULL)
      {
         uint8_t temp[4];

         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Digest the length field
         hashAlgo->update(&hashContext, temp, sizeof(temp));
         //Digest the session identifier
         hashAlgo->update(&hashContext, sessionId->value, sessionId->length);
      }

      //Digest the message
      hashAlgo->update(&hashContext, message->value, message->length);
      hashAlgo->final(&hashContext, NULL);

      //Import EC domain parameters
      error = ecLoadDomainParameters(&ecParams, curveInfo);

      //Check status code
      if(!error)
      {
         //Import ECDSA private key
         error = sshImportEcdsaPrivateKey(hostKey->privateKey,
            hostKey->privateKeyLen, hostKey->password, &ecPrivateKey);
      }

      //Check status code
      if(!error)
      {
         //Generate ECDSA signature
         error = ecdsaGenerateSignature(context->prngAlgo, context->prngContext,
            &ecParams, &ecPrivateKey, hashContext.digest, hashAlgo->digestSize,
            &ecdsaSignature);
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
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEd25519Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EddsaPrivateKey eddsaPrivateKey;
   DataChunk messageChunks[4];
   uint8_t temp[4];
   uint8_t d[ED25519_PRIVATE_KEY_LEN];

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&eddsaPrivateKey);

   //Import Ed25519 private key
   error = sshImportEd25519PrivateKey(hostKey->privateKey,
      hostKey->privateKeyLen, hostKey->password, &eddsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Retrieve raw private key
      error = mpiExport(&eddsaPrivateKey.d, d, ED25519_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Valid session identifier?
      if(sessionId != NULL)
      {
         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = sessionId->value;
         messageChunks[1].length = sessionId->length;
         messageChunks[2].buffer = message->value;
         messageChunks[2].length = message->length;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;
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
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Pointer to the message to be signed
 * @param[out] p Output stream where to write the signature
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshGenerateEd448Signature(SshConnection *connection,
   const char_t *publicKeyAlgo, const SshHostKey *hostKey,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   uint8_t *p, size_t *written)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   EddsaPrivateKey eddsaPrivateKey;
   DataChunk messageChunks[4];
   uint8_t temp[4];
   uint8_t d[ED448_PRIVATE_KEY_LEN];

   //Initialize EdDSA private key
   eddsaInitPrivateKey(&eddsaPrivateKey);

   //Import Ed448 private key
   error = sshImportEd448PrivateKey(hostKey->privateKey,
      hostKey->privateKeyLen, hostKey->password, &eddsaPrivateKey);

   //Check status code
   if(!error)
   {
      //Retrieve raw private key
      error = mpiExport(&eddsaPrivateKey.d, d, ED448_PRIVATE_KEY_LEN,
         MPI_FORMAT_LITTLE_ENDIAN);
   }

   //Check status code
   if(!error)
   {
      //Valid session identifier?
      if(sessionId != NULL)
      {
         //Encode the length of the session identifier as a 32-bit big-endian
         //integer
         STORE32BE(sessionId->length, temp);

         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = temp;
         messageChunks[0].length = sizeof(temp);
         messageChunks[1].buffer = sessionId->value;
         messageChunks[1].length = sessionId->length;
         messageChunks[2].buffer = message->value;
         messageChunks[2].length = message->length;
         messageChunks[3].buffer = NULL;
         messageChunks[3].length = 0;
      }
      else
      {
         //The message fits in a single chunk
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;
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

#endif
