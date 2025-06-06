/**
 * @file ssh_sign_verify.c
 * @brief RSA/DSA/ECDSA/EdDSA signature verification
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
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_cert_import.h"
#include "ssh/ssh_sign_verify.h"
#include "ssh/ssh_sign_misc.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Signature verification
 * @param[in] connection Pointer to the SSH connection
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signature Signature to be verified
 * @return Error code
 **/

error_t sshVerifySignature(SshConnection *connection,
   const SshString *publicKeyAlgo, const SshBinaryString *publicKeyBlob,
   const SshBinaryString *sessionId, const SshBinaryString *message,
   const SshBinaryString *signature)
{
   error_t error;
   size_t n;
   const uint8_t *p;
   SshString keyFormatId;
   SshString signFormatId;
   SshBinaryString signatureBlob;
   const char_t *expectedKeyFormatId;
   const char_t *expectedSignFormatId;

   //Point to the first field of the signature
   p = signature->value;
   n = signature->length;

   //Decode signature format identifier
   error = sshParseString(p, n, &signFormatId);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + signFormatId.length;
   n -= sizeof(uint32_t) + signFormatId.length;

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

   //Extract key format identifier from public key blob
   error = sshParseString(publicKeyBlob->value, publicKeyBlob->length,
      &keyFormatId);
   //Any error to report?
   if(error)
      return error;

   //Each public key algorithm is associated with a particular key format
   expectedKeyFormatId = sshGetKeyFormatId(publicKeyAlgo);

   //Inconsistent key format identifier?
   if(!sshCompareString(&keyFormatId, expectedKeyFormatId))
      return ERROR_INVALID_SIGNATURE;

   //Public key/certificate formats that do not explicitly specify a signature
   //format identifier must use the public key/certificate format identifier
   //as the signature identifier (refer to RFC 4253, section 6.6)
   expectedSignFormatId = sshGetSignFormatId(publicKeyAlgo);

   //Inconsistent signature format identifier?
   if(!sshCompareString(&signFormatId, expectedSignFormatId))
      return ERROR_INVALID_SIGNATURE;

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Valid signature verification callback function?
   if(connection->context->signVerifyCallback != NULL)
   {
      //Invoke user-defined callback
      error = connection->context->signVerifyCallback(connection,
         publicKeyAlgo, publicKeyBlob, sessionId, message, &signatureBlob);
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
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
      //RSA signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-rsa") ||
         sshCompareString(&signFormatId, "rsa-sha2-256") ||
         sshCompareString(&signFormatId, "rsa-sha2-512"))
      {
         //RSA signature verification
         error = sshVerifyRsaSignature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
      //DSA signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-dss"))
      {
         //DSA signature verification
         error = sshVerifyDsaSignature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
      //ECDSA signature algorithm?
      if(sshCompareString(&signFormatId, "ecdsa-sha2-nistp256") ||
         sshCompareString(&signFormatId, "ecdsa-sha2-nistp384") ||
         sshCompareString(&signFormatId, "ecdsa-sha2-nistp521"))
      {
         //ECDSA signature verification
         error = sshVerifyEcdsaSignature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
      //Ed25519 signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-ed25519"))
      {
         //Ed25519 signature verification
         error = sshVerifyEd25519Signature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
      //Ed448 signature algorithm?
      if(sshCompareString(&signFormatId, "ssh-ed448"))
      {
         //Ed448 signature verification
         error = sshVerifyEd448Signature(publicKeyAlgo, publicKeyBlob,
            sessionId, message, &signatureBlob);
      }
      else
#endif
      //Unknown public key type?
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
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyRsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_RSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   const HashAlgo *hashAlgo;
   HashContext hashContext;
   uint8_t digest[SSH_MAX_HASH_DIGEST_SIZE];

#if (SSH_SHA1_SUPPORT == ENABLED)
   //RSA with SHA-1 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ssh-rsa") ||
      sshCompareString(publicKeyAlgo, "ssh-rsa-cert") ||
      sshCompareString(publicKeyAlgo, "ssh-rsa-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA1_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   //RSA with SHA-256 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "rsa-sha2-256") ||
      sshCompareString(publicKeyAlgo, "rsa-sha2-256-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   //RSA with SHA-512 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "rsa-sha2-512") ||
      sshCompareString(publicKeyAlgo, "rsa-sha2-512-cert-v01@openssh.com"))
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
      RsaPublicKey rsaPublicKey;

      //Initialize RSA public key
      rsaInitPublicKey(&rsaPublicKey);

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
      hashAlgo->final(&hashContext, digest);

#if (SSH_CERT_SUPPORT == ENABLED)
      //RSA certificate?
      if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
      {
         SshCertificate cert;

         //Parse RSA certificate structure
         error = sshParseCertificate(publicKeyBlob->value,
            publicKeyBlob->length, &cert);

         //Check status
         if(!error)
         {
            //Import RSA public key
            error = sshImportRsaCertPublicKey(&rsaPublicKey, &cert);
         }
      }
      else
#endif
      //RSA public key?
      {
         SshRsaHostKey hostKey;

         //Parse RSA host key structure
         error = sshParseRsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
            &hostKey);

         //Check status code
         if(!error)
         {
            //Import RSA public key
            error = sshImportRsaHostKey(&rsaPublicKey, &hostKey);
         }
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
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyDsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_DSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   DsaPublicKey dsaPublicKey;
   DsaSignature dsaSignature;
   Sha1Context sha1Context;
   uint8_t digest[SHA1_DIGEST_SIZE];

   //The DSA signature blob contains R followed by S (which are 160-bit
   //integers)
   if(signatureBlob->length == (2 * SHA1_DIGEST_SIZE))
   {
      //Initialize DSA public key
      dsaInitPublicKey(&dsaPublicKey);
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
      sha1Final(&sha1Context, digest);

#if (SSH_CERT_SUPPORT == ENABLED)
      //DSA certificate?
      if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
      {
         SshCertificate cert;

         //Parse DSA certificate structure
         error = sshParseCertificate(publicKeyBlob->value,
            publicKeyBlob->length, &cert);

         //Check status
         if(!error)
         {
            //Import DSA public key
            error = sshImportDsaCertPublicKey(&dsaPublicKey, &cert);
         }
      }
      else
#endif
      //DSA public key?
      {
         SshDsaHostKey hostKey;

         //Parse DSA host key structure
         error = sshParseDsaHostKey(publicKeyBlob->value, publicKeyBlob->length,
            &hostKey);

         //Check status code
         if(!error)
         {
            //Import DSA public key
            error = sshImportDsaHostKey(&dsaPublicKey, &hostKey);
         }
      }

      //Check status code
      if(!error)
      {
         //Import integer R
         error = mpiImport(&dsaSignature.r, signatureBlob->value,
            SHA1_DIGEST_SIZE, MPI_FORMAT_BIG_ENDIAN);
      }

      //Check status code
      if(!error)
      {
         //Import integer S
         error = mpiImport(&dsaSignature.s, signatureBlob->value +
            SHA1_DIGEST_SIZE, SHA1_DIGEST_SIZE, MPI_FORMAT_BIG_ENDIAN);
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
   }
   else
   {
      //The length of the signature is not acceptable
      error = ERROR_INVALID_MESSAGE;
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief ECDSA signature verification
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEcdsaSignature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_ECDSA_SIGN_SUPPORT == ENABLED)
   error_t error;
   SshEcdsaSignature signature;
   const HashAlgo *hashAlgo;
   HashContext hashContext;
   uint8_t digest[SSH_MAX_HASH_DIGEST_SIZE];

#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   //ECDSA with NIST P-256 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256-cert") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp256-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA256_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   //ECDSA with NIST P-384 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384-cert") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp384-cert-v01@openssh.com"))
   {
      //Select the relevant hash algorithm
      hashAlgo = SHA384_HASH_ALGO;
   }
   else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   //ECDSA with NIST P-521 public key algorithm?
   if(sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521-cert") ||
      sshCompareString(publicKeyAlgo, "ecdsa-sha2-nistp521-cert-v01@openssh.com"))
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
      EcPublicKey ecPublicKey;
      EcdsaSignature ecdsaSignature;

      //Initialize ECDSA public key
      ecInitPublicKey(&ecPublicKey);
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
      hashAlgo->final(&hashContext, digest);

#if (SSH_CERT_SUPPORT == ENABLED)
      //ECDSA certificate?
      if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
      {
         SshCertificate cert;

         //Parse ECDSA certificate structure
         error = sshParseCertificate(publicKeyBlob->value,
            publicKeyBlob->length, &cert);

         //Check status
         if(!error)
         {
            //Import ECDSA public key
            error = sshImportEcdsaCertPublicKey(&ecPublicKey, &cert);
         }
      }
      else
#endif
      //ECDSA public key?
      {
         SshEcdsaHostKey hostKey;

         //Parse ECDSA host key structure
         error = sshParseEcdsaHostKey(publicKeyBlob->value,
            publicKeyBlob->length, &hostKey);

         //Check status code
         if(!error)
         {
            //Import ECDSA public key
            error = sshImportEcdsaHostKey(&ecPublicKey, &hostKey);
         }
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
         error = ecdsaImportSignature(&ecdsaSignature, ecPublicKey.curve,
            signature.r.value, signature.r.length, ECDSA_SIGNATURE_FORMAT_RAW_R);
      }

      //Check status code
      if(!error)
      {
         //Import integer S
         error = ecdsaImportSignature(&ecdsaSignature, ecPublicKey.curve,
            signature.s.value, signature.s.length, ECDSA_SIGNATURE_FORMAT_RAW_S);
      }

      //Check status code
      if(!error)
      {
         //Verify ECDSA signature
         error = ecdsaVerifySignature(&ecPublicKey, digest,
            hashAlgo->digestSize, &ecdsaSignature);
      }

      //Free previously allocated resources
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
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEd25519Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_ED25519_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *ed25519PublicKey;
   uint_t numMessageChunks;
   DataChunk messageChunks[3];
   uint8_t temp[4];

   //The Ed25519 signature shall consist of 32 octets
   if(signatureBlob->length != ED25519_SIGNATURE_LEN)
      return ERROR_INVALID_SIGNATURE;

#if (SSH_CERT_SUPPORT == ENABLED)
   //Ed25519 certificate?
   if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
   {
      SshCertificate cert;

      //Parse EdDSA certificate structure
      error = sshParseCertificate(publicKeyBlob->value, publicKeyBlob->length,
         &cert);

      //Check status
      if(!error)
      {
         //The Ed25519 public key consists of 32 octets
         ed25519PublicKey = cert.publicKey.eddsaPublicKey.q.value;
      }
   }
   else
#endif
   //Ed25519 public key?
   {
      SshEddsaHostKey hostKey;

      //Parse Ed25519 host key structure
      error = sshParseEd25519HostKey(publicKeyBlob->value,
         publicKeyBlob->length, &hostKey);

      //Check status
      if(!error)
      {
         //The Ed25519 public key consists of 32 octets
         ed25519PublicKey = hostKey.q.value;
      }
   }

   //Check status
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

         //Number of data chunks representing the message to be signed
         numMessageChunks = 3;
      }
      else
      {
         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;

         //The message fits in a single chunk
         numMessageChunks = 1;
      }

      //Verify Ed25519 signature (PureEdDSA mode)
      error = ed25519VerifySignatureEx(ed25519PublicKey, messageChunks,
         numMessageChunks, NULL, 0, 0, signatureBlob->value);
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
 * @param[in] publicKeyAlgo Public key algorithm
 * @param[in] publicKeyBlob Signer's public key
 * @param[in] sessionId Session identifier (optional parameter)
 * @param[in] message Message whose signature is to be verified
 * @param[in] signatureBlob Signature to be verified
 * @return Error code
 **/

error_t sshVerifyEd448Signature(const SshString *publicKeyAlgo,
   const SshBinaryString *publicKeyBlob, const SshBinaryString *sessionId,
   const SshBinaryString *message, const SshBinaryString *signatureBlob)
{
#if (SSH_ED448_SIGN_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *ed448PublicKey;
   uint_t numMessageChunks;
   DataChunk messageChunks[3];
   uint8_t temp[4];

   //The Ed448 signature shall consist of 57 octets
   if(signatureBlob->length != ED448_SIGNATURE_LEN)
      return ERROR_INVALID_SIGNATURE;

#if (SSH_CERT_SUPPORT == ENABLED)
   //Ed448 certificate?
   if(sshIsCertPublicKeyAlgo(publicKeyAlgo))
   {
      SshCertificate cert;

      //Parse EdDSA certificate structure
      error = sshParseCertificate(publicKeyBlob->value, publicKeyBlob->length,
         &cert);

      //Check status
      if(!error)
      {
         //The Ed448 public key consists of 57 octets
         ed448PublicKey = cert.publicKey.eddsaPublicKey.q.value;
      }
   }
   else
#endif
   //Ed448 public key?
   {
      SshEddsaHostKey hostKey;

      //Parse Ed448 host key structure
      error = sshParseEd448HostKey(publicKeyBlob->value,
         publicKeyBlob->length, &hostKey);

      //Check status
      if(!error)
      {
         //The Ed448 public key consists of 57 octets
         ed448PublicKey = hostKey.q.value;
      }
   }

   //Check status
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

         //Number of data chunks representing the message to be signed
         numMessageChunks = 3;
      }
      else
      {
         //Data to be signed is run through the EdDSA algorithm without
         //pre-hashing
         messageChunks[0].buffer = message->value;
         messageChunks[0].length = message->length;

         //The message fits in a single chunk
         numMessageChunks = 1;
      }

      //Verify Ed448 signature (PureEdDSA mode)
      error = ed448VerifySignatureEx(ed448PublicKey, messageChunks,
         numMessageChunks, NULL, 0, 0, signatureBlob->value);
   }

   //Return status code
   return error;
#else
   //Not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
