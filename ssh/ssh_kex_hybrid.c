/**
 * @file ssh_kex_hybrid.c
 * @brief Post-quantum hybrid key exchange
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
#include "ssh/ssh_transport.h"
#include "ssh/ssh_kex.h"
#include "ssh/ssh_kex_hybrid.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_key_material.h"
#include "ssh/ssh_exchange_hash.h"
#include "ssh/ssh_key_verify.h"
#include "ssh/ssh_cert_verify.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_HYBRID_KEX_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_KEX_HYBRID_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexHybridInit(SshConnection *connection)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Key exchange algorithms are formulated as key encapsulation mechanisms
   error = sshSelectKemAlgo(connection);

   //Check status code
   if(!error)
   {
      //Generate a post-quantum KEM key pair
      error = kemGenerateKeyPair(&connection->kemContext, context->prngAlgo,
         context->prngContext);
   }

   //Check status code
   if(!error)
   {
      //Select ECDH domain parameters
      error = sshSelectClassicalEcdhCurve(connection);
   }

   //Check status code
   if(!error)
   {
      //Generate a classical ECDH key pair
      error = sshGenerateClassicalEcdhKeyPair(connection);
   }

   //Check status code
   if(!error)
   {
      //Format SSH_MSG_KEX_HYBRID_INIT message
      error = sshFormatKexHybridInit(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_HYBRID_INIT message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The server responds with an SSH_MSG_KEX_HYBRID_REPLY message
      connection->state = SSH_CONN_STATE_KEX_HYBRID_REPLY;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEX_HYBRID_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexHybridReply(SshConnection *connection)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Generate a classical ECDH key pair
   error = sshGenerateClassicalEcdhKeyPair(connection);

   //Check status code
   if(!error)
   {
      //Format SSH_MSG_KEX_HYBRID_REPLY message
      error = sshFormatKexHybridReply(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_HYBRID_REPLY message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Key exchange ends by each side sending an SSH_MSG_NEWKEYS message
      connection->state = SSH_CONN_STATE_SERVER_NEW_KEYS;
   }

   //Return status code
   return error;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_HYBRID_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexHybridInit(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t m;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_HYBRID_INIT;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Get the length of the KEM public key
   m = connection->kemContext.kemAlgo->publicKeySize;

   //Format client's post-quantum public key (C_PQ)
   osMemcpy(p + sizeof(uint32_t), connection->kemContext.pk, m);

   //Format client's classical public key (C_CL)
   error = ecdhExportPublicKey(&connection->ecdhContext,
      p + sizeof(uint32_t) + m, &n, EC_PUBLIC_KEY_FORMAT_X963);
   //Any error to report?
   if(error)
      return error;

   //C_INIT is the concatenation of C_PQ and C_CL
   STORE32BE(m + n, p);

   //Total length of the message
   *length += sizeof(uint32_t) + m + n;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_HYBRID_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexHybridReply(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t m;
   size_t n;
   SshContext *context;
   HashContext hashContext;

   //Point to the SSH context
   context = connection->context;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_HYBRID_REPLY;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Format server's public host key (K_S)
   error = sshFormatHostKey(connection, p + sizeof(uint32_t), &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   *length += sizeof(uint32_t) + n;

   //Perform KEM encapsulation
   error = kemEncapsulate(&connection->kemContext, context->prngAlgo,
      context->prngContext, p + sizeof(uint32_t), connection->k);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the KEM ciphertext
   m = connection->kemContext.kemAlgo->ciphertextSize;
   //Get the length of the KEM shared secret
   connection->kLen = connection->kemContext.kemAlgo->sharedSecretSize;

   //The shared secret K is derived as the hash algorithm specified in the named
   //hybrid key exchange method name over the concatenation of K_PQ and K_CL
   connection->hashAlgo->init(&hashContext);
   connection->hashAlgo->update(&hashContext, connection->k, connection->kLen);

   //Format server's ephemeral public key (S_CL)
   error = ecdhExportPublicKey(&connection->ecdhContext,
      p + sizeof(uint32_t) + m, &n, EC_PUBLIC_KEY_FORMAT_X963);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with S_REPLY (concatenation of S_PQ and S_CL)
   error = sshUpdateExchangeHash(connection, p + sizeof(uint32_t), m + n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(m + n, p);

   //Point to the next field
   p += sizeof(uint32_t) + m + n;
   *length += sizeof(uint32_t) + m + n;

   //Compute the shared secret K_CL
   error = sshComputeClassicalEcdhSharedSecret(connection);
   //Any error to report?
   if(error)
      return error;

   //Derive the shared secret K = HASH(K_PQ, K_CL)
   connection->hashAlgo->update(&hashContext, connection->k, connection->kLen);
   connection->hashAlgo->final(&hashContext, connection->k + sizeof(uint32_t));

   //Log shared secret (for debugging purpose only)
   sshDumpKey(connection, "SHARED_SECRET", connection->k + sizeof(uint32_t),
      connection->hashAlgo->digestSize);

   //Convert K to string representation
   STORE32BE(connection->hashAlgo->digestSize, connection->k);
   connection->kLen = sizeof(uint32_t) + connection->hashAlgo->digestSize;

   //Update exchange hash H with K (shared secret)
   error = sshUpdateExchangeHashRaw(connection, connection->k,
      connection->kLen);
   //Any error to report?
   if(error)
      return error;

   //Compute the signature on the exchange hash
   error = sshGenerateExchangeHashSignature(connection, p + sizeof(uint32_t),
      &n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total length of the message
   *length += sizeof(uint32_t) + n;

   //Destroy classical and post-quantum private keys
   ecdhFree(&connection->ecdhContext);
   ecdhInit(&connection->ecdhContext);
   kemFree(&connection->kemContext);
   kemInit(&connection->kemContext, NULL);

   //Successful processing
   return NO_ERROR;
#else
   //Server operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_HYBRID_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexHybridInit(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   SshBinaryString clientInit;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_HYBRID_INIT message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_HYBRID_INIT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode C_INIT (concatenation of C_PQ and C_CL)
   error = sshParseBinaryString(p, length, &clientInit);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + clientInit.length;
   length -= sizeof(uint32_t) + clientInit.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Update exchange hash H with C_INIT (concatenation of C_PQ and C_CL)
   error = sshUpdateExchangeHash(connection, clientInit.value,
      clientInit.length);
   //Any error to report?
   if(error)
      return error;

   //Key exchange algorithms are formulated as key encapsulation mechanisms
   error = sshSelectKemAlgo(connection);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the KEM public key
   n = connection->kemContext.kemAlgo->publicKeySize;

   //Check the length of the C_INIT field
   if(clientInit.length < n)
      return ERROR_INVALID_MESSAGE;

   //Load client's post-quantum public key (C_PQ)
   error = kemLoadPublicKey(&connection->kemContext, clientInit.value);
   //Any error to report?
   if(error)
      return error;

   //Select ECDH domain parameters
   error = sshSelectClassicalEcdhCurve(connection);
   //Any error to report?
   if(error)
      return error;

   //Load client's classical public key (C_CL)
   error = ecdhImportPeerPublicKey(&connection->ecdhContext,
      clientInit.value + n, clientInit.length - n, EC_PUBLIC_KEY_FORMAT_X963);
   //Any error to report?
   if(error)
      return error;

   //The server responds with an SSH_MSG_KEX_HYBRID_REPLY message
   return sshSendKexHybridReply(connection);
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_HYBRID_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexHybridReply(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   const uint8_t *p;
   SshString hostKeyAlgo;
   SshBinaryString hostKey;
   SshBinaryString serverReply;
   SshBinaryString signature;
   SshContext *context;
   HashContext hashContext;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_HYBRID_REPLY message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_HYBRID_REPLY)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode server's public host key (K_S)
   error = sshParseBinaryString(p, length, &hostKey);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + hostKey.length;
   length -= sizeof(uint32_t) + hostKey.length;

   //Decode S_REPLY (concatenation of S_PQ and S_CL)
   error = sshParseBinaryString(p, length, &serverReply);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + serverReply.length;
   length -= sizeof(uint32_t) + serverReply.length;

   //Decode the signature field
   error = sshParseBinaryString(p, length, &signature);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + signature.length;
   length -= sizeof(uint32_t) + signature.length;

   //Malformed message?
   if(length != 0)
      return ERROR_INVALID_MESSAGE;

   //Get the selected server's host key algorithm
   hostKeyAlgo.value = connection->serverHostKeyAlgo;
   hostKeyAlgo.length = osStrlen(connection->serverHostKeyAlgo);

#if (SSH_CERT_SUPPORT == ENABLED)
   //Certificate-based authentication?
   if(sshIsCertPublicKeyAlgo(&hostKeyAlgo))
   {
      //Verify server's certificate
      error = sshVerifyServerCertificate(connection, &hostKeyAlgo, &hostKey);
   }
   else
#endif
   {
      //Verify server's host key
      error = sshVerifyServerHostKey(connection, &hostKeyAlgo, &hostKey);
   }

   //If the client fails to verify the server's host key, it should disconnect
   //from the server by sending an SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE message
   if(error)
      return ERROR_INVALID_KEY;

   //Update exchange hash H with K_S (server's public host key)
   error = sshUpdateExchangeHash(connection, hostKey.value, hostKey.length);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with C_INIT (concatenation of C_PQ and C_CL)
   error = sshDigestClientInit(connection);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with S_REPLY (concatenation of S_PQ and S_CL)
   error = sshUpdateExchangeHash(connection, serverReply.value,
      serverReply.length);
   //Any error to report?
   if(error)
      return error;

   //Get the length of the KEM ciphertext
   n = connection->kemContext.kemAlgo->ciphertextSize;
   //Get the length of the KEM shared secret
   connection->kLen = connection->kemContext.kemAlgo->sharedSecretSize;

   //Check the length of the S_REPLY field
   if(serverReply.length < n)
      return ERROR_INVALID_MESSAGE;

   //The client decapsulates the ciphertext by using its private key which
   //leads to K_PQ, a post-quantum shared secret
   error = kemDecapsulate(&connection->kemContext, serverReply.value,
      connection->k);
   //Any error to report?
   if(error)
      return error;

   //The shared secret K is derived as the hash algorithm specified in the named
   //hybrid key exchange method name over the concatenation of K_PQ and K_CL
   connection->hashAlgo->init(&hashContext);
   connection->hashAlgo->update(&hashContext, connection->k, connection->kLen);

   //Load server's classical public key (S_CL)
   error = ecdhImportPeerPublicKey(&connection->ecdhContext,
      serverReply.value + n, serverReply.length - n, EC_PUBLIC_KEY_FORMAT_X963);
   //Any error to report?
   if(error)
      return error;

   //Compute the classical shared secret K_CL
   error = sshComputeClassicalEcdhSharedSecret(connection);
   //Any error to report?
   if(error)
      return error;

   //Derive the shared secret K = HASH(K_PQ, K_CL)
   connection->hashAlgo->update(&hashContext, connection->k, connection->kLen);
   connection->hashAlgo->final(&hashContext, connection->k + sizeof(uint32_t));

   //Log shared secret (for debugging purpose only)
   sshDumpKey(connection, "SHARED_SECRET", connection->k + sizeof(uint32_t),
      connection->hashAlgo->digestSize);

   //Convert K to string representation
   STORE32BE(connection->hashAlgo->digestSize, connection->k);
   connection->kLen = sizeof(uint32_t) + connection->hashAlgo->digestSize;

   //Update exchange hash H with K (shared secret)
   error = sshUpdateExchangeHashRaw(connection, connection->k,
      connection->kLen);
   //Any error to report?
   if(error)
      return error;

   //Verify the signature on the exchange hash
   error = sshVerifyExchangeHashSignature(connection, &hostKey, &signature);
   //Any error to report?
   if(error)
      return error;

   //Destroy classical and post-quantum private keys
   ecdhFree(&connection->ecdhContext);
   ecdhInit(&connection->ecdhContext);
   kemFree(&connection->kemContext);
   kemInit(&connection->kemContext, NULL);

   //Key exchange ends by each side sending an SSH_MSG_NEWKEYS message
   return sshSendNewKeys(connection);
#else
   //Client operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse PQ-hybrid specific messages
 * @param[in] connection Pointer to the SSH connection
 * @param[in] type SSH message type
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexHybridMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length)
{
   error_t error;

#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Client operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check message type
      if(type == SSH_MSG_KEX_HYBRID_REPLY)
      {
         //Parse SSH_MSG_KEX_HYBRID_REPLY message
         error = sshParseKexHybridReply(connection, message, length);
      }
      else
      {
         //Unknown message type
         error = ERROR_INVALID_TYPE;
      }
   }
   else
#endif
#if (SSH_SERVER_SUPPORT == ENABLED)
   //Server operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
   {
      //Check message type
      if(type == SSH_MSG_KEX_HYBRID_INIT)
      {
         //Parse SSH_MSG_KEX_HYBRID_INIT message
         error = sshParseKexHybridInit(connection, message, length);
      }
      else
      {
         //Unknown message type
         error = ERROR_INVALID_TYPE;
      }
   }
   else
#endif
   //Invalid operation mode?
   {
      //Report an error
      error = ERROR_INVALID_TYPE;
   }

   //Return status code
   return error;
}


/**
 * @brief Select key encapsulation mechanism
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSelectKemAlgo(SshConnection *connection)
{
   error_t error;

   //Release KEM context
   kemFree(&connection->kemContext);

#if (SSH_MLKEM768_SUPPORT == ENABLED)
   //ML-KEM-768 key encapsulation mechanism?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem768nistp256-sha256") ||
      sshCompareAlgo(connection->kexAlgo, "mlkem768x25519-sha256"))
   {
      //Initialize KEM context
      kemInit(&connection->kemContext, MLKEM768_KEM_ALGO);
      //Successful processing
      error = NO_ERROR;
   }
   else
#endif
#if (SSH_MLKEM1024_SUPPORT == ENABLED)
   //ML-KEM-1024 key encapsulation mechanism?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem1024nistp384-sha384"))
   {
      //Initialize KEM context
      kemInit(&connection->kemContext, MLKEM1024_KEM_ALGO);
      //Successful processing
      error = NO_ERROR;
   }
   else
#endif
#if (SSH_SNTRUP761_SUPPORT == ENABLED)
   //Streamlined NTRU Prime 761 key encapsulation mechanism?
   if(sshCompareAlgo(connection->kexAlgo, "sntrup761x25519-sha512") ||
      sshCompareAlgo(connection->kexAlgo, "sntrup761x25519-sha512@openssh.com"))
   {
      //Initialize KEM context
      kemInit(&connection->kemContext, SNTRUP761_KEM_ALGO);
      //Successful processing
      error = NO_ERROR;
   }
   else
#endif
   //Unknown key encapsulation mechanism?
   {
      //Report an error
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief Select ECDH domain parameters
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSelectClassicalEcdhCurve(SshConnection *connection)
{
   error_t error;
   const EcCurve *curve;

#if (SSH_NISTP256_SUPPORT == ENABLED)
   //NIST P-256 elliptic curve?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem768nistp256-sha256"))
   {
      curve = SECP256R1_CURVE;
   }
   else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED)
   //NIST P-384 elliptic curve?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem1024nistp384-sha384"))
   {
      curve = SECP384R1_CURVE;
   }
   else
#endif
#if (SSH_CURVE25519_SUPPORT == ENABLED)
   //Curve25519 elliptic curve?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem768x25519-sha256") ||
      sshCompareAlgo(connection->kexAlgo, "sntrup761x25519-sha512") ||
      sshCompareAlgo(connection->kexAlgo, "sntrup761x25519-sha512@openssh.com"))
   {
      curve = X25519_CURVE;
   }
   else
#endif
   //Unknown elliptic curve?
   {
      curve = NULL;
   }

   //Make sure the specified elliptic curve is supported
   if(curve != NULL)
   {
      //Save ECDH domain parameters
      error = ecdhSetCurve(&connection->ecdhContext, curve);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Return status code
   return error;
}


/**
 * @brief ECDH key pair generation
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshGenerateClassicalEcdhKeyPair(SshConnection *connection)
{
   error_t error;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   //Valid ECDH key pair generation callback function?
   if(context->ecdhKeyPairGenCallback != NULL)
   {
      //Invoke user-defined callback
      error = context->ecdhKeyPairGenCallback(connection, connection->kexAlgo,
         &connection->ecdhContext.da.q);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_KEY_EXCH_ALGO)
   {
      //Generate an ephemeral key pair
      error = ecdhGenerateKeyPair(&connection->ecdhContext, context->prngAlgo,
         context->prngContext);
   }

   //Return status code
   return error;
}


/**
 * @brief ECDH shared secret calculation
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshComputeClassicalEcdhSharedSecret(SshConnection *connection)
{
   error_t error;

#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   //Valid ECDH shared secret calculation callback function?
   if(connection->context->ecdhSharedSecretCalcCallback != NULL)
   {
      //Invoke user-defined callback
      error = connection->context->ecdhSharedSecretCalcCallback(connection,
         connection->kexAlgo, &connection->ecdhContext.qb, connection->k,
         &connection->kLen);
   }
   else
#endif
   {
      //No callback function registered
      error = ERROR_UNSUPPORTED_KEY_EXCH_ALGO;
   }

   //Check status code
   if(error == ERROR_UNSUPPORTED_KEY_EXCH_ALGO)
   {
      //Compute the shared secret K
      error = ecdhComputeSharedSecret(&connection->ecdhContext, connection->k,
         SSH_MAX_SHARED_SECRET_LEN, &connection->kLen);
   }

   //Return status code
   return error;
}


/**
 * @brief Update exchange hash with C_INIT (concatenation of C_PQ and C_CL)
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshDigestClientInit(SshConnection *connection)
{
   error_t error;
   size_t m;
   size_t n;
   uint8_t *buffer;

   //Allocate a temporary buffer
   buffer = sshAllocMem(SSH_BUFFER_SIZE);

   //Successful memory allocation?
   if(buffer != NULL)
   {
      //Get the length of the KEM public key
      m = connection->kemContext.kemAlgo->publicKeySize;

      //Format client's post-quantum public key (C_PQ)
      osMemcpy(buffer, connection->kemContext.pk, m);

      //Format client's classical public key (C_CL)
      error = ecdhExportPublicKey(&connection->ecdhContext, buffer + m, &n,
         EC_PUBLIC_KEY_FORMAT_X963);

      //Check status code
      if(!error)
      {
         //Update exchange hash H with C_INIT (concatenation of C_PQ and C_CL)
         error = sshUpdateExchangeHash(connection, buffer, m + n);
      }

      //Release previously allocated memory
      sshFreeMem(buffer);
   }
   else
   {
      //Failed to allocate memory
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
}

#endif
