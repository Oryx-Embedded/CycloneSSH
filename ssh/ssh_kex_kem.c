/**
 * @file ssh_kex_kem.c
 * @brief Pure post-quantum key exchange
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2026 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.6.6
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL SSH_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_transport.h"
#include "ssh/ssh_kex.h"
#include "ssh/ssh_kex_kem.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_key_material.h"
#include "ssh/ssh_exchange_hash.h"
#include "ssh/ssh_key_verify.h"
#include "ssh/ssh_cert_verify.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_KEM_KEX_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_KEX_KEM_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexKemInit(SshConnection *connection)
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
      //Format SSH_MSG_KEX_KEM_INIT message
      error = sshFormatKexKemInit(connection, message, &length);
   }

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_KEM_INIT message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //The server responds with an SSH_MSG_KEX_KEM_REPLY message
      connection->state = SSH_CONN_STATE_KEX_KEM_REPLY;
   }

   //Return status code
   return error;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Send SSH_MSG_KEX_KEM_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendKexKemReply(SshConnection *connection)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_KEX_KEM_REPLY message
   error = sshFormatKexKemReply(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_KEX_KEM_REPLY message (%" PRIuSIZE " bytes)...\r\n", length);
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
 * @brief Format SSH_MSG_KEX_KEM_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexKemInit(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_CLIENT_SUPPORT == ENABLED)
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_KEM_INIT;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Get the length of the public key
   n = connection->kemContext.kemAlgo->publicKeySize;

   //C_INIT is the ephemeral client ML-KEM public key (C_PK)
   osMemcpy(p + sizeof(uint32_t), connection->kemContext.pk, n);
   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total length of the message
   *length += sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
#else
   //Client operation mode is not implemented
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief Format SSH_MSG_KEX_KEM_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatKexKemReply(SshConnection *connection, uint8_t *p,
   size_t *length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_KEX_KEM_REPLY;

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
      context->prngContext, p + sizeof(uint32_t), connection->k +
      sizeof(uint32_t));
   //Any error to report?
   if(error)
      return error;

   //Get the length of the KEM ciphertext
   n = connection->kemContext.kemAlgo->ciphertextSize;

   //Update exchange hash H with S_REPLY
   error = sshUpdateExchangeHash(connection, p + sizeof(uint32_t), n);
   //Any error to report?
   if(error)
      return error;

   //The octet string value is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Point to the next field
   p += sizeof(uint32_t) + n;
   *length += sizeof(uint32_t) + n;

   //Get the length of the KEM shared secret
   n = connection->kemContext.kemAlgo->sharedSecretSize;

   //Log shared secret (for debugging purpose only)
   sshDumpKey(connection, "SHARED_SECRET", connection->k + sizeof(uint32_t), n);

   //Convert K_PQ to string representation
   STORE32BE(n, connection->k);
   connection->kLen = sizeof(uint32_t) + n;

   //Update exchange hash H with K_PQ (shared secret)
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

   //Destroy post-quantum private key
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
 * @brief Parse SSH_MSG_KEX_KEM_INIT message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexKemInit(SshConnection *connection,
   const uint8_t *message, size_t length)
{
#if (SSH_SERVER_SUPPORT == ENABLED)
   error_t error;
   const uint8_t *p;
   SshBinaryString clientInit;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_KEM_INIT message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(connection->context->mode != SSH_OPERATION_MODE_SERVER)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_KEM_INIT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //C_INIT is the ephemeral client ML-KEM public key (C_PK)
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

   //Update exchange hash H with C_INIT
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

   //Check the length of the C_INIT field
   if(clientInit.length != connection->kemContext.kemAlgo->publicKeySize)
   {
      //Abort using a disconnect message (SSH_MSG_DISCONNECT) with a
      //SSH_DISCONNECT_KEY_EXCHANGE_FAILED as the reason
      return ERROR_KEY_EXCH_FAILED;
   }

   //Load ephemeral client ML-KEM public key (C_PK)
   error = kemLoadPublicKey(&connection->kemContext, clientInit.value);
   //Any error to report?
   if(error)
      return error;

   //The server responds with an SSH_MSG_KEX_KEM_REPLY message
   return sshSendKexKemReply(connection);
#else
   //Server operation mode is not implemented
   return ERROR_UNEXPECTED_MESSAGE;
#endif
}


/**
 * @brief Parse SSH_MSG_KEX_KEM_REPLY message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexKemReply(SshConnection *connection,
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

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_KEX_KEM_REPLY message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check operation mode
   if(context->mode != SSH_OPERATION_MODE_CLIENT)
      return ERROR_UNEXPECTED_MESSAGE;

   //Check connection state
   if(connection->state != SSH_CONN_STATE_KEX_KEM_REPLY)
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

   //Decode S_REPLY
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

   //Update exchange hash H with C_INIT
   error = sshUpdateExchangeHash(connection, connection->kemContext.pk,
      connection->kemContext.kemAlgo->publicKeySize);
   //Any error to report?
   if(error)
      return error;

   //Update exchange hash H with S_REPLY
   error = sshUpdateExchangeHash(connection, serverReply.value,
      serverReply.length);
   //Any error to report?
   if(error)
      return error;

   //Before decapsulating, the client must check if the ciphertext S_CT length
   //matches the selected ML-KEM variant
   if(serverReply.length != connection->kemContext.kemAlgo->ciphertextSize)
   {
      //The client must abort using a disconnect message (SSH_MSG_DISCONNECT)
      //with a SSH_DISCONNECT_KEY_EXCHANGE_FAILED as the reason if the S_CT
      //length does not match the ML-KEM variant
      return ERROR_KEY_EXCH_FAILED;
   }

   //K_PQ is the post-quantum shared secret decapsulated from S_CT
   error = kemDecapsulate(&connection->kemContext, serverReply.value,
      connection->k + sizeof(uint32_t));
   //Any error to report?
   if(error)
      return error;

   //Get the length of the KEM shared secret
   n = connection->kemContext.kemAlgo->sharedSecretSize;

   //Log shared secret (for debugging purpose only)
   sshDumpKey(connection, "SHARED_SECRET", connection->k + sizeof(uint32_t), n);

   //Convert K_PQ to string representation
   STORE32BE(n, connection->k);
   connection->kLen = sizeof(uint32_t) + n;

   //Update exchange hash H with K_PQ (shared secret)
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

   //Destroy post-quantum private key
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
 * @brief Parse ML-KEM specific messages
 * @param[in] connection Pointer to the SSH connection
 * @param[in] type SSH message type
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseKexKemMessage(SshConnection *connection, uint8_t type,
   const uint8_t *message, size_t length)
{
   error_t error;

#if (SSH_CLIENT_SUPPORT == ENABLED)
   //Client operation mode?
   if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Check message type
      if(type == SSH_MSG_KEX_KEM_REPLY)
      {
         //Parse SSH_MSG_KEX_KEM_REPLY message
         error = sshParseKexKemReply(connection, message, length);
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
      if(type == SSH_MSG_KEX_KEM_INIT)
      {
         //Parse SSH_MSG_KEX_KEM_INIT message
         error = sshParseKexKemInit(connection, message, length);
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

#if (SSH_MLKEM512_SUPPORT == ENABLED)
   //ML-KEM-512 key encapsulation mechanism?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem512-sha256"))
   {
      //Initialize KEM context
      kemInit(&connection->kemContext, MLKEM512_KEM_ALGO);
      //Successful processing
      error = NO_ERROR;
   }
   else
#endif
#if (SSH_MLKEM768_SUPPORT == ENABLED)
   //ML-KEM-768 key encapsulation mechanism?
   if(sshCompareAlgo(connection->kexAlgo, "mlkem768-sha256"))
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
   if(sshCompareAlgo(connection->kexAlgo, "mlkem1024-sha384"))
   {
      //Initialize KEM context
      kemInit(&connection->kemContext, MLKEM1024_KEM_ALGO);
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

#endif
