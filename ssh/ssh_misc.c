/**
 * @file ssh_misc.c
 * @brief SSH helper functions
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
#include "ssh/ssh_transport.h"
#include "ssh/ssh_kex.h"
#include "ssh/ssh_kex_dh.h"
#include "ssh/ssh_kex_ecdh.h"
#include "ssh/ssh_auth.h"
#include "ssh/ssh_channel.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_export.h"
#include "ssh/ssh_misc.h"
#include "pkix/pem_import.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Open a new SSH connection
 * @param[in] context Pointer to the SSH context
 * @param[in] socket Handle that identifies a socket
 * @return Handle referencing the newly created SSH connection
 **/

SshConnection *sshOpenConnection(SshContext *context, Socket *socket)
{
   uint_t i;
   SshConnection *connection;

   //Initialize handle
   connection = NULL;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through the connection table
   for(i = 0; i < context->numConnections; i++)
   {
      //Unused SSH channel?
      if(context->connections[i].state == SSH_CONN_STATE_CLOSED)
      {
         //Point to the current SSH connection
         connection = &context->connections[i];

         //Clear the structure describing the connection
         osMemset(connection, 0, sizeof(SshConnection));

         //Attach SSH server context
         connection->context = context;
         //Attach socket handle
         connection->socket = socket;
         //Index of the selected host key
         connection->hostKeyIndex = 0;
         //Initialize time stamp
         connection->timestamp = osGetSystemTime();

#if (SSH_DH_SUPPORT == ENABLED)
         //Initialize Diffie-Hellman context
         dhInit(&connection->dhContext);
#endif
#if (SSH_ECDH_SUPPORT == ENABLED)
         //Initialize ECDH context
         ecdhInit(&connection->ecdhContext);
#endif
         //The sequence number is initialized to zero for the first packet (refer
         //to RFC 4253, section 6.4)
         osMemset(connection->encryptionEngine.seqNum, 0, 4);
         osMemset(connection->decryptionEngine.seqNum, 0, 4);

         //When the connection has been established, both sides must send an
         //identification string (refer to RFC 4253, section 4.2)
         if(context->mode == SSH_OPERATION_MODE_CLIENT)
         {
            connection->state = SSH_CONN_STATE_CLIENT_ID;
         }
         else
         {
            connection->state = SSH_CONN_STATE_SERVER_ID;
         }

         //We are done
         break;
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return a handle to the newly created SSH connection
   return connection;
}


/**
 * @brief Close SSH connection
 * @param[in] connection Pointer to the SSH connection
 **/

void sshCloseConnection(SshConnection *connection)
{
   uint_t i;
   SshContext *context;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("Closing SSH connection...\r\n");

   //Point to the SSH context
   context = connection->context;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Loop through SSH channels
   for(i = 0; i < context->numChannels; i++)
   {
      //Point to the current SSH channel
      channel = &context->channels[i];

      //Multiple channels can be multiplexed into a single connection
      if(channel->state != SSH_CHANNEL_STATE_UNUSED &&
         channel->connection == connection)
      {
         //Check channel state
         if(connection->context->mode == SSH_OPERATION_MODE_SERVER &&
            (channel->closeRequest || !channel->channelSuccessSent))
         {
            //Release SSH channel
            channel->state = SSH_CHANNEL_STATE_UNUSED;
         }
         else
         {
            //Close SSH channel
            channel->state = SSH_CHANNEL_STATE_CLOSED;
            //Update channel related events
            sshUpdateChannelEvents(&context->channels[i]);
         }
      }
   }

   //Valid socket handle?
   if(connection->socket != NULL)
   {
      //Close TCP socket
      socketClose(connection->socket);
      connection->socket = NULL;
   }

#if (SSH_DH_SUPPORT == ENABLED)
   //Release Diffie-Hellman context
   dhFree(&connection->dhContext);
#endif
#if (SSH_ECDH_SUPPORT == ENABLED)
   //Release ECDH context
   ecdhFree(&connection->ecdhContext);
#endif

   //Mark the connection as closed
   connection->state = SSH_CONN_STATE_CLOSED;

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);
}


/**
 * @brief Register connection events
 * @param[in] context Pointer to the SSH context
 * @param[in] connection Pointer to the SSH connection
 * @param[in] eventDesc Event to be registered
 **/

void sshRegisterConnectionEvents(SshContext *context, SshConnection *connection,
   SocketEventDesc *eventDesc)
{
   uint_t i;

   //Register socket handle
   eventDesc->socket = connection->socket;

   //On-going packet transfer?
   if(connection->txBufferPos < connection->txBufferLen)
   {
      //Wait until there is more room in the send buffer
      eventDesc->eventMask = SOCKET_EVENT_TX_READY;
   }
   else if(connection->rxBufferLen > 0)
   {
      //Wait for data to be available for reading
      eventDesc->eventMask = SOCKET_EVENT_RX_READY;
   }
   else
   {
      //Wait for data to be available for reading
      eventDesc->eventMask = SOCKET_EVENT_RX_READY;

      //Check the state of the connection
      if(connection->state == SSH_CONN_STATE_CLIENT_ID ||
         connection->state == SSH_CONN_STATE_CLIENT_KEX_INIT ||
         connection->state == SSH_CONN_STATE_KEX_DH_INIT ||
         connection->state == SSH_CONN_STATE_KEX_ECDH_INIT ||
         connection->state == SSH_CONN_STATE_CLIENT_NEW_KEYS ||
         connection->state == SSH_CONN_STATE_SERVICE_REQUEST ||
         connection->state == SSH_CONN_STATE_USER_AUTH_REQUEST)
      {
         //Client operation mode?
         if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
         {
            //Wait until there is more room in the send buffer
            eventDesc->eventMask = SOCKET_EVENT_TX_READY;
         }
      }
      else if(connection->state == SSH_CONN_STATE_SERVER_ID ||
         connection->state == SSH_CONN_STATE_SERVER_KEX_INIT ||
         connection->state == SSH_CONN_STATE_SERVER_NEW_KEYS)
      {
         //Client operation mode?
         if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
         {
            //Wait until there is more room in the send buffer
            eventDesc->eventMask = SOCKET_EVENT_TX_READY;
         }
      }
      else if(connection->state == SSH_CONN_STATE_OPEN)
      {
         //Loop through SSH channels
         for(i = 0; i < context->numChannels; i++)
         {
            //Multiple channels can be multiplexed into a single connection
            if(context->channels[i].state != SSH_CHANNEL_STATE_UNUSED &&
               context->channels[i].connection == connection)
            {
               //Register the events related to the current SSH channel
               sshRegisterChannelEvents(&context->channels[i], eventDesc);
            }
         }
      }
      else if(connection->state == SSH_CONN_STATE_DISCONNECT)
      {
         //Wait until there is more room in the send buffer
         eventDesc->eventMask = SOCKET_EVENT_TX_READY;
      }
      else
      {
         //Just for sanity
      }
   }
}


/**
 * @brief Connection event handler
 * @param[in] context Pointer to the SSH context
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshProcessConnectionEvents(SshContext *context,
   SshConnection *connection)
{
   error_t error;
   uint_t i;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Update time stamp
   connection->timestamp = osGetSystemTime();

   //The SSH Connection Protocol has been designed to run on top of the SSH
   //transport layer and user authentication protocols
   if(connection->state == SSH_CONN_STATE_OPEN)
   {
      //Loop through SSH channels
      for(i = 0; i < context->numChannels && !error; i++)
      {
         //Multiple channels can be multiplexed into a single connection
         if(context->channels[i].state != SSH_CHANNEL_STATE_UNUSED &&
            context->channels[i].connection == connection)
         {
            //Check whether the connection is ready for transmission
            if(connection->txBufferLen == 0 && connection->rxBufferLen == 0)
            {
               //Process channel related events
               error = sshProcessChannelEvents(&context->channels[i]);
            }
         }
      }
   }

   //Check status code
   if(!error)
   {
      //On-going packet transmission?
      if(connection->txBufferPos < connection->txBufferLen)
      {
         //Send more data
         error = socketSend(connection->socket,
            connection->buffer + connection->txBufferPos,
            connection->txBufferLen - connection->txBufferPos, &n, 0);

         //Check status code
         if(error == NO_ERROR || error == ERROR_TIMEOUT)
         {
            //Advance data pointer
            connection->txBufferPos += n;

            //Check whether the transmission is complete
            if(connection->txBufferPos >= connection->txBufferLen)
            {
               //Flush transmit buffer
               connection->txBufferLen = 0;
               connection->txBufferPos = 0;
            }
         }
      }
      else
      {
#if (SSH_CLIENT_SUPPORT == ENABLED)
         //Client operation mode?
         if(connection->context->mode == SSH_OPERATION_MODE_CLIENT)
         {
            //Check the state of the connection
            if(connection->state == SSH_CONN_STATE_CLIENT_ID)
            {
               //Send client's identification string
               error = sshSendIdString(connection);
            }
            else if(connection->state == SSH_CONN_STATE_CLIENT_KEX_INIT)
            {
               //Send SSH_MSG_KEXINIT message
               error = sshSendKexInit(connection);
            }
#if (SSH_DH_SUPPORT == ENABLED)
            else if(connection->state == SSH_CONN_STATE_KEX_DH_INIT)
            {
               //Send SSH_MSG_KEX_DH_INIT message
               error = sshSendKexDhInit(connection);
            }
#endif
#if (SSH_ECDH_SUPPORT == ENABLED)
            else if(connection->state == SSH_CONN_STATE_KEX_ECDH_INIT)
            {
               //Send SSH_MSG_KEX_ECDH_INIT message
               error = sshSendKexEcdhInit(connection);
            }
#endif
            else if(connection->state == SSH_CONN_STATE_SERVICE_REQUEST)
            {
               //Send SSH_MSG_SERVICE_REQUEST message
               error = sshSendServiceRequest(connection);
            }
            else if(connection->state == SSH_CONN_STATE_USER_AUTH_REQUEST)
            {
               //Send SSH_MSG_USERAUTH_REQUEST message
               error = sshSendUserAuthRequest(connection);
            }
            else if(connection->state == SSH_CONN_STATE_SERVER_ID ||
               connection->state == SSH_CONN_STATE_SERVER_KEX_INIT ||
               connection->state == SSH_CONN_STATE_KEX_DH_REPLY ||
               connection->state == SSH_CONN_STATE_KEX_ECDH_REPLY ||
               connection->state == SSH_CONN_STATE_SERVER_NEW_KEYS ||
               connection->state == SSH_CONN_STATE_SERVICE_ACCEPT ||
               connection->state == SSH_CONN_STATE_USER_AUTH_REPLY ||
               connection->state == SSH_CONN_STATE_OPEN)
            {
               //Receive incoming packet
               error = sshReceivePacket(connection);
            }
            else if(connection->state == SSH_CONN_STATE_DISCONNECT)
            {
               //The SSH_MSG_DISCONNECT message causes immediate termination of
               //the connection
               error = ERROR_CONNECTION_CLOSING;
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
         else
#endif
#if (SSH_SERVER_SUPPORT == ENABLED)
         //Server operation mode?
         if(connection->context->mode == SSH_OPERATION_MODE_SERVER)
         {
            //Check the state of the connection
            if(connection->state == SSH_CONN_STATE_SERVER_ID)
            {
               //Send server's identification string
               error = sshSendIdString(connection);
            }
            else if(connection->state == SSH_CONN_STATE_SERVER_KEX_INIT)
            {
               //Send SSH_MSG_KEXINIT message
               error = sshSendKexInit(connection);
            }
            else if(connection->state == SSH_CONN_STATE_SERVER_NEW_KEYS)
            {
               //Send SSH_MSG_NEWKEYS message
               error = sshSendNewKeys(connection);
            }
            else if(connection->state == SSH_CONN_STATE_CLIENT_ID ||
               connection->state == SSH_CONN_STATE_CLIENT_KEX_INIT ||
               connection->state == SSH_CONN_STATE_KEX_DH_INIT ||
               connection->state == SSH_CONN_STATE_KEX_ECDH_INIT ||
               connection->state == SSH_CONN_STATE_CLIENT_NEW_KEYS ||
               connection->state == SSH_CONN_STATE_SERVICE_REQUEST ||
               connection->state == SSH_CONN_STATE_USER_AUTH_REQUEST ||
               connection->state == SSH_CONN_STATE_OPEN)
            {
               //Receive incoming packet
               error = sshReceivePacket(connection);
            }
            else if(connection->state == SSH_CONN_STATE_DISCONNECT)
            {
               //The SSH_MSG_DISCONNECT message causes immediate termination of
               //the connection
               error = ERROR_CONNECTION_CLOSING;
            }
            else
            {
               //Invalid state
               error = ERROR_WRONG_STATE;
            }
         }
         else
#endif
         //Invalid operation mode?
         {
            //Report an error
            error = ERROR_FAILURE;
         }
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Subscribe to the specified channel events
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] event Event object used to receive notifications
 * @param[in] eventMask Logic OR of the requested socket events
 **/

void sshRegisterUserEvents(SshChannel *channel, OsEvent *event,
   uint_t eventMask)
{
   //Valid channel handle?
   if(channel != NULL)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&channel->context->mutex);

      //An user event may have been previously registered...
      if(channel->userEvent != NULL)
      {
         channel->eventMask |= eventMask;
      }
      else
      {
         channel->eventMask = eventMask;
      }

      //Suscribe to get notified of events
      channel->userEvent = event;
      //Update channel related events
      sshUpdateChannelEvents(channel);

      //Release exclusive access to the SSH context
      osReleaseMutex(&channel->context->mutex);
   }
}


/**
 * @brief Unsubscribe previously registered events
 * @param[in] channel Handle referencing an SSH channel
 **/

void sshUnregisterUserEvents(SshChannel *channel)
{
   //Valid channel handle?
   if(channel != NULL)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&channel->context->mutex);

      //Unsuscribe channel events
      channel->userEvent = NULL;

      //Release exclusive access to the SSH context
      osReleaseMutex(&channel->context->mutex);
   }
}


/**
 * @brief Retrieve event flags for a specified channel
 * @param[in] channel Handle referencing an SSH channel
 * @return Logic OR of events in the signaled state
 **/

uint_t sshGetUserEvents(SshChannel *channel)
{
   uint_t eventFlags;

   //Valid channel handle?
   if(channel != NULL)
   {
      //Acquire exclusive access to the SSH context
      osAcquireMutex(&channel->context->mutex);

      //Read event flags for the specified socket
      eventFlags = channel->eventFlags;

      //Release exclusive access to the SSH context
      osReleaseMutex(&channel->context->mutex);
   }
   else
   {
      //The socket handle is not valid
      eventFlags = 0;
   }

   //Return the events in the signaled state
   return eventFlags;
}


/**
 * @brief Notify the SSH context that event is occurring
 * @param[in] context Pointer to the SSH context
 **/

void sshNotifyEvent(SshContext *context)
{
   //Notify the SSH context that event is occurring
   osSetEvent(&context->event);
}


/**
 * @brief Get the currently selected host key
 * @param[in] connection Pointer to the SSH connection
 * @return Selected host key
 **/

SshHostKey *sshGetHostKey(SshConnection *connection)
{
   SshContext *context;
   SshHostKey *hostKey;

   //Point to the SSH context
   context = connection->context;

   //Ensure the index is valid
   if(connection->hostKeyIndex >= 1 &&
      connection->hostKeyIndex <= context->numHostKeys)
   {
      //Point to the selected host key
      hostKey = &context->hostKeys[connection->hostKeyIndex - 1];
   }
   else
   {
      //No host key is currently selected
      hostKey = NULL;
   }

   //Return the selected host key
   return hostKey;
}


/**
 * @brief Select a host key that matches then specified algorithm
 * @param[in] context Pointer to the SSH context
 * @param[in] hostKeyAlgo Selected host key algorithm name
 * @return Index of the selected host key
 **/

uint_t sshSelectHostKey(SshContext *context, const char_t *hostKeyAlgo)
{
   uint_t i;
   SshHostKey *hostKey;

   //Loop through the host keys
   for(i = 0; i < context->numHostKeys; i++)
   {
      //Point to the current host key
      hostKey = &context->hostKeys[i];

#if (SSH_RSA_SUPPORT == ENABLED)
      //RSA host key algorithm?
      if(sshCompareAlgo(hostKeyAlgo, "ssh-rsa") ||
         sshCompareAlgo(hostKeyAlgo, "rsa-sha2-256") ||
         sshCompareAlgo(hostKeyAlgo, "rsa-sha2-512"))
      {
         //Check key format identifier
         if(sshCompareAlgo(hostKey->keyFormatId, "ssh-rsa"))
         {
            //The current host key is acceptable
            break;
         }
      }
      else
#endif
#if (SSH_DSA_SUPPORT == ENABLED)
      //DSA host key algorithm?
      if(sshCompareAlgo(hostKeyAlgo, "ssh-dss"))
      {
         //Check key format identifier
         if(sshCompareAlgo(hostKey->keyFormatId, hostKeyAlgo))
         {
            //The current host key is acceptable
            break;
         }
      }
      else
#endif
#if (SSH_ECDSA_SUPPORT == ENABLED)
      //ECDSA host key algorithm?
      if(sshCompareAlgo(hostKeyAlgo, "ecdsa-sha2-nistp256") ||
         sshCompareAlgo(hostKeyAlgo, "ecdsa-sha2-nistp384") ||
         sshCompareAlgo(hostKeyAlgo, "ecdsa-sha2-nistp521"))
      {
         //Check key format identifier
         if(sshCompareAlgo(hostKey->keyFormatId, hostKeyAlgo))
         {
            //The current host key is acceptable
            break;
         }
      }
      else
#endif
#if (SSH_ED25519_SUPPORT == ENABLED)
      //Ed22519 host key algorithm?
      if(sshCompareAlgo(hostKeyAlgo, "ssh-ed25519"))
      {
         //Check key format identifier
         if(sshCompareAlgo(hostKey->keyFormatId, hostKeyAlgo))
         {
            //The current host key is acceptable
            break;
         }
      }
      else
#endif
#if (SSH_ED448_SUPPORT == ENABLED)
      //Ed448 host key algorithm?
      if(sshCompareAlgo(hostKeyAlgo, "ssh-ed448"))
      {
         //Check key format identifier
         if(sshCompareAlgo(hostKey->keyFormatId, hostKeyAlgo))
         {
            //The current host key is acceptable
            break;
         }
      }
      else
#endif
      //Unknown host key type?
      {
         //Just for sanity
      }
   }

   //Check whether a suitable host key has been found
   if(i < context->numHostKeys)
   {
      i++;
   }
   else
   {
      i = 0;
   }

   //Return the index of the host key
   return i;
}


/**
 * @brief Format host key structure
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Output stream where to write the host key
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatHostKey(SshConnection *connection, uint8_t *p,
   size_t *written)
{
   error_t error;
   SshHostKey *hostKey;

   //Get the currently selected host key
   hostKey = sshGetHostKey(connection);

   //Valid host key?
   if(hostKey != NULL)
   {
#if (SSH_RSA_SUPPORT == ENABLED)
      //RSA host key?
      if(sshCompareAlgo(hostKey->keyFormatId, "ssh-rsa"))
      {
         RsaPublicKey rsaPublicKey;

         //Initialize RSA public key
         rsaInitPublicKey(&rsaPublicKey);

         //Load RSA public key
         error = pemImportRsaPublicKey(hostKey->publicKey,
            hostKey->publicKeyLen, &rsaPublicKey);

         //Check status code
         if(!error)
         {
            //Format RSA host key structure
            error = sshFormatRsaPublicKey(&rsaPublicKey, p, written);
         }

         //Free previously allocated resources
         rsaFreePublicKey(&rsaPublicKey);
      }
      else
#endif
#if (SSH_DSA_SUPPORT == ENABLED)
      //DSA host key?
      if(sshCompareAlgo(hostKey->keyFormatId, "ssh-dss"))
      {
         DsaPublicKey dsaPublicKey;

         //Initialize DSA public key
         dsaInitPublicKey(&dsaPublicKey);

         //Load DSA public key
         error = pemImportDsaPublicKey(hostKey->publicKey,
            hostKey->publicKeyLen, &dsaPublicKey);

         //Check status code
         if(!error)
         {
            //Format DSA host key structure
            error = sshFormatDsaPublicKey(&dsaPublicKey, p, written);
         }

         //Free previously allocated resources
         dsaFreePublicKey(&dsaPublicKey);
      }
      else
#endif
#if (SSH_ECDSA_SUPPORT == ENABLED)
      //ECDSA host key?
      if(sshCompareAlgo(hostKey->keyFormatId, "ecdsa-sha2-nistp256") ||
         sshCompareAlgo(hostKey->keyFormatId, "ecdsa-sha2-nistp384") ||
         sshCompareAlgo(hostKey->keyFormatId, "ecdsa-sha2-nistp521"))
      {
         const EcCurveInfo *curveInfo;
         EcDomainParameters ecParams;
         EcPublicKey ecPublicKey;

         //Initialize EC domain parameters
         ecInitDomainParameters(&ecParams);
         //Initialize EC public key
         ecInitPublicKey(&ecPublicKey);

#if (SSH_NISTP256_SUPPORT == ENABLED)
         //NIST P-256 elliptic curve?
         if(sshCompareAlgo(hostKey->keyFormatId, "ecdsa-sha2-nistp256"))
         {
            curveInfo = SECP256R1_CURVE;
         }
         else
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED)
         //NIST P-384 elliptic curve?
         if(sshCompareAlgo(hostKey->keyFormatId, "ecdsa-sha2-nistp384"))
         {
            curveInfo = SECP384R1_CURVE;
         }
         else
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED)
         //NIST P-512 elliptic curve?
         if(sshCompareAlgo(hostKey->keyFormatId, "ecdsa-sha2-nistp521"))
         {
            curveInfo = SECP521R1_CURVE;
         }
         else
#endif
         //Unknown elliptic curve?
         {
            curveInfo = NULL;
         }

         //Load EC domain parameters
         error = ecLoadDomainParameters(&ecParams, curveInfo);

         //Check status code
         if(!error)
         {
            //Load ECDSA public key
            error = pemImportEcPublicKey(hostKey->publicKey,
               hostKey->publicKeyLen, &ecPublicKey);
         }

         //Check status code
         if(!error)
         {
            //Format ECDSA host key structure
            error = sshFormatEcdsaPublicKey(&ecParams, &ecPublicKey, p,
               written);
         }

         //Free previously allocated resources
         ecFreeDomainParameters(&ecParams);
         ecFreePublicKey(&ecPublicKey);
      }
      else
#endif
#if (SSH_ED25519_SUPPORT == ENABLED)
      //Ed25519 host key?
      if(sshCompareAlgo(hostKey->keyFormatId, "ssh-ed25519"))
      {
         EddsaPublicKey eddsaPublicKey;

         //Initialize EdDSA public key
         eddsaInitPublicKey(&eddsaPublicKey);

         //Load RSA public key
         error = pemImportEddsaPublicKey(hostKey->publicKey,
            hostKey->publicKeyLen, &eddsaPublicKey);

         //Check status code
         if(!error)
         {
            //Format Ed25519 host key structure
            error = sshFormatEd25519PublicKey(&eddsaPublicKey, p, written);
         }

         //Free previously allocated resources
         eddsaFreePublicKey(&eddsaPublicKey);
      }
      else
#endif
#if (SSH_ED448_SUPPORT == ENABLED)
      //Ed448 host key?
      if(sshCompareAlgo(hostKey->keyFormatId, "ssh-ed448"))
      {
         EddsaPublicKey eddsaPublicKey;

         //Initialize EdDSA public key
         eddsaInitPublicKey(&eddsaPublicKey);

         //Load RSA public key
         error = pemImportEddsaPublicKey(hostKey->publicKey,
            hostKey->publicKeyLen, &eddsaPublicKey);

         //Check status code
         if(!error)
         {
            //Format Ed448 host key structure
            error = sshFormatEd448PublicKey(&eddsaPublicKey, p, written);
         }

         //Free previously allocated resources
         eddsaFreePublicKey(&eddsaPublicKey);
      }
      else
#endif
      //Unknown host key type?
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }
   else
   {
      //No host key is currently selected
      error = ERROR_INVALID_KEY;
   }

   //Return status code
   return error;
}


/**
 * @brief Check whether the specified host key structure is valid
 * @param[in] hostKeyAlgo Host key algorithm name
 * @param[in] hostKeyBlob Pointer to the host key blob
 * @return Error code
 **/

error_t sshCheckHostKey(const SshString *hostKeyAlgo,
   const SshBinaryString *hostKeyBlob)
{
   error_t error;
   SshString keyFormatId;

   //Decode key format identifier
   error = sshParseString(hostKeyBlob->value, hostKeyBlob->length,
      &keyFormatId);

   //Check status code
   if(!error)
   {
#if (SSH_RSA_SUPPORT == ENABLED)
      //RSA host key algorithm?
      if(sshCompareString(hostKeyAlgo, "ssh-rsa") ||
         sshCompareString(hostKeyAlgo, "rsa-sha2-256") ||
         sshCompareString(hostKeyAlgo, "rsa-sha2-512"))
      {
         //Check key format identifier
         if(sshCompareString(&keyFormatId, "ssh-rsa"))
         {
            SshRsaHostKey hostKey;

            //Parse RSA host key structure
            error = sshParseRsaHostKey(hostKeyBlob->value,
               hostKeyBlob->length, &hostKey);
         }
         else
         {
            //The supplied key is not consistent with the host key algorithm
            error = ERROR_INVALID_KEY;
         }
      }
      else
#endif
#if (SSH_DSA_SUPPORT == ENABLED)
      //DSA host key algorithm?
      if(sshCompareString(hostKeyAlgo, "ssh-dss"))
      {
         //Check key format identifier
         if(sshCompareStrings(&keyFormatId, hostKeyAlgo))
         {
            SshDsaHostKey hostKey;

            //Parse DSA host key structure
            error = sshParseDsaHostKey(hostKeyBlob->value,
               hostKeyBlob->length, &hostKey);
         }
         else
         {
            //The supplied key is not consistent with the host key algorithm
            error = ERROR_INVALID_KEY;
         }
      }
      else
#endif
#if (SSH_ECDSA_SUPPORT == ENABLED)
      //ECDSA host key algorithm?
      if(sshCompareString(hostKeyAlgo, "ecdsa-sha2-nistp256") ||
         sshCompareString(hostKeyAlgo, "ecdsa-sha2-nistp384") ||
         sshCompareString(hostKeyAlgo, "ecdsa-sha2-nistp521"))
      {
         //Check key format identifier
         if(sshCompareStrings(&keyFormatId, hostKeyAlgo))
         {
            SshEcdsaHostKey hostKey;

            //Parse ECDSA host key structure
            error = sshParseEcdsaHostKey(hostKeyBlob->value,
               hostKeyBlob->length, &hostKey);

            //Check status code
            if(!error)
            {
               //Check whether the curve name is consistent
               if(sshCompareString(&keyFormatId, "ecdsa-sha2-nistp256") &&
                  sshCompareString(&hostKey.curveName, "nistp256"))
               {
                  //NIST P-256 elliptic curve
               }
               else if(sshCompareString(&keyFormatId, "ecdsa-sha2-nistp384") &&
                  sshCompareString(&hostKey.curveName, "nistp384"))
               {
                  //NIST P-384 elliptic curve
               }
               else if(sshCompareString(&keyFormatId, "ecdsa-sha2-nistp521") &&
                  sshCompareString(&hostKey.curveName, "nistp521"))
               {
                  //NIST P-521 elliptic curve
               }
               else
               {
                  //The curve name is not consistent
                  error = ERROR_INVALID_KEY;
               }
            }
         }
         else
         {
            //The supplied key is not consistent with the host key algorithm
            error = ERROR_INVALID_KEY;
         }
      }
      else
#endif
#if (SSH_ED25519_SUPPORT == ENABLED)
      //Ed22519 host key algorithm?
      if(sshCompareString(hostKeyAlgo, "ssh-ed25519"))
      {
         //Check key format identifier
         if(sshCompareStrings(&keyFormatId, hostKeyAlgo))
         {
            SshEddsaHostKey hostKey;

            //Parse Ed25519 host key structure
            error = sshParseEd25519HostKey(hostKeyBlob->value,
               hostKeyBlob->length, &hostKey);
         }
         else
         {
            //The supplied key is not consistent with the host key algorithm
            error = ERROR_INVALID_KEY;
         }
      }
      else
#endif
#if (SSH_ED448_SUPPORT == ENABLED)
      //Ed448 host key algorithm?
      if(sshCompareString(hostKeyAlgo, "ssh-ed448"))
      {
         //Check key format identifier
         if(sshCompareStrings(&keyFormatId, hostKeyAlgo))
         {
            SshEddsaHostKey hostKey;

            //Parse Ed448 host key structure
            error = sshParseEd448HostKey(hostKeyBlob->value,
               hostKeyBlob->length, &hostKey);
         }
         else
         {
            //The supplied key is not consistent with the host key algorithm
            error = ERROR_INVALID_KEY;
         }
      }
      else
#endif
      //Unknown host key type?
      {
         //Report an error
         error = ERROR_INVALID_KEY;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse a string
 * @param[in] p Input stream where to read the string
 * @param[in] length Number of bytes available in the input stream
 * @param[out] string String resulting from the parsing process
 * @return Error code
 **/

error_t sshParseString(const uint8_t *p, size_t length, SshString *string)
{
   size_t n;

   //Malformed data?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_SYNTAX;

   //A string is stored as a uint32 containing its length and zero or more
   //bytes that are the value of the string
   n = LOAD32BE(p);

   //Point to the value of the string
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed data?
   if(length < n)
      return ERROR_INVALID_SYNTAX;

   //Save the value of the string
   string->value = (char_t *) p;
   string->length = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse a binary string
 * @param[in] p Input stream where to read the string
 * @param[in] length Number of bytes available in the input stream
 * @param[out] string Binary string resulting from the parsing process
 * @return Error code
 **/

error_t sshParseBinaryString(const uint8_t *p, size_t length,
   SshBinaryString *string)
{
   size_t n;

   //Malformed data?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_SYNTAX;

   //A string is stored as a uint32 containing its length and zero or more
   //bytes that are the value of the string
   n = LOAD32BE(p);

   //Point to the value of the string
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed data?
   if(length < n)
      return ERROR_INVALID_SYNTAX;

   //Save the value of the string
   string->value = p;
   string->length = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse a comma-separated list of names
 * @param[in] p Input stream where to read the list
 * @param[in] length Number of bytes available in the input stream
 * @param[out] nameList Name list resulting from the parsing process
 * @return Error code
 **/

error_t sshParseNameList(const uint8_t *p, size_t length,
   SshNameList *nameList)
{
   size_t i;
   size_t n;

   //Malformed data?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_SYNTAX;

   //A name-list is represented as a uint32 containing its length followed by
   //a comma-separated list of zero or more names
   n = LOAD32BE(p);

   //Point to the list of names
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed data?
   if(length < n)
      return ERROR_INVALID_SYNTAX;

   //Loop through the comma-separated list of names
   for(i = 0; i < n; i++)
   {
      //A name must have a non-zero length (refer to RFC 4251 section 5)
      if(i == 0 || i == (n - 1))
      {
         if(p[i] == ',')
            return ERROR_INVALID_SYNTAX;
      }
      else
      {
         if(p[i] == ',' && p[i - 1] == ',')
            return ERROR_INVALID_SYNTAX;
      }

      //Terminating null characters must not be used, neither for the
      //individual names, nor for the list as a whole
      if(p[i] == '\0')
         return ERROR_INVALID_SYNTAX;
   }

   //Save the list of names
   nameList->value = (char_t *) p;
   nameList->length = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Get the element at specified index
 * @param[in] nameList List of names
 * @param[in] index Zero-based index of the element to get
 * @param[out] name Value of the element
 * @return TRUE if the index is valid, else FALSE
 **/

bool_t sshGetName(const SshNameList *nameList, uint_t index, SshString *name)
{
   size_t i;
   size_t j;
   uint_t n;

   //Initialize variables
   i = 0;
   n = 0;

   //Loop through the list of names
   for(j = 0; j <= nameList->length; j++)
   {
      //Names are separated by commas
      if(j == nameList->length || nameList->value[j] == ',')
      {
         //Matching index?
         if(n++ == index)
         {
            //Point to first character of the name
            name->value = nameList->value + i;
            //Determine the length of the name
            name->length = j - i;

            //The index is valid
            return TRUE;
         }

         //Point to the next name of the list
         i = j + 1;
      }
   }

   //The index is out of range
   return FALSE;
}


/**
 * @brief Format a string
 * @param[in] value NULL-terminating string
 * @param[out] p Output stream where to write the string
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatString(const char_t *value, uint8_t *p, size_t *written)
{
   size_t n;

   //Retrieve the length of the string
   n = osStrlen(value);

   //A string is stored as a uint32 containing its length and zero or more
   //bytes that are the value of the string
   STORE32BE(n, p);

   //Copy the value of the string
   osMemcpy(p + sizeof(uint32_t), value, n);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format a binary string
 * @param[in] value Pointer to the binary string
 * @param[in] valueLen Length of the binary string, in bytes
 * @param[out] p Output stream where to write the binary string
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatBinaryString(const void *value, size_t valueLen, uint8_t *p,
   size_t *written)
{
   //A string is stored as a uint32 containing its length and zero or more
   //bytes that are the value of the string
   STORE32BE(valueLen, p);

   //Copy the value of the string
   osMemcpy(p + sizeof(uint32_t), value, valueLen);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t) + valueLen;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format a comma-separated list of names
 * @param[in] nameList List of names
 * @param[in] nameListLen Number of items in the list
 * @param[out] p Output stream where to write the name list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatNameList(const char_t *nameList[], uint_t nameListLen,
   uint8_t *p, size_t *written)
{
   uint_t i;
   size_t n;

   //A name-list is represented as a uint32 containing its length followed
   //by a comma-separated list of zero or more names
   n = sizeof(uint32_t);

   //Loop through the list of names
   for(i = 0; i < nameListLen; i++)
   {
      //Names are separated by commas
      if(n != sizeof(uint32_t))
      {
         p[n++] = ',';
      }

      //A name must have a non-zero length and it must not contain a comma
      osStrcpy((char_t *) p + n, nameList[i]);

      //Update the length of the name list
      n += osStrlen(nameList[i]);
   }

   //The name list is preceded by a uint32 containing its length
   STORE32BE(n - sizeof(uint32_t), p);

   //Total number of bytes that have been written
   *written = n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format a multiple precision integer
 * @param[in] value Pointer to a multiple precision integer
 * @param[out] p Output stream where to write the multiple precision integer
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatMpint(const Mpi *value, uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Retrieve the length of the multiple precision integer
   n = mpiGetBitLength(value);

   //The value zero must be stored as a string with zero bytes of data
   if(n != 0)
   {
      //If the most significant bit would be set for a positive number, the
      //number must be preceded by a zero byte (refer to RFC 4251, section 5)
      n = (n / 8) + 1;
   }

   //The value of the multiple precision integer is encoded MSB first.
   //Unnecessary leading bytes with the value 0 must not be included
   error = mpiExport(value, p + 4, n, MPI_FORMAT_BIG_ENDIAN);

   //Check status code
   if(!error)
   {
      //The integer is preceded by a uint32 containing its length
      STORE32BE(n, p);

      //Total number of bytes that have been written
      *written = sizeof(uint32_t) + n;
   }

   //Return status code
   return error;
}


/**
 * @brief Convert a binary string to mpint representation
 * @param[in] value Pointer to the binary string (MSB first encoded)
 * @param[out] length Length of the binary string, in bytes
 * @param[out] p Output stream where to write the mpint representation
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshConvertArrayToMpint(const uint8_t *value, size_t length, uint8_t *p,
   size_t *written)
{
   size_t n;

   //Skip leading zeroes
   while(length > 0 && value[0] == 0)
   {
      value++;
      length--;
   }

   //The value zero must be stored as a string with zero bytes of data (refer
   //to RFC 4251, section 5)
   n = 0;

   //If the most significant bit would be set for a positive number, the
   //number must be preceded by a zero byte
   if((value[0] & 0x80) != 0)
   {
      //The number is preceded by a zero byte
      p[4 + n] = 0;

      //Update the length of the data
      n++;
   }

   //The value of the multiple precision integer is encoded MSB first.
   //Unnecessary leading bytes with the value 0 must not be included
   osMemcpy(p + 4 + n, value, length);

   //Update the length of the data
   n += length;

   //The integer is preceded by a uint32 containing its length
   STORE32BE(n, p);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t) + n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Compare a binary string against the supplied value
 * @param[in] string Pointer to the binary string
 * @param[in] value NULL-terminated string
 * @return Comparison result
 **/

bool_t sshCompareString(const SshString *string, const char_t *value)
{
   bool_t res;
   size_t n;

   //Initialize flag
   res = FALSE;

   //Determine the length of the string
   n = osStrlen(value);

   //Check the length of the binary string
   if(string->value != NULL && string->length == n)
   {
      //Perform string comparison
      if(!osStrncmp(string->value, value, n))
      {
         res = TRUE;
      }
   }

   //Return comparison result
   return res;
}


/**
 * @brief Compare binary strings
 * @param[in] string1 Pointer to the first binary string
 * @param[in] string2 Pointer to the second binary string
 * @return Comparison result
 **/

bool_t sshCompareStrings(const SshString *string1, const SshString *string2)
{
   bool_t res;

   //Initialize flag
   res = FALSE;

   //Check the length of the binary strings
   if(string1->value != NULL && string2->value != NULL &&
      string1->length == string2->length)
   {
      //Perform string comparison
      if(!osMemcmp(string1->value, string2->value, string2->length))
      {
         res = TRUE;
      }
   }

   //Return comparison result
   return res;
}


/**
 * @brief Compare algorithm names
 * @param[in] name1 Name of the first algorithm
 * @param[in] name2 Name of the second algorithm
 * @return Comparison result
 **/

bool_t sshCompareAlgo(const char_t *name1, const char_t *name2)
{
   bool_t res;

   //Initialize flag
   res = FALSE;

   //Valid strings?
   if(name1 != NULL && name2 != NULL)
   {
      //Perform string comparison
      if(!osStrcmp(name1, name2))
      {
         res = TRUE;
      }
   }

   //Return comparison result
   return res;
}

#endif
