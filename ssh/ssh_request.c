/**
 * @file ssh_request.c
 * @brief Global request and channel request handling
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
#include "ssh/ssh_request.h"
#include "ssh/ssh_channel.h"
#include "ssh/ssh_packet.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief Send SSH_MSG_GLOBAL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] requestName NULL-terminated string containing the request name
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @return Error code
 **/

error_t sshSendGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_GLOBAL_REQUEST message
   error = sshFormatGlobalRequest(connection, requestName, requestParams,
      wantReply, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_GLOBAL_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Check whether a reply is expected from the other party
      if(wantReply)
      {
         //The recipient will respond with either SSH_MSG_REQUEST_SUCCESS or
         //SSH_MSG_REQUEST_FAILURE message
         connection->requestState = SSH_REQUEST_STATE_PENDING;
      }
      else
      {
         //The recipient will not respond to the request
         connection->requestState = SSH_REQUEST_STATE_IDLE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_REQUEST_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendRequestSuccess(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_REQUEST_SUCCESS message
   error = sshFormatRequestSuccess(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_REQUEST_SUCCESS message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_REQUEST_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @return Error code
 **/

error_t sshSendRequestFailure(SshConnection *connection)
{
   error_t error;
   size_t length;
   uint8_t *message;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_REQUEST_FAILURE message
   error = sshFormatRequestFailure(connection, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_REQUEST_FAILURE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_REQUEST message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] requestType NULL-terminated string containing the request type
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @return Error code
 **/

error_t sshSendChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_REQUEST message
   error = sshFormatChannelRequest(channel, requestType, requestParams,
      wantReply, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_REQUEST message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //Check whether a reply is expected from the other party
      if(wantReply)
      {
         //The recipient will respond with either SSH_MSG_CHANNEL_SUCCESS or
         //SSH_MSG_CHANNEL_FAILURE message
         channel->requestState = SSH_REQUEST_STATE_PENDING;
      }
      else
      {
         //The recipient will not respond to the request
         channel->requestState = SSH_REQUEST_STATE_IDLE;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_SUCCESS message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelSuccess(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_SUCCESS message
   error = sshFormatChannelSuccess(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_SUCCESS message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Check status code
   if(!error)
   {
      //An SSH_MSG_CHANNEL_SUCCESS message has been successfully sent
      channel->channelSuccessSent = TRUE;
   }

   //Return status code
   return error;
}


/**
 * @brief Send SSH_MSG_CHANNEL_FAILURE message
 * @param[in] channel Handle referencing an SSH channel
 * @return Error code
 **/

error_t sshSendChannelFailure(SshChannel *channel)
{
   error_t error;
   size_t length;
   uint8_t *message;
   SshConnection *connection;

   //Point to the SSH connection
   connection = channel->connection;

   //Point to the buffer where to format the message
   message = connection->buffer + SSH_PACKET_HEADER_SIZE;

   //Format SSH_MSG_CHANNEL_FAILURE message
   error = sshFormatChannelFailure(channel, message, &length);

   //Check status code
   if(!error)
   {
      //Debug message
      TRACE_INFO("Sending SSH_MSG_CHANNEL_FAILURE message (%" PRIuSIZE " bytes)...\r\n", length);
      TRACE_VERBOSE_ARRAY("  ", message, length);

      //Send message
      error = sshSendPacket(connection, message, length);
   }

   //Return status code
   return error;
}


/**
 * @brief Format SSH_MSG_GLOBAL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] requestName NULL-terminated string containing the request name
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply,
   uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_GLOBAL_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set request name
   error = sshFormatString(requestName, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Set want_reply boolean
   p[0] = wantReply ? TRUE : FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Check request type
   if(!osStrcmp(requestName, "tcpip-forward"))
   {
      //Format "tcpip-forward" request specific data
      error = sshFormatFwdReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestName, "cancel-tcpip-forward"))
   {
      //Format "cancel-tcpip-forward" request specific data
      error = sshFormatCancelFwdReqParams(requestParams, p, &n);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_REQUEST;
   }

   //Check status code
   if(!error)
   {
      //Total length of the message
      *length += n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format "tcpip-forward" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatFwdReqParams(const SshFwdReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //The 'address to bind' field specifies the IP address on which connections
   //for forwarding are to be accepted
   error = sshFormatBinaryString(requestParams->addrToBind.value,
      requestParams->addrToBind.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //The 'port number to bind' field specifies the port on which connections
   //for forwarding are to be accepted
   STORE32BE(requestParams->portNumToBind, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "cancel-tcpip-forward" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatCancelFwdReqParams(const SshCancelFwdReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //Set 'address to bind' field
   error = sshFormatBinaryString(requestParams->addrToBind.value,
      requestParams->addrToBind.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Set 'port number to bind' field
   STORE32BE(requestParams->portNumToBind, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_REQUEST_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatRequestSuccess(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   //Set message type
   p[0] = SSH_MSG_REQUEST_SUCCESS;

   //Usually, the response specific data is non-existent (refer to RFC 4254,
   //section 4)
   *length = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_REQUEST_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatRequestFailure(SshConnection *connection, uint8_t *p,
   size_t *length)
{
   //Set message type
   p[0] = SSH_MSG_REQUEST_FAILURE;

   //Total length of the message
   *length = sizeof(uint8_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_REQUEST message
 * @param[in] channel Handle referencing an SSH channel
 * @param[in] requestType NULL-terminated string containing the request type
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[in] wantReply This flag specifies whether a reply is expected
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply, uint8_t *p, size_t *length)
{
   error_t error;
   size_t n;

   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_REQUEST;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel number
   STORE32BE(channel->remoteChannelNum, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *length += sizeof(uint32_t);

   //Set request type
   error = sshFormatString(requestType, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *length += n;

   //Set want_reply boolean
   p[0] = wantReply ? TRUE : FALSE;

   //Point to the next field
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Check request type
   if(!osStrcmp(requestType, "pty-req"))
   {
      //Format "pty-req" request specific data
      error = sshFormatPtyReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "shell"))
   {
      //The "shell" request does not contain type-specific data
      n = 0;
   }
   else if(!osStrcmp(requestType, "exec"))
   {
      //Format "exec" request specific data
      error = sshFormatExecReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "subsystem"))
   {
      //Format "subsystem" request specific data
      error = sshFormatSubsystemReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "window-change"))
   {
      //Format "window-change" request specific data
      error = sshFormatWindowChangeReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "signal"))
   {
      //Format "signal" request specific data
      error = sshFormatSignalReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "exit-status"))
   {
      //Format "exit-status" request specific data
      error = sshFormatExitStatusReqParams(requestParams, p, &n);
   }
   else if(!osStrcmp(requestType, "break"))
   {
      //Format "break" request specific data
      error = sshFormatBreakReqParams(requestParams, p, &n);
   }
   else
   {
      //Report an error
      error = ERROR_UNSUPPORTED_REQUEST;
   }

   //Check status code
   if(!error)
   {
      //Total length of the message
      *length += n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format "pty-req" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatPtyReqParams(const SshPtyReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   error_t error;
   size_t n;

   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //Set terminal environment variables
   error = sshFormatBinaryString(requestParams->termEnvVar.value,
      requestParams->termEnvVar.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += n;
   *written += n;

   //Set terminal width (in characters)
   STORE32BE(requestParams->termWidthChars, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in rows)
   STORE32BE(requestParams->termHeightRows, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal width (in pixels)
   STORE32BE(requestParams->termWidthPixels, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in pixels)
   STORE32BE(requestParams->termHeightPixels, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal environment variables
   error = sshFormatBinaryString(requestParams->termModes.value,
      requestParams->termModes.length, p, &n);
   //Any error to report?
   if(error)
      return error;

   //Total number of bytes that have been written
   *written += n;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "exec" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatExecReqParams(const SshExecReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set command line
   error = sshFormatBinaryString(requestParams->command.value,
      requestParams->command.length, p, written);

   //Return status code
   return error;
}


/**
 * @brief Format "subsystem" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatSubsystemReqParams(const SshSubsystemReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set subsystem name
   error = sshFormatBinaryString(requestParams->subsystemName.value,
      requestParams->subsystemName.length, p, written);

   //Return status code
   return error;
}


/**
 * @brief Format "window-change" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatWindowChangeReqParams(const SshWindowChangeReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Total length of the request specific data
   *written = 0;

   //Set terminal width (in characters)
   STORE32BE(requestParams->termWidthChars, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in rows)
   STORE32BE(requestParams->termHeightRows, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal width (in pixels)
   STORE32BE(requestParams->termWidthPixels, p);

   //Point to the next field
   p += sizeof(uint32_t);
   *written += sizeof(uint32_t);

   //Set terminal height (in pixels)
   STORE32BE(requestParams->termHeightPixels, p);

   //Total number of bytes that have been written
   *written += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "signal" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatSignalReqParams(const SshSignalReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   error_t error;

   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set signal name
   error = sshFormatBinaryString(requestParams->signalName.value,
      requestParams->signalName.length, p, written);

   //Return status code
   return error;
}


/**
 * @brief Format "exit-status" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatExitStatusReqParams(const SshExitStatusReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set exit status
   STORE32BE(requestParams->exitStatus, p);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format "break" request specific data
 * @param[in] requestParams Pointer to the request specific parameters
 * @param[out] p Output stream where to write the request type specific data
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatBreakReqParams(const SshBreakReqParams *requestParams,
   uint8_t *p, size_t *written)
{
   //Check parameters
   if(requestParams == NULL)
      return ERROR_INVALID_PARAMETER;

   //Set break length (in milliseconds)
   STORE32BE(requestParams->breakLen, p);

   //Total number of bytes that have been written
   *written = sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_SUCCESS message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelSuccess(SshChannel *channel, uint8_t *p,
   size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_SUCCESS;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Format SSH_MSG_CHANNEL_FAILURE message
 * @param[in] channel Handle referencing an SSH channel
 * @param[out] p Buffer where to format the message
 * @param[out] length Length of the resulting message, in bytes
 * @return Error code
 **/

error_t sshFormatChannelFailure(SshChannel *channel, uint8_t *p,
   size_t *length)
{
   //Total length of the message
   *length = 0;

   //Set message type
   p[0] = SSH_MSG_CHANNEL_FAILURE;

   //Point to the first field of the message
   p += sizeof(uint8_t);
   *length += sizeof(uint8_t);

   //Set recipient channel
   STORE32BE(channel->remoteChannelNum, p);

   //Total length of the message
   *length += sizeof(uint32_t);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_GLOBAL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseGlobalRequest(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   uint_t i;
   const uint8_t *p;
   SshString requestName;
   SshBoolean wantReply;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_GLOBAL_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Decode the request name
   error = sshParseString(p, length, &requestName);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + requestName.length;
   length -= sizeof(uint32_t) + requestName.length;

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode want_reply field
   wantReply = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Initialize status code
   error = ERROR_UNKNOWN_REQUEST;

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Multiple callbacks may be registered
   for(i = 0; i < SSH_MAX_REQ_CALLBACKS && error == ERROR_UNKNOWN_REQUEST; i++)
   {
      //Valid callback function?
      if(context->globalReqCallback[i] != NULL)
      {
         //Process global request
         error = context->globalReqCallback[i](connection, &requestName, p,
            length, context->globalReqParam[i]);
      }
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Check the value of the want_reply boolean
   if(!wantReply)
   {
      //If want_reply is FALSE, no response will be sent to the request
      error = NO_ERROR;
   }
   else
   {
      //Otherwise, the recipient responds with either SSH_MSG_REQUEST_SUCCESS
      //or SSH_MSG_REQUEST_FAILURE
      if(!error)
      {
         //Send an SSH_MSG_REQUEST_SUCCESS response
         error = sshSendRequestSuccess(connection);
      }
      else
      {
         //If the recipient does not recognize or support the request, it simply
         //responds with SSH_MSG_REQUEST_FAILURE (refer to RFC 4254, section 4)
         error = sshSendRequestFailure(connection);
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_MSG_REQUEST_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseRequestSuccess(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   //Debug message
   TRACE_INFO("SSH_MSG_REQUEST_SUCCESS message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Check global request state
   if(connection->requestState != SSH_REQUEST_STATE_PENDING)
      return ERROR_UNEXPECTED_MESSAGE;

   //Update global request state
   connection->requestState = SSH_REQUEST_STATE_SUCCESS;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_REQUEST_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseRequestFailure(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   //Debug message
   TRACE_INFO("SSH_MSG_REQUEST_FAILURE message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Malformed message?
   if(length != sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Check global request state
   if(connection->requestState != SSH_REQUEST_STATE_PENDING)
      return ERROR_UNEXPECTED_MESSAGE;

   //Update global request state
   connection->requestState = SSH_REQUEST_STATE_FAILURE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_REQUEST message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelRequest(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   uint_t i;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshString requestType;
   SshBoolean wantReply;
   SshChannel *channel;
   SshContext *context;

   //Point to the SSH context
   context = connection->context;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_REQUEST message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get recipient channel number
   recipientChannel = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Decode the request type
   error = sshParseString(p, length, &requestType);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + requestType.length;
   length -= sizeof(uint32_t) + requestType.length;

   //Malformed message?
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Decode want_reply field
   wantReply = p[0];

   //Point to the next field
   p += sizeof(uint8_t);
   length -= sizeof(uint8_t);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->closeReceived)
      {
         //Initialize status code
         error = ERROR_UNKNOWN_REQUEST;

         //Multiple callbacks may be registered
         for(i = 0; i < SSH_MAX_REQ_CALLBACKS && error == ERROR_UNKNOWN_REQUEST; i++)
         {
            //Valid callback function?
            if(context->channelReqCallback[i] != NULL)
            {
               //Process channel request
               error = context->channelReqCallback[i](channel, &requestType, p,
                  length, context->channelReqParam[i]);
            }
         }

         //Check the value of the want_reply boolean
         if(!wantReply || channel->closeSent)
         {
            //If want_reply is FALSE, no response will be sent to the request
            error = NO_ERROR;
         }
         else
         {
            //Otherwise, the recipient responds with either SSH_MSG_CHANNEL_SUCCESS,
            //SSH_MSG_CHANNEL_FAILURE, or request-specific continuation messages
            if(!error)
            {
               //Send an SSH_MSG_CHANNEL_SUCCESS response
               error = sshSendChannelSuccess(channel);
            }
            else
            {
               //If the request is not recognized or is not supported for the
               //channel, SSH_MSG_CHANNEL_FAILURE is returned (refer to RFC 4254,
               //section 5.4)
               error = sshSendChannelFailure(channel);
            }
         }
      }
      else
      {
         //Invalid channel state
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //The recipient channel number is not valid
      error = ERROR_INVALID_CHANNEL;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Parse "pty-req" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] ptyReqParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParsePtyReqParams(const uint8_t *p, size_t length,
   SshPtyReqParams *ptyReqParams)
{
   error_t error;

   //Parse the terminal environment variable value
   error = sshParseString(p, length, &ptyReqParams->termEnvVar);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   p += sizeof(uint32_t) + ptyReqParams->termEnvVar.length;
   length -= sizeof(uint32_t) + ptyReqParams->termEnvVar.length;

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in characters)
   ptyReqParams->termWidthChars = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in rows)
   ptyReqParams->termHeightRows = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in pixels)
   ptyReqParams->termWidthPixels = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in pixels)
   ptyReqParams->termHeightPixels = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Parse the encoded terminal modes
   error = sshParseBinaryString(p, length, &ptyReqParams->termModes);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + ptyReqParams->termModes.length))
      return ERROR_INVALID_MESSAGE;

   //Debug message
   TRACE_INFO("  Term Width (chars) = %" PRIu32 "\r\n", ptyReqParams->termWidthChars);
   TRACE_INFO("  Term Height (rows) = %" PRIu32 "\r\n", ptyReqParams->termHeightRows);
   TRACE_INFO("  Term Width (pixels) = %" PRIu32 "\r\n", ptyReqParams->termWidthPixels);
   TRACE_INFO("  Term Height (pixels) = %" PRIu32 "\r\n", ptyReqParams->termHeightPixels);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "exec" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] requestParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseExecReqParams(const uint8_t *p, size_t length,
   SshExecReqParams *requestParams)
{
   error_t error;

   //Parse command
   error = sshParseString(p, length, &requestParams->command);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + requestParams->command.length))
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Retrieve the specified argument from an "exec" request
 * @param[in] requestParams Pointer to the "exec" request parameters
 * @param[in] index Zero-based index of the argument
 * @param[out] arg Value of the argument
 * @return TRUE if the index is valid, else FALSE
 **/

bool_t sshGetExecReqArg(const SshExecReqParams *requestParams, uint_t index,
   SshString *arg)
{
   size_t i;
   size_t j;
   uint_t n;

   //Initialize variables
   i = 0;
   n = 0;

   //Parse the command line
   for(j = 0; j <= requestParams->command.length; j++)
   {
      //Arguments are separated by whitespace characters
      if(j == requestParams->command.length ||
         osIsblank(requestParams->command.value[j]))
      {
         //Non-empty string?
         if(i < j)
         {
            //Matching index?
            if(n++ == index)
            {
               //Point to first character of the argument
               arg->value = requestParams->command.value + i;
               //Determine the length of the argument
               arg->length = j - i;

               //The index is valid
               return TRUE;
            }
         }

         //Point to the next argument of the list
         i = j + 1;
      }
   }

   //The index is out of range
   return FALSE;
}


/**
 * @brief Parse "subsystem" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] requestParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseSubsystemReqParams(const uint8_t *p, size_t length,
   SshSubsystemReqParams *requestParams)
{
   error_t error;

   //Parse subsystem name
   error = sshParseString(p, length, &requestParams->subsystemName);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + requestParams->subsystemName.length))
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "window-change" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] requestParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseWindowChangeReqParams(const uint8_t *p, size_t length,
   SshWindowChangeReqParams *requestParams)
{
   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in characters)
   requestParams->termWidthChars = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in rows)
   requestParams->termHeightRows = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length < sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal width (in pixels)
   requestParams->termWidthPixels = LOAD32BE(p);

   //Point to the next field
   p += sizeof(uint32_t);
   length -= sizeof(uint32_t);

   //Malformed request?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get terminal height (in pixels)
   requestParams->termHeightPixels = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Term Width (chars) = %" PRIu32 "\r\n", requestParams->termWidthChars);
   TRACE_INFO("  Term Height (rows) = %" PRIu32 "\r\n", requestParams->termHeightRows);
   TRACE_INFO("  Term Width (pixels) = %" PRIu32 "\r\n", requestParams->termWidthPixels);
   TRACE_INFO("  Term Height (pixels) = %" PRIu32 "\r\n", requestParams->termHeightPixels);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "signal" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] requestParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseSignalReqParams(const uint8_t *p, size_t length,
   SshSignalReqParams *requestParams)
{
   error_t error;

   //Parse signal name
   error = sshParseString(p, length, &requestParams->signalName);
   //Any error to report?
   if(error)
      return error;

   //Malformed request?
   if(length != (sizeof(uint32_t) + requestParams->signalName.length))
      return ERROR_INVALID_MESSAGE;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse "exit-status" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] requestParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseExitStatusReqParams(const uint8_t *p, size_t length,
   SshExitStatusReqParams *requestParams)
{
   //Malformed request?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get exit status
   requestParams->exitStatus = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Exit status = %" PRIu32 "\r\n", requestParams->exitStatus);

   //Successful processing
   return NO_ERROR;
}

/**
 * @brief Parse "break" request specific data
 * @param[in] p Pointer to the request type specific data
 * @param[in] length Length of the request specific data, in bytes
 * @param[out] requestParams Information resulting from the parsing process
 * @return Error code
 **/

error_t sshParseBreakReqParams(const uint8_t *p, size_t length,
   SshBreakReqParams *requestParams)
{
   //Malformed request?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Get break length (in milliseconds)
   requestParams->breakLen = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Break Length (ms) = %" PRIu32 "\r\n", requestParams->breakLen);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_SUCCESS message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelSuccess(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_SUCCESS message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode the recipient channel
   recipientChannel = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Recipient Channel = %" PRIu32 "\r\n", recipientChannel);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->closeReceived)
      {
         //Check channel request state
         if(channel->requestState == SSH_REQUEST_STATE_PENDING)
         {
            //Update channel request state
            channel->requestState = SSH_REQUEST_STATE_SUCCESS;

            //Successfull processing
            error = NO_ERROR;
         }
         else
         {
            //Invalid channel request state
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //Invalid channel state
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //The recipient channel number is not valid
      error = ERROR_INVALID_CHANNEL;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&connection->context->mutex);

   //Return status code
   return error;
}


/**
 * @brief Parse SSH_MSG_CHANNEL_FAILURE message
 * @param[in] connection Pointer to the SSH connection
 * @param[in] message Pointer to message
 * @param[in] length Length of the message, in bytes
 * @return Error code
 **/

error_t sshParseChannelFailure(SshConnection *connection,
   const uint8_t *message, size_t length)
{
   error_t error;
   const uint8_t *p;
   uint32_t recipientChannel;
   SshChannel *channel;

   //Debug message
   TRACE_INFO("SSH_MSG_CHANNEL_FAILURE message received (%" PRIuSIZE " bytes)...\r\n", length);
   TRACE_VERBOSE_ARRAY("  ", message, length);

   //Check connection state
   if(connection->state != SSH_CONN_STATE_OPEN)
      return ERROR_UNEXPECTED_MESSAGE;

   //Sanity check
   if(length < sizeof(uint8_t))
      return ERROR_INVALID_MESSAGE;

   //Point to the first field of the message
   p = message + sizeof(uint8_t);
   //Remaining bytes to process
   length -= sizeof(uint8_t);

   //Malformed message?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_MESSAGE;

   //Decode the recipient channel
   recipientChannel = LOAD32BE(p);

   //Debug message
   TRACE_INFO("  Recipient Channel = %" PRIu32 "\r\n", recipientChannel);

   //Acquire exclusive access to the SSH context
   osAcquireMutex(&connection->context->mutex);

   //Point to the matching channel
   channel = sshGetChannel(connection, recipientChannel);

   //Valid channel?
   if(channel != NULL)
   {
      //Check channel state
      if(channel->state == SSH_CHANNEL_STATE_OPEN && !channel->closeReceived)
      {
         //Check channel request state
         if(channel->requestState == SSH_REQUEST_STATE_PENDING)
         {
            //Update channel request state
            channel->requestState = SSH_REQUEST_STATE_FAILURE;

            //Successfull processing
            error = NO_ERROR;
         }
         else
         {
            //Invalid channel request state
            error = ERROR_UNEXPECTED_MESSAGE;
         }
      }
      else
      {
         //Invalid channel state
         error = ERROR_UNEXPECTED_MESSAGE;
      }
   }
   else
   {
      //The recipient channel number is not valid
      error = ERROR_INVALID_CHANNEL;
   }

   //Release exclusive access to the SSH context
   osReleaseMutex(&connection->context->mutex);

   //Return status code
   return error;
}

#endif
