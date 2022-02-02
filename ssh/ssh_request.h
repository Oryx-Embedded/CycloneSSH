/**
 * @file ssh_request.h
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

#ifndef _SSH_REQUEST_H
#define _SSH_REQUEST_H

//Dependencies
#include "ssh/ssh.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief "tcpip-forward" request specific parameters
 **/

typedef struct
{
   SshString addrToBind;
   uint32_t portNumToBind;
} SshFwdReqParams;


/**
 * @brief "cancel-tcpip-forward" request specific parameters
 **/

typedef struct
{
   SshString addrToBind;
   uint32_t portNumToBind;
} SshCancelFwdReqParams;


/**
 * @brief "x11" channel specific parameters
 **/

typedef struct
{
   SshString originatorAddr;
   uint32_t originatorPort;
} SshX11ChannelParams;


/**
 * @brief "forwarded-tcpip" channel specific parameters
 **/

typedef struct
{
   SshString addr;
   uint32_t port;
   SshString originatorAddr;
   uint32_t originatorPort;
} SshForwardedTcpIpChannelParams;


/**
 * @brief "direct-tcpip" channel specific parameters
 **/

typedef struct
{
   SshString host;
   uint32_t port;
   SshString originatorAddr;
   uint32_t originatorPort;
} SshDirectTcpipChannelParams;


/**
 * @brief "pty-req" request specific parameters
 **/

typedef struct
{
   SshString termEnvVar;
   uint32_t termWidthChars;
   uint32_t termHeightRows;
   uint32_t termWidthPixels;
   uint32_t termHeightPixels;
   SshBinaryString termModes;
} SshPtyReqParams;


/**
 * @brief "x11-req" request specific parameters
 **/

typedef struct
{
   bool_t singleConnection;
   SshString x11AuthProtocol;
   SshString x11AuthCookie;
   uint32_t x11ScreenNum;
} SshX11ReqParams;


/**
 * @brief "env" request specific parameters
 **/

typedef struct
{
   SshString varName;
   SshString varValue;
} SshEnvReqParams;


/**
 * @brief "exec" request specific parameters
 **/

typedef struct
{
   SshString command;
} SshExecReqParams;


/**
 * @brief "subsystem" request specific parameters
 **/

typedef struct
{
   SshString subsystemName;
} SshSubsystemReqParams;


/**
 * @brief "window-change" request specific parameters
 **/

typedef struct
{
   uint32_t termWidthChars;
   uint32_t termHeightRows;
   uint32_t termWidthPixels;
   uint32_t termHeightPixels;
} SshWindowChangeReqParams;


/**
 * @brief "xon-xoff" request specific parameters
 **/

typedef struct
{
   bool_t clientCanDo;
} SshXonXoffReqParams;


/**
 * @brief "signal" request specific parameters
 **/

typedef struct
{
   SshString signalName;
} SshSignalReqParams;


/**
 * @brief "exit-status" request specific parameters
 **/

typedef struct
{
   uint32_t exitStatus;
} SshExitStatusReqParams;


/**
 * @brief "exit-signal" request specific parameters
 **/

typedef struct
{
   SshString signalName;
   bool_t coreDumped;
   SshString errorMessage;
   SshString languageTag;
} SshExitSignalReqParams;


/**
 * @brief "break" request specific parameters
 **/

typedef struct
{
   uint32_t breakLen;
} SshBreakReqParams;


//SSH related functions
error_t sshSendGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply);

error_t sshSendRequestSuccess(SshConnection *connection);
error_t sshSendRequestFailure(SshConnection *connection);

error_t sshSendChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply);

error_t sshSendChannelSuccess(SshChannel *channel);
error_t sshSendChannelFailure(SshChannel *channel);

error_t sshFormatGlobalRequest(SshConnection *connection,
   const char_t *requestName, const void *requestParams, bool_t wantReply,
   uint8_t *p, size_t *length);

error_t sshFormatFwdReqParams(const SshFwdReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatCancelFwdReqParams(const SshCancelFwdReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatRequestSuccess(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatRequestFailure(SshConnection *connection, uint8_t *p,
   size_t *length);

error_t sshFormatChannelRequest(SshChannel *channel, const char_t *requestType,
   const void *requestParams, bool_t wantReply, uint8_t *p, size_t *length);

error_t sshFormatPtyReqParams(const SshPtyReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatExecReqParams(const SshExecReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatSubsystemReqParams(const SshSubsystemReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatWindowChangeReqParams(const SshWindowChangeReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatSignalReqParams(const SshSignalReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatExitStatusReqParams(const SshExitStatusReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatBreakReqParams(const SshBreakReqParams *requestParams,
   uint8_t *p, size_t *written);

error_t sshFormatChannelSuccess(SshChannel *channel, uint8_t *p,
   size_t *length);

error_t sshFormatChannelFailure(SshChannel *channel, uint8_t *p,
   size_t *length);

error_t sshParseGlobalRequest(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseRequestSuccess(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseRequestFailure(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelRequest(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParsePtyReqParams(const uint8_t *p, size_t length,
   SshPtyReqParams *requestParams);

error_t sshParseExecReqParams(const uint8_t *p, size_t length,
   SshExecReqParams *requestParams);

bool_t sshGetExecReqArg(const SshExecReqParams *requestParams, uint_t index,
   SshString *arg);

error_t sshParseSubsystemReqParams(const uint8_t *p, size_t length,
   SshSubsystemReqParams *requestParams);

error_t sshParseWindowChangeReqParams(const uint8_t *p, size_t length,
   SshWindowChangeReqParams *requestParams);

error_t sshParseSignalReqParams(const uint8_t *p, size_t length,
   SshSignalReqParams *requestParams);

error_t sshParseExitStatusReqParams(const uint8_t *p, size_t length,
   SshExitStatusReqParams *requestParams);

error_t sshParseBreakReqParams(const uint8_t *p, size_t length,
   SshBreakReqParams *requestParams);

error_t sshParseChannelSuccess(SshConnection *connection,
   const uint8_t *message, size_t length);

error_t sshParseChannelFailure(SshConnection *connection,
   const uint8_t *message, size_t length);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
