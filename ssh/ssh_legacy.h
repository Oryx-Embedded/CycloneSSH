/**
 * @file ssh_legacy.h
 * @brief Legacy definitions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2019-2021 Oryx Embedded SARL. All rights reserved.
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
 * @version 2.0.4
 **/

#ifndef _SSH_LEGACY_H
#define _SSH_LEGACY_H

//Deprecated definitions
#define SshClientConnection SshConnection
#define SshWindowChangeParams SshWindowChangeReqParams
#define passwordCallback passwordAuthCallback
#define termWidthChar termWidthChars
#define termHeightChar termHeightRows
#define termWidthPixel termWidthPixels
#define termHeightPixel termHeightPixels

//Deprecated functions
#define sshServerSetTimeout sshSetChannelTimeout
#define sshServerWriteChannel sshWriteChannel
#define sshServerReadChannel sshReadChannel
#define sshServerTerminateChannel sshCloseChannel
#define sshParseWindowChangeParams sshParseWindowChangeReqParams

#endif
