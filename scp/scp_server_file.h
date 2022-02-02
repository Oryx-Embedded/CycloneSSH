/**
 * @file scp_server_file.h
 * @brief File operations
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

#ifndef _SCP_SERVER_FILE_H
#define _SCP_SERVER_FILE_H

//Dependencies
#include "scp/scp_server.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//SCP server related functions
error_t scpServerOpenFileForWriting(ScpServerSession *session,
   const char_t *filename, uint32_t mode, uint64_t size);

error_t scpServerOpenFileForReading(ScpServerSession *session);

error_t scpServerWriteData(ScpServerSession *session);
error_t scpServerReadData(ScpServerSession *session);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
