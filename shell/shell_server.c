/**
 * @file shell_server.c
 * @brief SSH secure shell server
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

//Switch to the appropriate trace level
#define TRACE_LEVEL SHELL_TRACE_LEVEL

//Dependencies
#include "ssh/ssh.h"
#include "shell/shell_server.h"
#include "shell/shell_server_pty.h"
#include "shell/shell_server_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SHELL_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains shell server settings
 **/

void shellServerGetDefaultSettings(ShellServerSettings *settings)
{
   //SSH server context
   settings->sshServerContext = NULL;

   //Shell sessions
   settings->numSessions = 0;
   settings->sessions = NULL;

   //User verification callback function
   settings->checkUserCallback = NULL;
   //Command line processing callback function
   settings->commandLineCallback = NULL;
}


/**
 * @brief Initialize shell server context
 * @param[in] context Pointer to the shell server context
 * @param[in] settings Shell server specific settings
 * @return Error code
 **/

error_t shellServerInit(ShellServerContext *context,
   const ShellServerSettings *settings)
{
   uint_t i;

   //Debug message
   TRACE_INFO("Initializing shell server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid shell sessions?
   if(settings->sessions == NULL || settings->numSessions < 1 ||
      settings->numSessions > SHELL_SERVER_MAX_SESSIONS)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Clear shell server context
   osMemset(context, 0, sizeof(ShellServerContext));

   //Save user settings
   context->sshServerContext = settings->sshServerContext;
   context->numSessions = settings->numSessions;
   context->sessions = settings->sessions;
   context->checkUserCallback = settings->checkUserCallback;
   context->commandLineCallback = settings->commandLineCallback;

   //Loop through shell sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Initialize the structure representing the shell session
      osMemset(&context->sessions[i], 0, sizeof(ShellServerSession));

      //Create an event object to manage session lifetime
      if(!osCreateEvent(&context->sessions[i].startEvent))
         return ERROR_OUT_OF_RESOURCES;

      //Create an event object to manage session events
      if(!osCreateEvent(&context->sessions[i].event))
         return ERROR_OUT_OF_RESOURCES;
   }

   //Create an event object to poll the state of channels
   if(!osCreateEvent(&context->event))
      return ERROR_OUT_OF_RESOURCES;

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Start shell server
 * @param[in] context Pointer to the shell server context
 * @return Error code
 **/

error_t shellServerStart(ShellServerContext *context)
{
   error_t error;
   uint_t i;
   OsTask *task;

   //Make sure the shell server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting shell server...\r\n");

   //Make sure the shell server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Register channel request processing callback
   error = sshServerRegisterChannelRequestCallback(context->sshServerContext,
      shellServerChannelRequestCallback, context);
   //Any error to report?
   if(error)
      return error;

   //Loop through the shell sessions
   for(i = 0; i < context->numSessions; i++)
   {
      //Create a task to service a given shell session
      task = osCreateTask("Shell Session", shellServerTask,
         &context->sessions[i], SHELL_SERVER_STACK_SIZE,
         SHELL_SERVER_PRIORITY);

      //Failed to create task?
      if(task == NULL)
         return ERROR_OUT_OF_RESOURCES;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set welcome banner
 * @param[in] session Handle referencing a shell session
 * @param[in] banner NULL-terminated string containing the banner message
 * @return Error code
 **/

error_t shellServerSetBanner(ShellServerSession *session,
   const char_t *banner)
{
   size_t n;

   //Check parameters
   if(session == NULL || banner == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the banner message
   n = osStrlen(banner);

   //Check the length of the string
   if(n > SHELL_SERVER_BUFFER_SIZE)
      return ERROR_INVALID_LENGTH;

   //Copy the banner message
   osStrncpy(session->buffer, banner, n);

   //Save the length of the banner message
   session->bufferLen = n;
   session->bufferPos = 0;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set shell prompt
 * @param[in] session Handle referencing a shell session
 * @param[in] prompt NULL-terminated string containing the prompt to be used
 * @return Error code
 **/

error_t shellServerSetPrompt(ShellServerSession *session,
   const char_t *prompt)
{
   //Check parameters
   if(session == NULL || prompt == NULL)
      return ERROR_INVALID_PARAMETER;

   //Check the length of the prompt string
   if(osStrlen(prompt) > SHELL_SERVER_MAX_PROMPT_LEN)
      return ERROR_INVALID_LENGTH;

   //Set the shell prompt to be used
   osStrcpy(session->prompt, prompt);
   //Save the length of the prompt string
   session->promptLen = osStrlen(prompt);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Set timeout for read/write operations
 * @param[in] session Handle referencing a shell session
 * @param[in] timeout Maximum time to wait
 * @return Error code
 **/

error_t shellServerSetTimeout(ShellServerSession *session, systime_t timeout)
{
   error_t error;

   //Valid shell session?
   if(session != NULL)
   {
      //Set timeout for read/write operations
      error = sshSetChannelTimeout(session->channel, timeout);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Write to stdout stream
 * @param[in] session Handle referencing a shell session
 * @param[in] data Pointer to a buffer containing the data to be written
 * @param[in] length Number of data bytes to write
 * @param[in] written Number of bytes that have been written (optional parameter)
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t shellServerWriteStream(ShellServerSession *session, const void *data,
   size_t length, size_t *written, uint_t flags)
{
   error_t error;

   //Valid shell session?
   if(session != NULL)
   {
      //Write data to the specified channel
      error = sshWriteChannel(session->channel, data, length, written, flags);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Read from stdin stream
 * @param[in] session Handle referencing a shell session
 * @param[out] data Buffer where to store the incoming data
 * @param[in] size Maximum number of bytes that can be read
 * @param[out] received Actual number of bytes that have been read
 * @param[in] flags Set of flags that influences the behavior of this function
 * @return Error code
 **/

error_t shellServerReadStream(ShellServerSession *session, void *data,
   size_t size, size_t *received, uint_t flags)
{
   error_t error;

   //Valid shell session?
   if(session != NULL)
   {
      //Receive data from the specified channel
      error = sshReadChannel(session->channel, data, size, received, flags);
   }
   else
   {
      //Report an error
      error = ERROR_INVALID_PARAMETER;
   }

   //Return status code
   return error;
}


/**
 * @brief Shell server task
 * @param[in] param Pointer to the shell session
 **/

void shellServerTask(void *param)
{
   error_t error;
   SshChannel *channel;
   ShellServerSession *session;

   //Point to the shell session
   session = (ShellServerSession *) param;

   //Debug message
   TRACE_INFO("Starting shell task...\r\n");

   //Initialize status code
   error = NO_ERROR;

   //Process connection requests
   while(1)
   {
      //Wait for an connection request
      osWaitForEvent(&session->startEvent, INFINITE_DELAY);

      //Debug message
      TRACE_INFO("Starting shell session...\r\n");

      //Retrieve SSH channel handle
      channel = session->channel;

      //Check session state
      if(session->state == SHELL_SERVER_SESSION_STATE_OPEN)
      {
         //Set timeout for read/write operations
         sshSetChannelTimeout(channel, INFINITE_DELAY);

         //Any banner message?
         if(session->bufferLen > 0)
         {
            //Display welcome banner
            error = sshWriteChannel(channel, session->buffer,
               session->bufferLen, NULL, 0);
         }

         //Check status code
         if(!error)
         {
            //Display shell prompt
            error = sshWriteChannel(channel, session->prompt,
               osStrlen(session->prompt), NULL, 0);
         }

         //Initialize variables
         session->bufferLen = 0;
         session->bufferPos = 0;
         session->escSeqLen = 0;

         //Process user commands
         while(!error)
         {
            SshChannelEventDesc eventDesc[1];

            //Specifying the events the application is interested in
            eventDesc[0].channel = channel;
            eventDesc[0].eventMask = SSH_CHANNEL_EVENT_RX_READY;
            eventDesc[0].eventFlags = 0;

            //Wait for the channel to become ready to perform I/O
            error = sshPollChannels(eventDesc, 1, &session->event,
               SHELL_SERVER_TICK_INTERVAL);

            //Check status code
            if(error == NO_ERROR || error == ERROR_TIMEOUT)
            {
               //Window resized?
               if(session->windowResize)
               {
                  //Process window resize event
                  error = shellServerProcessWindowResize(session);
               }

               //Character received?
               if(eventDesc[0].eventFlags != 0)
               {
                  //Process received character
                  error = shellServerProcessChar(session);
               }
               else
               {
                  //Wait for the next character
                  error = NO_ERROR;
               }
            }
            else
            {
               //A communication error has occurred
               break;
            }
         }
      }
      else if(session->state == SHELL_SERVER_SESSION_STATE_EXEC)
      {
         //Properly terminate the command line with a NULL character
         session->buffer[session->bufferLen] = '\0';
         //Process command line
         error = shellServerProcessCommandLine(session, session->buffer);
      }
      else
      {
         //Just for sanity
      }

      //Close SSH channel
      sshCloseChannel(channel);

      //Mark the current session as closed
      session->state = SHELL_SERVER_SESSION_STATE_CLOSED;

      //Debug message
      TRACE_INFO("Shell session terminated...\r\n");
   }
}

#endif
