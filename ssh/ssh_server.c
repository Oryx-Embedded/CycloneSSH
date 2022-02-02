/**
 * @file ssh_server.c
 * @brief SSH server
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
#include "ssh/ssh_misc.h"
#include "ssh/ssh_server.h"
#include "ssh/ssh_server_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED && SSH_SERVER_SUPPORT == ENABLED)


/**
 * @brief Initialize settings with default values
 * @param[out] settings Structure that contains SSH server settings
 **/

void sshServerGetDefaultSettings(SshServerSettings *settings)
{
   //The SSH server is not bound to any interface
   settings->interface = NULL;

   //SSH port number
   settings->port = SSH_PORT;

   //SSH connections
   settings->numConnections = 0;
   settings->connections = NULL;

   //SSH channels
   settings->numChannels = 0;
   settings->channels = NULL;

   //Pseudo-random number generator
   settings->prngAlgo = NULL;
   settings->prngContext = NULL;

#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
   //Public key authentication callback function
   settings->publicKeyAuthCallback = NULL;
#endif

#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
   //Password authentication callback function
   settings->passwordAuthCallback = NULL;
   //Password change callback function
   settings->passwordChangeCallback = NULL;
#endif

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
   //Signature generation callback function
   settings->signGenCallback = NULL;
   //Signature verification callback function
   settings->signVerifyCallback = NULL;
#endif

#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
   //ECDH key pair generation callback
   settings->ecdhKeyPairGenCallback = NULL;
   //ECDH shared secret calculation callback
   settings->ecdhSharedSecretCalcCallback = NULL;
#endif
}


/**
 * @brief Initialize SSH server context
 * @param[in] context Pointer to the SSH server context
 * @param[in] settings SSH server specific settings
 * @return Error code
 **/

error_t sshServerInit(SshServerContext *context,
   const SshServerSettings *settings)
{
   error_t error;

   //Debug message
   TRACE_INFO("Initializing SSH server...\r\n");

   //Ensure the parameters are valid
   if(context == NULL || settings == NULL)
      return ERROR_INVALID_PARAMETER;

   //Invalid number of SSH connections?
   if(settings->numConnections < 1 ||
      settings->numConnections > SSH_MAX_CONNECTIONS)
   {
      return ERROR_INVALID_PARAMETER;
   }

   //Invalid number of SSH channels?
   if(settings->numChannels < settings->numConnections)
      return ERROR_INVALID_PARAMETER;

   //Initialize SSH context
   error = sshInit(&context->sshContext, settings->connections,
      settings->numConnections, settings->channels, settings->numChannels);
   //Any error to report?
   if(error)
      return error;

   //Save settings
   context->interface = settings->interface;
   context->port = settings->port;

   //Start of exception handling block
   do
   {
      //Select server operation mode
      error = sshSetOperationMode(&context->sshContext,
         SSH_OPERATION_MODE_SERVER);
      //Any error to report?
      if(error)
         break;

      //Set the pseudo-random number generator to be used
      error = sshSetPrng(&context->sshContext, settings->prngAlgo,
         settings->prngContext);
      //Any error to report?
      if(error)
         break;

#if (SSH_PUBLIC_KEY_AUTH_SUPPORT == ENABLED)
      //Valid public key authentication callback function?
      if(settings->publicKeyAuthCallback != NULL)
      {
         //Register callback function
         error = sshRegisterPublicKeyAuthCallback(&context->sshContext,
            settings->publicKeyAuthCallback);
         //Any error to report?
         if(error)
            break;
      }
#endif

#if (SSH_PASSWORD_AUTH_SUPPORT == ENABLED)
      //Valid password authentication callback function?
      if(settings->passwordAuthCallback != NULL)
      {
         //Register callback function
         error = sshRegisterPasswordAuthCallback(&context->sshContext,
            settings->passwordAuthCallback);
         //Any error to report?
         if(error)
            break;
      }

      //Valid password change callback function?
      if(settings->passwordChangeCallback != NULL)
      {
         //Register callback function
         error = sshRegisterPasswordChangeCallback(&context->sshContext,
            settings->passwordChangeCallback);
         //Any error to report?
         if(error)
            break;
      }
#endif

#if (SSH_SIGN_CALLBACK_SUPPORT == ENABLED)
      //Valid signature generation callback function?
      if(settings->signGenCallback != NULL)
      {
         //Register callback function
         error = sshRegisterSignGenCallback(&context->sshContext,
            settings->signGenCallback);
         //Any error to report?
         if(error)
            break;
      }

      //Valid signature verification callback function?
      if(settings->signVerifyCallback != NULL)
      {
         //Register callback function
         error = sshRegisterSignVerifyCallback(&context->sshContext,
            settings->signVerifyCallback);
         //Any error to report?
         if(error)
            break;
      }
#endif

#if (SSH_ECDH_CALLBACK_SUPPORT == ENABLED)
      //Valid ECDH key pair generation callback function?
      if(settings->ecdhKeyPairGenCallback != NULL)
      {
         //Register callback function
         error = sshRegisterEcdhKeyPairGenCallback(&context->sshContext,
            settings->ecdhKeyPairGenCallback);
         //Any error to report?
         if(error)
            break;
      }

      //Valid ECDH shared secret calculation callback function?
      if(settings->ecdhSharedSecretCalcCallback != NULL)
      {
         //Register callback function
         error = sshRegisterEcdhSharedSecretCalcCallback(&context->sshContext,
            settings->ecdhSharedSecretCalcCallback);
         //Any error to report?
         if(error)
            break;
      }
#endif

      //End of exception handling block
   } while(0);

   //Check status code
   if(error)
   {
      //Clean up side effects
      sshServerDeinit(context);
   }

   //Return status code
   return error;
}


/**
 * @brief Register global request callback function
 * @param[in] context Pointer to the SSH server context
 * @param[in] callback Global request callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshServerRegisterGlobalRequestCallback(SshServerContext *context,
   SshGlobalReqCallback callback, void *param)
{
   //Register global request callback function
   return sshRegisterGlobalRequestCallback(&context->sshContext, callback,
      param);
}


/**
 * @brief Unregister global request callback function
 * @param[in] context Pointer to the SSH server context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshServerUnregisterGlobalRequestCallback(SshServerContext *context,
   SshGlobalReqCallback callback)
{
   //Unregister global request callback function
   return sshUnregisterGlobalRequestCallback(&context->sshContext, callback);
}


/**
 * @brief Register channel request callback function
 * @param[in] context Pointer to the SSH server context
 * @param[in] callback Channel request callback function
 * @param[in] param An opaque pointer passed to the callback function
 * @return Error code
 **/

error_t sshServerRegisterChannelRequestCallback(SshServerContext *context,
   SshChannelReqCallback callback, void *param)
{
   //Register channel request callback function
   return sshRegisterChannelRequestCallback(&context->sshContext, callback,
      param);
}


/**
 * @brief Unregister channel request callback function
 * @param[in] context Pointer to the SSH server context
 * @param[in] callback Previously registered callback function
 * @return Error code
 **/

error_t sshServerUnregisterChannelRequestCallback(SshServerContext *context,
   SshChannelReqCallback callback)
{
   //Unregister channel request callback function
   return sshUnregisterChannelRequestCallback(&context->sshContext, callback);
}


/**
 * @brief Load server's host key
 * @param[in] context Pointer to the SSH server context
 * @param[in] publicKey Public key (PEM, SSH2 or OpenSSH format)
 * @param[in] publicKeyLen Length of the public key
 * @param[in] privateKey Private key (PEM format)
 * @param[in] privateKeyLen Length of the private key
 * @return Error code
 **/

error_t sshServerLoadHostKey(SshServerContext *context, const char_t *publicKey,
   size_t publicKeyLen, const char_t *privateKey, size_t privateKeyLen)
{
   error_t error;

   //Ensure the SSH server is stopped
   if(!context->running)
   {
      //Add a new key pair
      error = sshLoadHostKey(&context->sshContext, publicKey, publicKeyLen,
         privateKey, privateKeyLen);
   }
   else
   {
      //Host keys cannot be changed while the SSH server is running
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Unload all server's host keys
 * @param[in] context Pointer to the SSH server context
 * @return Error code
 **/

error_t sshServerUnloadAllHostKeys(SshServerContext *context)
{
   error_t error;

   //Ensure the SSH server is stopped
   if(!context->running)
   {
      //Remove all the key pairs that have been previously loaded
      error = sshUnloadAllHostKeys(&context->sshContext);
   }
   else
   {
      //Host keys cannot be changed while the SSH server is running
      error = ERROR_WRONG_STATE;
   }

   //Return status code
   return error;
}


/**
 * @brief Start SSH server
 * @param[in] context Pointer to the SSH server context
 * @return Error code
 **/

error_t sshServerStart(SshServerContext *context)
{
   error_t error;

   //Make sure the SSH server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Starting SSH server...\r\n");

   //Make sure the SSH server is not already running
   if(context->running)
      return ERROR_ALREADY_RUNNING;

   //Start of exception handling block
   do
   {
      //Open a TCP socket
      context->socket = socketOpen(SOCKET_TYPE_STREAM, SOCKET_IP_PROTO_TCP);

      //Failed to open socket?
      if(context->socket == NULL)
      {
         //Report an error
         error = ERROR_OPEN_FAILED;
         //Exit immediately
         break;
      }

      //Force the socket to operate in non-blocking mode
      error = socketSetTimeout(context->socket, 0);
      //Any error to report?
      if(error)
         break;

      //Associate the socket with the relevant interface
      error = socketBindToInterface(context->socket, context->interface);
      //Any error to report?
      if(error)
         break;

      //The SSH server listens for connection requests on port 22
      error = socketBind(context->socket, &IP_ADDR_ANY, context->port);
      //Any error to report?
      if(error)
         break;

      //Place socket in listening state
      error = socketListen(context->socket, 0);
      //Any error to report?
      if(error)
         break;

      //Start the SSH server
      context->stop = FALSE;
      context->running = TRUE;

#if (OS_STATIC_TASK_SUPPORT == ENABLED)
      //Create a task using statically allocated memory
      context->taskId = osCreateStaticTask("SSH Server",
         (OsTaskCode) sshServerTask, context, &context->taskTcb,
         context->taskStack, SSH_SERVER_STACK_SIZE, SSH_SERVER_PRIORITY);
#else
      //Create a task
      context->taskId = osCreateTask("SSH Server", (OsTaskCode) sshServerTask,
         context, SSH_SERVER_STACK_SIZE, SSH_SERVER_PRIORITY);
#endif

      //Failed to create task?
      if(context->taskId == OS_INVALID_TASK_ID)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         break;
      }

      //End of exception handling block
   } while(0);

   //Any error to report?
   if(error)
   {
      //Clean up side effects
      context->running = FALSE;

      //Close listening socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Return status code
   return error;
}


/**
 * @brief Stop SSH server
 * @param[in] context Pointer to the SSH server context
 * @return Error code
 **/

error_t sshServerStop(SshServerContext *context)
{
   uint_t i;

   //Make sure the SSH server context is valid
   if(context == NULL)
      return ERROR_INVALID_PARAMETER;

   //Debug message
   TRACE_INFO("Stopping SSH server...\r\n");

   //Check whether the SSH server is running
   if(context->running)
   {
      //Stop the SSH server
      context->stop = TRUE;
      //Send a signal to the task to abort any blocking operation
      sshNotifyEvent(&context->sshContext);

      //Wait for the task to terminate
      while(context->running)
      {
         osDelayTask(1);
      }

      //Loop through SSH connections
      for(i = 0; i < context->sshContext.numConnections; i++)
      {
         //Active connection?
         if(context->sshContext.connections[i].state != SSH_CONN_STATE_CLOSED)
         {
            //Close the SSH connection
            sshCloseConnection(&context->sshContext.connections[i]);
         }
      }

      //Close listening socket
      socketClose(context->socket);
      context->socket = NULL;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief SSH server task
 * @param[in] context Pointer to the SSH server context
 **/

void sshServerTask(SshServerContext *context)
{
   error_t error;
   uint_t i;
   SshContext *sshContext;
   SshConnection *connection;

   //Point to the SSH context
   sshContext = &context->sshContext;

#if (NET_RTOS_SUPPORT == ENABLED)
   //Task prologue
   osEnterTask();

   //Process events
   while(1)
   {
#endif
      //Clear event descriptor set
      osMemset(sshContext->eventDesc, 0, sizeof(sshContext->eventDesc));

      //Specify the events the application is interested in
      for(i = 0; i < sshContext->numConnections; i++)
      {
         //Point to the structure describing the current connection
         connection = &sshContext->connections[i];

         //Loop through active connections only
         if(connection->state != SSH_CONN_STATE_CLOSED)
         {
            //Register the events related to the current SSH connection
            sshRegisterConnectionEvents(sshContext, connection,
               &sshContext->eventDesc[i]);
         }
      }

      //The SSH server listens for connection requests on port 22
      sshContext->eventDesc[i].socket = context->socket;
      sshContext->eventDesc[i].eventMask = SOCKET_EVENT_ACCEPT;

      //Wait for one of the set of sockets to become ready to perform I/O
      error = socketPoll(sshContext->eventDesc, sshContext->numConnections + 1,
         &sshContext->event, SSH_SERVER_TICK_INTERVAL);

      //Check status code
      if(error == NO_ERROR || error == ERROR_TIMEOUT)
      {
         //Stop request?
         if(context->stop)
         {
            //Stop SSH server operation
            context->running = FALSE;
            //Task epilogue
            osExitTask();
            //Kill ourselves
            osDeleteTask(OS_SELF_TASK_ID);
         }

         //Event-driven processing
         for(i = 0; i < sshContext->numConnections; i++)
         {
            //Point to the structure describing the current connection
            connection = &sshContext->connections[i];

            //Loop through active connections only
            if(connection->state != SSH_CONN_STATE_CLOSED)
            {
               //Check whether the socket is ready to perform I/O
               if(sshContext->eventDesc[i].eventFlags != 0)
               {
                  //Connection event handler
                  error = sshProcessConnectionEvents(sshContext, connection);

                  //Any communication error?
                  if(error != NO_ERROR && error != ERROR_TIMEOUT)
                  {
                     //Close the SSH connection
                     sshCloseConnection(connection);
                  }
               }
            }
         }

         //Any connection request received on port 22?
         if(sshContext->eventDesc[i].eventFlags != 0)
         {
            //Accept connection request
            sshServerAcceptConnection(context);
         }
      }

      //Handle periodic operations
      sshServerTick(context);

#if (NET_RTOS_SUPPORT == ENABLED)
   }
#endif
}


/**
 * @brief Release SSH server context
 * @param[in] context Pointer to the SSH server context
 **/

void sshServerDeinit(SshServerContext *context)
{
   //Make sure the SSH server context is valid
   if(context != NULL)
   {
      //Close listening socket
      socketClose(context->socket);

      //Release SSH context
      sshDeinit(&context->sshContext);

      //Clear SSH server context
      osMemset(context, 0, sizeof(SshServerContext));
   }
}

#endif
