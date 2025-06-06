/**
 * @file ssh_key_decrypt.c
 * @brief SSH private key decryption
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
#include "ssh/ssh_key_import.h"
#include "ssh/ssh_key_export.h"
#include "ssh/ssh_key_format.h"
#include "ssh/ssh_key_decrypt.h"
#include "ssh/ssh_misc.h"
#include "cipher/aes.h"
#include "cipher/blowfish.h"
#include "cipher_modes/ctr.h"
#include "pkix/pem_decrypt.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief SSH private key decryption
 * @param[in] input Pointer to the encrypted private key (PEM or OpenSSH format)
 * @param[in] inputLen Length of the encrypted private key
 * @param[in] password NULL-terminated string containing the password
 * @param[out] output Pointer to decrypted private key
 * @param[out] outputLen Length of the decrypted private key
 * @return Error code
 **/

error_t sshDecryptPrivateKey(const char_t *input, size_t inputLen,
   const char_t *password, char_t *output, size_t *outputLen)
{
#if (SSH_ENCRYPTED_KEY_SUPPORT == ENABLED)
   error_t error;
   size_t n;
   size_t length;
   uint8_t *p;
   uint8_t *buffer;
   SshPrivateKeyHeader privateKeyHeader;

   //Check parameters
   if(input == NULL || password == NULL || output == NULL || outputLen == NULL)
      return ERROR_INVALID_PARAMETER;

   //Retrieve the length of the private key structure
   error = sshDecodeOpenSshPrivateKeyFile(input, inputLen, NULL, &n);

   //Check status code
   if(!error)
   {
      //Allocate a memory buffer to hold the private key structure
      buffer = sshAllocMem(n);

      //Successful memory allocation?
      if(buffer != NULL)
      {
         //Decode the content of the private key file (OpenSSH format)
         error = sshDecodeOpenSshPrivateKeyFile(input, inputLen, buffer, &n);

         //Check status code
         if(!error)
         {
            //Parse private key header
            error = sshParseOpenSshPrivateKeyHeader(buffer, n,
               &privateKeyHeader);
         }

         //Check status code
         if(!error)
         {
            //Point to the encrypted data
            p = (uint8_t *) privateKeyHeader.encrypted.value;
            length = privateKeyHeader.encrypted.length;

            //Perform decryption operation
            error = sshDecryptOpenSshPrivateKey(&privateKeyHeader, password,
               p, p, length);
         }

         //Check status code
         if(!error)
         {
            //Point to the output buffer
            p = (uint8_t *) output;
            length = 0;

            //Format private key header
            error = sshFormatOpenSshPrivateKeyHeader(p, &n);
         }

         //Check status code
         if(!error)
         {
            //Point to the next field
            p += n;
            length += n;

            //Format 'publickey' field
            error = sshFormatBinaryString(privateKeyHeader.publicKey.value,
               privateKeyHeader.publicKey.length, p, &n);
         }

         //Check status code
         if(!error)
         {
            //Point to the next field
            p += n;
            length += n;

            //Format 'encrypted' field
            error = sshFormatBinaryString(privateKeyHeader.encrypted.value,
               privateKeyHeader.encrypted.length, p, &n);
         }

         //Check status code
         if(!error)
         {
            //Point to the next field
            p += n;
            length += n;

            //Convert the private key structure to OpenSSH format
            error = sshEncodeOpenSshPrivateKeyFile(output, length, output,
               outputLen);
         }

         //Release previously allocated memory
         sshFreeMem(buffer);
      }
      else
      {
         //Failed to allocate memory
         error = ERROR_OUT_OF_MEMORY;
      }
   }
   else
   {
      //Decrypt the private key (PEM format)
      error = pemDecryptPrivateKey(input, inputLen, password, output,
         outputLen);
   }

   //Return status code
   return error;
#else
   //Encrypted private keys are not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief OpenSSH private key decryption
 * @param[in] privateKeyHeader Private key header
 * @param[in] password NULL-terminated string containing the password
 * @param[in] ciphertext Pointer to the ciphertext data
 * @param[out] plaintext Pointer to the plaintext data
 * @param[in] length Total number of data bytes to be decrypted
 * @return Error code
 **/

error_t sshDecryptOpenSshPrivateKey(const SshPrivateKeyHeader *privateKeyHeader,
   const char_t *password, const uint8_t *ciphertext, uint8_t *plaintext,
   size_t length)
{
   //Check KDF and cipher algorithms
   if(sshCompareString(&privateKeyHeader->kdfName, "none") &&
      sshCompareString(&privateKeyHeader->cipherName, "none"))
   {
      //The length of the 'encrypted' section must be a multiple of 8
      if((privateKeyHeader->encrypted.length % 8) != 0)
         return ERROR_INVALID_SYNTAX;

      //The key is not encrypted
      osMemmove(plaintext, ciphertext, length);
   }
   else if(sshCompareString(&privateKeyHeader->kdfName, "bcrypt") &&
      sshCompareString(&privateKeyHeader->cipherName, "aes256-ctr"))
   {
#if (SSH_ENCRYPTED_KEY_SUPPORT == ENABLED)
      error_t error;
      uint32_t checkInt1;
      uint32_t checkInt2;
      size_t passwordLen;
      uint8_t k[48];
      SshKdfOptions kdfOptions;
      AesContext *aesContext;

      //Sanity check
      if(privateKeyHeader->encrypted.length < 8)
         return ERROR_INVALID_SYNTAX;

      //The length of the 'encrypted' section must be a multiple of the
      //block size
      if((privateKeyHeader->encrypted.length % AES_BLOCK_SIZE) != 0)
         return ERROR_DECRYPTION_FAILED;

      //Parse KDF options
      error = sshParseKdfOptions(privateKeyHeader->kdfOptions.value,
         privateKeyHeader->kdfOptions.length, &kdfOptions);
      //Any error to report?
      if(error)
         return error;

      //Retrieve the length of the password
      passwordLen = osStrlen(password);

      //The KDF is used to derive a key, IV from the passphrase
      error = sshKdf(password, passwordLen, kdfOptions.salt.value,
         kdfOptions.salt.length, kdfOptions.rounds, k, 48);

      //Allocate a memory buffer to hold the AES context
      aesContext = sshAllocMem(sizeof(AesContext));

      //Successful memory allocation?
      if(aesContext != NULL)
      {
         //Load encryption key
         error = aesInit(aesContext, k, 32);

         //Check status code
         if(!error)
         {
            //Perform CTR decryption
            error = ctrDecrypt(AES_CIPHER_ALGO, aesContext, 128, k + 32,
               ciphertext, plaintext, length);
         }

         //Check status code
         if(!error)
         {
            //Decode 'checkint' fields
            checkInt1 = LOAD32BE(plaintext);
            checkInt2 = LOAD32BE(plaintext + 4);

            //Before the key is encrypted, a random integer is assigned to both
            //'checkint' fields so successful decryption can be quickly checked
            //by verifying that both checkint fields hold the same value
            if(checkInt1 != checkInt2)
            {
               error = ERROR_DECRYPTION_FAILED;
            }
         }

         //Erase cipher context
         aesDeinit(aesContext);
         //Release previously allocated memory
         sshFreeMem(aesContext);
      }
      else
      {
         //Report an error
         error = ERROR_OUT_OF_MEMORY;
      }

      //Any error to report?
      if(error)
         return error;
#else
      //Encrypted private keys are not supported
      return ERROR_DECRYPTION_FAILED;
#endif
   }
   else
   {
      //Unknown KDF or cipher algorithm
      return ERROR_DECRYPTION_FAILED;
   }

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Parse KDF options
 * @param[in] data Pointer to the KDF options
 * @param[in] length Length of the KDF options, in bytes
 * @param[out] kdfOptions Information resulting from the parsing process
 * @brief
 **/

error_t sshParseKdfOptions(const uint8_t *data, size_t length,
   SshKdfOptions *kdfOptions)
{
   error_t error;

   //Decode 'salt' field
   error = sshParseBinaryString(data, length, &kdfOptions->salt);
   //Any error to report?
   if(error)
      return error;

   //Point to the next field
   data += sizeof(uint32_t) + kdfOptions->salt.length;
   length -= sizeof(uint32_t) + kdfOptions->salt.length;

   //Malformed KDF options?
   if(length != sizeof(uint32_t))
      return ERROR_INVALID_SYNTAX;

   //Decode 'rounds' fields
   kdfOptions->rounds = LOAD32BE(data);

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Key derivation function
 * @param[in] password Password
 * @param[in] passwordLen Length password
 * @param[in] salt Salt
 * @param[in] saltLen Length of the salt
 * @param[in] rounds Iteration count
 * @param[out] key Derived key
 * @param[in] keyLen Intended length of the derived key
 * @return Error code
 **/

error_t sshKdf(const char *password, size_t passwordLen, const uint8_t *salt,
   size_t saltLen, uint_t rounds, uint8_t *key, size_t keyLen)
{
#if (SSH_ENCRYPTED_KEY_SUPPORT == ENABLED)
   error_t error;
   size_t i;
   size_t j;
   size_t k;
   size_t n;
   size_t m;
   uint8_t a[4];
   uint8_t u[32];
   uint8_t t[32];
   uint8_t saltHash[SHA512_DIGEST_SIZE];
   uint8_t passwordHash[SHA512_DIGEST_SIZE];
   Sha512Context *sha512Context;

   //Check parameters
   if(password == NULL || salt == NULL || key == NULL || keyLen == 0)
      return ERROR_INVALID_PARAMETER;

   //The iteration count must be a positive integer
   if(rounds < 1)
      return ERROR_INVALID_PARAMETER;

   //Initialize status code
   error = NO_ERROR;

   //Calculate the number of blocks to generate
   n = (keyLen + sizeof(t) - 1) / sizeof(t);
   m = (keyLen + n - 1) / n;

   //Allocate a memory buffer to hold the SHA-512 context
   sha512Context = sshAllocMem(sizeof(Sha512Context));

   //Successful memory allocation?
   if(sha512Context != NULL)
   {
      //Digest password
      sha512Init(sha512Context);
      sha512Update(sha512Context, password, passwordLen);
      sha512Final(sha512Context, passwordHash);

      //For each block of the derived key apply the function F
      for(i = 1; i <= n && !error; i++)
      {
         //Calculate the 4-octet encoding of the integer i (MSB first)
         STORE32BE(i, a);

         //Initialize current block
         osMemset(t, 0, sizeof(t));

         //Iterate as many times as required
         for(j = 0; j < rounds && !error; j++)
         {
            //First round?
            if(j == 0)
            {
               //Compute U1 = PRF(P, S || INT(i))
               sha512Init(sha512Context);
               sha512Update(sha512Context, salt, saltLen);
               sha512Update(sha512Context, a, sizeof(a));
               sha512Final(sha512Context, saltHash);
            }
            else
            {
               //Compute U(j) = PRF(P, U(j-1))
               sha512Init(sha512Context);
               sha512Update(sha512Context, u, sizeof(u));
               sha512Final(sha512Context, saltHash);
            }

            //Apply KDF hash function
            error = sshKdfHash(passwordHash, saltHash, u);

            //Compute T = U(1) xor U(2) xor ... xor U(c)
            for(k = 0; k < sizeof(t); k++)
            {
               t[k] ^= u[k];
            }
         }

         //Shuffle output bytes
         for(j = 0; j < m; j++)
         {
            k = j * n + i - 1;

            if(k < keyLen)
            {
               key[k] = t[j];
            }
         }
      }

      //Release previously allocated memory
      sshFreeMem(sha512Context);
   }
   else
   {
      //Report an error
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
#else
   //Encrypted private keys are not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}


/**
 * @brief KDF hash function
 * @param[in] password Password
 * @param[in] salt Salt
 * @param[out] output Digest value
 * @return Error code
 **/

error_t sshKdfHash(uint8_t *password, uint8_t *salt, uint8_t *output)
{
#if (SSH_ENCRYPTED_KEY_SUPPORT == ENABLED)
   error_t error;
   uint_t i;
   uint32_t temp;
   BlowfishContext *blowfishContext;

   //Allocate a memory buffer to hold the Blowfish context
   blowfishContext = sshAllocMem(sizeof(BlowfishContext));

   //Successful memory allocation?
   if(blowfishContext != NULL)
   {
      //Initialize Blowfish state
      error = blowfishInitState(blowfishContext);

      //Check status code
      if(!error)
      {
         //Perform the first key expansion
         blowfishExpandKey(blowfishContext, salt, SHA512_DIGEST_SIZE,
            password, SHA512_DIGEST_SIZE);
      }

      //Iterate 64 times
      for(i = 0; i < 64 && !error; i++)
      {
         //Perform key expansion with salt
         error = blowfishExpandKey(blowfishContext, NULL, 0, salt,
            SHA512_DIGEST_SIZE);

         //Check status code
         if(!error)
         {
            //Perform key expansion with password
            error = blowfishExpandKey(blowfishContext, NULL, 0, password,
               SHA512_DIGEST_SIZE);
         }
      }

      //Check status code
      if(!error)
      {
         //Initialize plaintext
         osMemcpy(output, "OxychromaticBlowfishSwatDynamite", 32);

         //Repeatedly encrypt the text 64 times
         for(i = 0; i < 64; i++)
         {
            //Perform encryption using Blowfish in ECB mode
            blowfishEncryptBlock(blowfishContext, output, output);
            blowfishEncryptBlock(blowfishContext, output + 8, output + 8);
            blowfishEncryptBlock(blowfishContext, output + 16, output + 16);
            blowfishEncryptBlock(blowfishContext, output + 24, output + 24);
         }
      }

      //Check status code
      if(!error)
      {
         //Swap 32-bit words
         for(i = 0; i < 32; i += 4)
         {
            temp = output[i + 0];
            output[i + 0] = output[i + 3];
            output[i + 3] = temp;
            temp = output[i + 1];
            output[i + 1] = output[i + 2];
            output[i + 2] = temp;
         }
      }

      //Erase Blowfish state
      blowfishDeinit(blowfishContext);
      //Release previously allocated memory
      sshFreeMem(blowfishContext);
   }
   else
   {
      //Report an error
      error = ERROR_OUT_OF_MEMORY;
   }

   //Return status code
   return error;
#else
   //Encrypted private keys are not supported
   return ERROR_NOT_IMPLEMENTED;
#endif
}

#endif
