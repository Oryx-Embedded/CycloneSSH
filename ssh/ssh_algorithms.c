/**
 * @file ssh_algorithms.c
 * @brief SSH algorithm negotiation
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
#include "ssh/ssh_algorithms.h"
#include "ssh/ssh_misc.h"
#include "debug.h"

//Check SSH stack configuration
#if (SSH_SUPPORT == ENABLED)


/**
 * @brief List of supported key exchange algorithms
 **/

const char_t *sshSupportedKexAlgos[] =
{
#if (SSH_ECDH_SUPPORT == ENABLED)
#if (SSH_CURVE25519_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   "curve25519-sha256",
   "curve25519-sha256@libssh.org",
#endif
#if (SSH_CURVE448_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   "curve448-sha512",
#endif
#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   "ecdh-sha2-nistp256",
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   "ecdh-sha2-nistp384",
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   "ecdh-sha2-nistp521",
#endif
#endif
#if (SSH_DH_SUPPORT == ENABLED)
#if (SSH_MAX_DH_MODULUS_SIZE >= 4096 && SSH_MIN_DH_MODULUS_SIZE <= 4096 && \
   SSH_SHA512_SUPPORT == ENABLED)
   "diffie-hellman-group16-sha512",
#endif
#if (SSH_MAX_DH_MODULUS_SIZE >= 3072 && SSH_MIN_DH_MODULUS_SIZE <= 3072 && \
   SSH_SHA512_SUPPORT == ENABLED)
   "diffie-hellman-group15-sha512",
#endif
#if (SSH_MAX_DH_MODULUS_SIZE >= 2048 && SSH_MIN_DH_MODULUS_SIZE <= 2048 && \
   SSH_SHA256_SUPPORT == ENABLED)
   "diffie-hellman-group14-sha256",
#endif
#if (SSH_MAX_DH_MODULUS_SIZE >= 2048 && SSH_MIN_DH_MODULUS_SIZE <= 2048 && \
   SSH_SHA1_SUPPORT == ENABLED)
   "diffie-hellman-group14-sha1",
#endif
#if (SSH_MAX_DH_MODULUS_SIZE >= 1024 && SSH_MIN_DH_MODULUS_SIZE <= 1024 && \
   SSH_SHA1_SUPPORT == ENABLED)
   "diffie-hellman-group1-sha1",
#endif
#endif
};


/**
 * @brief List of supported host key algorithms
 **/

const char_t *sshSupportedHostKeyAlgos[] =
{
#if (SSH_ED25519_SUPPORT == ENABLED)
   "ssh-ed25519",
#endif
#if (SSH_ED448_SUPPORT == ENABLED)
   "ssh-ed448",
#endif
#if (SSH_ECDSA_SUPPORT == ENABLED)
#if (SSH_NISTP256_SUPPORT == ENABLED && SSH_SHA256_SUPPORT == ENABLED)
   "ecdsa-sha2-nistp256",
#endif
#if (SSH_NISTP384_SUPPORT == ENABLED && SSH_SHA384_SUPPORT == ENABLED)
   "ecdsa-sha2-nistp384",
#endif
#if (SSH_NISTP521_SUPPORT == ENABLED && SSH_SHA512_SUPPORT == ENABLED)
   "ecdsa-sha2-nistp521",
#endif
#endif
#if (SSH_RSA_SUPPORT == ENABLED)
#if (SSH_SHA256_SUPPORT == ENABLED)
   "rsa-sha2-256",
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   "rsa-sha2-512",
#endif
#if (SSH_SHA1_SUPPORT == ENABLED)
   "ssh-rsa",
#endif
#endif
#if (SSH_DSA_SUPPORT == ENABLED)
#if (SSH_SHA1_SUPPORT == ENABLED)
   "ssh-dss",
#endif
#endif
};


/**
 * @brief List of supported encryption algorithms
 **/

const char_t *sshSupportedEncAlgos[] =
{
#if (SSH_CHACHA20_POLY1305_SUPPORT == ENABLED)
   "chacha20-poly1305@openssh.com",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   "aes128-gcm@openssh.com",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_GCM_CIPHER_SUPPORT == ENABLED)
   "aes256-gcm@openssh.com",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "aes128-ctr",
#endif
#if (SSH_AES_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "aes192-ctr",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "aes256-ctr",
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "camellia128-ctr",
#endif
#if (SSH_CAMELLIA_192_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "camellia192-ctr",
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "camellia256-ctr",
#endif
#if (SSH_AES_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "aes128-cbc",
#endif
#if (SSH_AES_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "aes192-cbc",
#endif
#if (SSH_AES_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "aes256-cbc",
#endif
#if (SSH_CAMELLIA_128_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "camellia128-cbc",
#endif
#if (SSH_CAMELLIA_192_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "camellia192-cbc",
#endif
#if (SSH_CAMELLIA_256_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "camellia256-cbc",
#endif
#if (SSH_SEED_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "seed-ctr@ssh.com",
#endif
#if (SSH_SEED_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "seed-cbc@ssh.com",
#endif
#if (SSH_3DES_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "3des-ctr",
#endif
#if (SSH_3DES_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "3des-cbc",
#endif
#if (SSH_BLOWFISH_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "blowfish-ctr",
#endif
#if (SSH_BLOWFISH_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "blowfish-cbc",
#endif
#if (SSH_IDEA_SUPPORT == ENABLED && SSH_CTR_CIPHER_SUPPORT == ENABLED)
   "idea-ctr",
#endif
#if (SSH_IDEA_SUPPORT == ENABLED && SSH_CBC_CIPHER_SUPPORT == ENABLED)
   "idea-cbc",
#endif
#if (SSH_RC4_256_SUPPORT == ENABLED && SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   "arcfour256",
#endif
#if (SSH_RC4_128_SUPPORT == ENABLED && SSH_STREAM_CIPHER_SUPPORT == ENABLED)
   "arcfour128",
#endif
};


/**
 * @brief List of supported MAC algorithms
 **/

const char_t *sshSupportedMacAlgos[] =
{
#if (SSH_SHA256_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha2-256-etm@openssh.com",
#endif
#if (SSH_SHA256_SUPPORT == ENABLED)
   "hmac-sha2-256",
#endif
#if (SSH_SHA512_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha2-512-etm@openssh.com",
#endif
#if (SSH_SHA512_SUPPORT == ENABLED)
   "hmac-sha2-512",
#endif
#if (SSH_SHA1_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha1-etm@openssh.com",
#endif
#if (SSH_SHA1_SUPPORT == ENABLED)
   "hmac-sha1",
#endif
#if (SSH_RIPEMD160_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-ripemd160-etm@openssh.com",
#endif
#if (SSH_RIPEMD160_SUPPORT == ENABLED)
   "hmac-ripemd160@openssh.com",
#endif
#if (SSH_MD5_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-md5-etm@openssh.com",
#endif
#if (SSH_MD5_SUPPORT == ENABLED)
   "hmac-md5",
#endif
#if (SSH_SHA1_96_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-sha1-96-etm@openssh.com",
#endif
#if (SSH_SHA1_96_SUPPORT == ENABLED)
   "hmac-sha1-96",
#endif
#if (SSH_MD5_96_SUPPORT == ENABLED && SSH_ETM_SUPPORT == ENABLED)
   "hmac-md5-96-etm@openssh.com",
#endif
#if (SSH_MD5_96_SUPPORT == ENABLED)
   "hmac-md5-96",
#endif
};


/**
 * @brief List of supported compression algorithms
 **/

const char_t *sshSupportedCompressionAlgos[] =
{
   "none"
};


/**
 * @brief Format the list of key exchange algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatKexAlgoList(SshContext *context, uint8_t *p, size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //The first algorithm must be the preferred (and guessed) algorithm
   return sshFormatNameList(sshSupportedKexAlgos,
      arraysize(sshSupportedKexAlgos), p, written);
}


/**
 * @brief Format the list of host key algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatHostKeyAlgoList(SshContext *context, uint8_t *p,
   size_t *written)
{
   error_t error;
   uint_t i;
   size_t n;

   //Initialize status code
   error = NO_ERROR;

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //The client lists the algorithms that it is willing to accept (refer
      //to RFC 4253, section 7.1)
      error = sshFormatNameList(sshSupportedHostKeyAlgos,
         arraysize(sshSupportedHostKeyAlgos), p, &n);
   }
   else
   {
      //A name-list is represented as a uint32 containing its length followed
      //by a comma-separated list of zero or more names
      n = sizeof(uint32_t);

      //Loop through the supported host key algorithms
      for(i = 0; i < arraysize(sshSupportedHostKeyAlgos); i++)
      {
         //The server lists the algorithms for which it has host keys (refer
         //to RFC 4253, section 7.1)
         if(sshSelectHostKey(context, sshSupportedHostKeyAlgos[i]) > 0)
         {
            //Algorithm names are separated by commas
            if(n != sizeof(uint32_t))
            {
               p[n++] = ',';
            }

            //A name must have a non-zero length and it must not contain a comma
            osStrcpy((char_t *) p + n, sshSupportedHostKeyAlgos[i]);

            //Update the length of the name list
            n += osStrlen(sshSupportedHostKeyAlgos[i]);
         }
      }

      //The name list is preceded by a uint32 containing its length
      STORE32BE(n - sizeof(uint32_t), p);
   }

   //Check status code
   if(!error)
   {
      //Total number of bytes that have been written
      *written = n;
   }

   //Return status code
   return error;
}


/**
 * @brief Format the list of encryption algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatEncAlgoList(SshContext *context, uint8_t *p, size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //Each supported algorithm must be listed in order of preference
   return sshFormatNameList(sshSupportedEncAlgos,
      arraysize(sshSupportedEncAlgos), p, written);
}


/**
 * @brief Format the list of integrity algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatMacAlgoList(SshContext *context, uint8_t *p, size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //Each supported algorithm must be listed in order of preference
   return sshFormatNameList(sshSupportedMacAlgos,
      arraysize(sshSupportedMacAlgos), p, written);
}


/**
 * @brief Format the list of compression algorithms
 * @param[in] context Pointer to the SSH context
 * @param[out] p  Output stream where to write the name-list
 * @param[out] written Total number of bytes that have been written
 * @return Error code
 **/

error_t sshFormatCompressionAlgoList(SshContext *context, uint8_t *p,
   size_t *written)
{
   //The algorithm name-list must be a comma-separated list of algorithm names.
   //Each supported algorithm must be listed in order of preference
   return sshFormatNameList(sshSupportedCompressionAlgos,
      arraysize(sshSupportedCompressionAlgos), p, written);
}


/**
 * @brief Generic algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @param[in] supportedAlgoList List of algorithms supported by the entity
 * @param[in] supportedAlgoListLen Number of items in the name list
 * @return Error code
 **/

const char_t *sshSelectAlgo(SshContext *context, const SshNameList *peerAlgoList,
   const char_t **supportedAlgoList, uint_t supportedAlgoListLen)
{
   uint_t i;
   uint_t j;
   SshString name;
   const char_t *selectedAlgo;

   //Name of the chosen algorithm
   selectedAlgo = NULL;

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //Loop through the list of algorithms supported by the SSH client
      for(j = 0; j < supportedAlgoListLen && selectedAlgo == NULL; j++)
      {
         //Loop through the list of algorithms offered by the SSH server
         for(i = 0; selectedAlgo == NULL; i++)
         {
            //Algorithm names are separated by commas
            if(sshGetName(peerAlgoList, i, &name))
            {
               //Compare algorithm names
               if(sshCompareString(&name, supportedAlgoList[j]))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  selectedAlgo = supportedAlgoList[j];
               }
            }
            else
            {
               //The end of the list was reached
               break;
            }
         }
      }
   }
   else
   {
      //Loop through the list of algorithms offered by the SSH client
      for(i = 0; selectedAlgo == NULL; i++)
      {
         //Algorithm names are separated by commas
         if(sshGetName(peerAlgoList, i, &name))
         {
            //Loop through the list of algorithms supported by the SSH server
            for(j = 0; j < supportedAlgoListLen && selectedAlgo == NULL; j++)
            {
               //Compare algorithm names
               if(sshCompareString(&name, supportedAlgoList[j]))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  selectedAlgo = supportedAlgoList[j];
               }
            }
         }
         else
         {
            //The end of the list was reached
            break;
         }
      }
   }

   //Return the name of the chosen algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Key exchange algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Error code
 **/

const char_t *sshSelectKexAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   //The first algorithm on the client's name-list that satisfies the
   //requirements and is also supported by the server must be chosen
   return sshSelectAlgo(context, peerAlgoList, sshSupportedKexAlgos,
      arraysize(sshSupportedKexAlgos));
}


/**
 * @brief Host key algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Error code
 **/

const char_t *sshSelectHostKeyAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   uint_t i;
   uint_t j;
   SshString name;
   const char_t *selectedAlgo;

   //Name of the chosen host key algorithm
   selectedAlgo = NULL;

   //Check whether SSH operates as a client or a server
   if(context->mode == SSH_OPERATION_MODE_CLIENT)
   {
      //The first algorithm on the client's name-list that satisfies the
      //requirements and is also supported by the server must be chosen
      selectedAlgo = sshSelectAlgo(context, peerAlgoList,
         sshSupportedHostKeyAlgos, arraysize(sshSupportedHostKeyAlgos));
   }
   else
   {
      //Loop through the list of algorithms offered by the SSH client
      for(i = 0; selectedAlgo == NULL; i++)
      {
         //Algorithm names are separated by commas
         if(sshGetName(peerAlgoList, i, &name))
         {
            //Loop through the list of algorithms supported by the SSH server
            for(j = 0; j < arraysize(sshSupportedHostKeyAlgos) &&
               selectedAlgo == NULL; j++)
            {
               //Compare algorithm names
               if(sshCompareString(&name, sshSupportedHostKeyAlgos[j]))
               {
                  //The chosen algorithm must be the first algorithm on the
                  //client's name list that is also on the server's name list
                  if(sshSelectHostKey(context, sshSupportedHostKeyAlgos[j]) > 0)
                  {
                     //Select current host key algorithm
                     selectedAlgo = sshSupportedHostKeyAlgos[j];
                  }
               }
            }
         }
         else
         {
            //The end of the list was reached
            break;
         }
      }
   }

   //Return the name of the chosen host key algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Encryption algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Error code
 **/

const char_t *sshSelectEncAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   //The chosen encryption algorithm to each direction must be the first
   //algorithm on the client's name-list that is also on the server's name-list
   return sshSelectAlgo(context, peerAlgoList, sshSupportedEncAlgos,
      arraysize(sshSupportedEncAlgos));
}


/**
 * @brief Integrity algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Error code
 **/

const char_t *sshSelectMacAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   //The chosen MAC algorithm to each direction must be the first algorithm
   //on the client's name-list that is also on the server's name-list
   return sshSelectAlgo(context, peerAlgoList, sshSupportedMacAlgos,
      arraysize(sshSupportedMacAlgos));
}


/**
 * @brief Compression algorithm negotiation
 * @param[in] context Pointer to the SSH context
 * @param[in] peerAlgoList List of algorithms supported by the peer
 * @return Error code
 **/

const char_t *sshSelectCompressionAlgo(SshContext *context,
   const SshNameList *peerAlgoList)
{
   //The chosen compression algorithm to each direction must be the first
   //algorithm on the client's name-list that is also on the server's name-list
   return sshSelectAlgo(context, peerAlgoList, sshSupportedCompressionAlgos,
      arraysize(sshSupportedCompressionAlgos));
}


/**
 * @brief Public key algorithm selection
 * @param[in] keyFormatId Key format identifier
 * @return Error code
 **/

const char_t *sshSelectPublicKeyAlgo(const char_t *keyFormatId)
{
   uint_t i;
   const char_t *selectedAlgo;

   //Name of the chosen public key algorithm
   selectedAlgo = NULL;

   //Loop through the list of supported algorithms
   for(i = 0; i < arraysize(sshSupportedHostKeyAlgos); i++)
   {
      //RSA public key algorithm?
      if(sshCompareAlgo(sshSupportedHostKeyAlgos[i], "ssh-rsa") ||
         sshCompareAlgo(sshSupportedHostKeyAlgos[i], "rsa-sha2-256") ||
         sshCompareAlgo(sshSupportedHostKeyAlgos[i], "rsa-sha2-512"))
      {
         //Check key format identifier
         if(sshCompareAlgo(keyFormatId, "ssh-rsa"))
         {
            //Select current public key algorithm
            selectedAlgo = sshSupportedHostKeyAlgos[i];
            break;
         }
      }
      else
      {
         //Check key format identifier
         if(sshCompareAlgo(keyFormatId, sshSupportedHostKeyAlgos[i]))
         {
            //Select current public key algorithm
            selectedAlgo = sshSupportedHostKeyAlgos[i];
            break;
         }
      }
   }

   //Return the name of the chosen public key algorithm, if any
   return selectedAlgo;
}


/**
 * @brief Check whether the other party's guess is correct
 * @param[in] context Pointer to the SSH context
 * @param[in] kexAlgoList List of key exchange algorithms advertised by the
 *   other party
 * @param[in] hostKeyAlgoList List of host key algorithms advertised by the
 *   other party
 * @return TRUE if the guess is correct else FALSE
 **/

bool_t sshIsGuessCorrect(SshContext *context, const SshNameList *kexAlgoList,
   const SshNameList *hostKeyAlgoList)
{
   bool_t correct;
   SshString preferredKexAlgo;
   SshString preferredHostKeyAlgo;

   //The first key exchange algorithm of the list is the preferred algorithm
   correct = sshGetName(kexAlgoList, 0, &preferredKexAlgo);

   //Each name-list must contain at least one algorithm name
   if(correct)
   {
      //The first host key algorithm of the list is the preferred algorithm
      correct = sshGetName(hostKeyAlgoList, 0, &preferredHostKeyAlgo);
   }

   //Each name-list must contain at least one algorithm name
   if(correct)
   {
      //The guess is considered wrong if the key exchange algorithm or the
      //host key algorithm is guessed wrong (server and client have different
      //preferred algorithm)
      if(!sshCompareString(&preferredKexAlgo, sshSupportedKexAlgos[0]) ||
         !sshCompareString(&preferredHostKeyAlgo, sshSupportedHostKeyAlgos[0]))
      {
         correct = FALSE;
      }
   }

   //Return TRUE if the guess is correct
   return correct;
}


/**
 * @brief Test if a specified algorithm is a Diffie-Hellman key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if Diffie-Hellman key exchange algorithm, else FALSE
 **/

bool_t sshIsDhKexAlgo(const char_t *kexAlgo)
{
   //Diffie-Hellman key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "diffie-hellman-group1-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group14-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group14-sha256") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group15-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group16-sha512") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha1") ||
      sshCompareAlgo(kexAlgo, "diffie-hellman-group-exchange-sha256"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}


/**
 * @brief Test if a specified algorithm is an ECDH key exchange algorithm
 * @param[in] kexAlgo Key exchange algorithm name
 * @return TRUE if ECDH key exchange algorithm, else FALSE
 **/

bool_t sshIsEcdhKexAlgo(const char_t *kexAlgo)
{
   //ECDH key exchange algorithm?
   if(sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp256") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp384") ||
      sshCompareAlgo(kexAlgo, "ecdh-sha2-nistp521") ||
      sshCompareAlgo(kexAlgo, "curve25519-sha256") ||
      sshCompareAlgo(kexAlgo, "curve25519-sha256@libssh.org") ||
      sshCompareAlgo(kexAlgo, "curve448-sha512"))
   {
      return TRUE;
   }
   else
   {
      return FALSE;
   }
}

#endif
