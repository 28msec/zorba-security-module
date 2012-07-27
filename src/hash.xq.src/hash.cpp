/*
 * Copyright 2006-2008 The FLWOR Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sstream>
#include <map>

#include <zorba/base64.h>
#include <zorba/diagnostic_list.h>
#include <zorba/external_module.h>
#include <zorba/user_exception.h>
#include <zorba/item_factory.h>
#include <zorba/singleton_item_sequence.h>
#include <zorba/empty_sequence.h>
#include <zorba/xquery_exception.h>
#include <zorba/zorba.h>
#include "hash.h"

#include "openssl/md5.h"
#include "openssl/sha.h"


namespace zorba { namespace security {

/******************************************************************************
 ******************************************************************************/
zorba::String
HashModule::getStringArgument(
    const ExternalFunction::Arguments_t& aArgs,
    int aIndex)
{
  zorba::Item lItem;
  Iterator_t args_iter = aArgs[aIndex]->getIterator();
  args_iter->open();
  args_iter->next(lItem);
  zorba::String lTmpString = lItem.getStringValue();
  args_iter->close();
  return lTmpString;
}

zorba::Item
HashModule::getItemArgument(
    const ExternalFunction::Arguments_t& aArgs,
    int aIndex)
{
  zorba::Item lItem;
  Iterator_t args_iter = aArgs[aIndex]->getIterator();
  args_iter->open();
  args_iter->next(lItem);
  args_iter->close();
  return lItem;
}

HashModule::~HashModule()
{
  for (FuncMap_t::const_iterator lIter = theFunctions.begin();
       lIter != theFunctions.end(); ++lIter) {
    delete lIter->second;
  }
  theFunctions.clear();
}


void
HashModule::destroy()
{
  if (!dynamic_cast<HashModule*>(this)) {
    return;
  }
  delete this;
}

ExternalFunction*
HashModule::getExternalFunction(const 
    String& aLocalname)
{
  ExternalFunction*& lFunc = theFunctions[aLocalname];
  if (!lFunc) {
    if (!aLocalname.compare("hash")) {
      lFunc = new HashFunction(this);
    } else if (!aLocalname.compare("hash-binary")) {
      lFunc = new HashBinaryFunction(this);
    }
  }
  return lFunc;
}

ItemFactory* HashModule::theFactory = 0;

/******************************************************************************
 ******************************************************************************/
zorba::ItemSequence_t
HashModule::hash(const ExternalFunction::Arguments_t& aArgs) const
{
  zorba::Item lMessage = getItemArgument(aArgs, 0);
  zorba::String lAlg = getStringArgument(aArgs, 1);

  bool lDecode = lMessage.getTypeCode() == store::XS_BASE64BINARY &&
    lMessage.isEncoded();

  if (lAlg == "sha1" || lAlg == "SHA1")
  {
    return hash<SHA_CTX, SHA_DIGEST_LENGTH>
      (&SHA1_Init, &SHA1_Update, &SHA1_Final, &SHA1, lMessage, lDecode);
  }
  else if (lAlg == "sha256" || lAlg == "SHA256")
  {
    return hash<SHA256_CTX, SHA256_DIGEST_LENGTH>
      (&SHA256_Init, &SHA256_Update, &SHA256_Final, &SHA256, lMessage, lDecode);
  }
  else if (lAlg == "md5" || lAlg == "MD5")
  {
    return hash<MD5_CTX, MD5_DIGEST_LENGTH>
      (&MD5_Init, &MD5_Update, &MD5_Final, &MD5, lMessage, lDecode);
  } 
  else
  {
    std::ostringstream lMsg;
    lMsg << lAlg << ": unsupported hash algorithm";
    throw USER_EXCEPTION(
        getItemFactory()->createQName(
          getURI(), "unsupported-algorithm"),
        lMsg.str());
  }
  return zorba::ItemSequence_t(new EmptySequence());
}

/******************************************************************************
 ******************************************************************************/
zorba::ItemSequence_t
HashFunction::evaluate(const Arguments_t& aArgs) const
{
  return theModule->hash(aArgs);
}

/******************************************************************************
 ******************************************************************************/
zorba::ItemSequence_t
HashBinaryFunction::evaluate(const Arguments_t& aArgs) const
{
  return theModule->hash(aArgs);
}

} /* namespace security */
} /* namespace zorba */

#ifdef WIN32
#  define DLL_EXPORT __declspec(dllexport)
#else
#  define DLL_EXPORT __attribute__ ((visibility("default")))
#endif

extern "C" DLL_EXPORT zorba::ExternalModule* createModule() {
  return new zorba::security::HashModule();
}
