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
#include <openssl/hmac.h>

#include <zorba/diagnostic_list.h>
#include <zorba/item_factory.h>
#include <zorba/singleton_item_sequence.h>
#include <zorba/user_exception.h>
#include <zorba/util/base64_stream.h>
#include <zorba/util/base64_util.h>

#include "hmac.h"

namespace zorba { namespace security {

ItemFactory* HMACModule::theFactory = 0;

zorba::Item
getOneItemArgument(
  const ExternalFunction::Arguments_t& aArgs,
  int aIndex)
{
  zorba::Item lItem;
  Iterator_t args_iter = aArgs[aIndex]->getIterator();
  args_iter->open();
  args_iter->next(lItem);
  return lItem;
}

zorba::String
getOneStringArgument(
  const ExternalFunction::Arguments_t& aArgs,
  int aIndex)
{
  zorba::Item lItem = getOneItemArgument(aArgs, aIndex);
  return lItem.getStringValue();
}


HMACModule::~HMACModule()
{
  for (FuncMap_t::const_iterator lIter = theFunctions.begin();
       lIter != theFunctions.end(); ++lIter) {
    delete lIter->second;
  }
  theFunctions.clear();
}
  
ExternalFunction*
HMACModule::getExternalFunction(const String& aLocalname)
{
  ExternalFunction*& lFunc = theFunctions[aLocalname];
  if (!lFunc)
  {
    if (!aLocalname.compare("compute"))
    {
      lFunc = new HMACComputeFunction(this);
    }
    else if (!aLocalname.compare("compute-binary")) {
      lFunc = new HMACComputeBinaryFunction(this);
    }
  }
  return lFunc;
}

void
HMACModule::destroy()
{
  if (!dynamic_cast<HMACModule*>(this)) {
    return;
  }
  delete this;
}

String
HMACComputeFunction::getURI() const
{
  return theModule->getURI();
}

String
HMACComputeBinaryFunction::getURI() const
{
  return theModule->getURI();
}

static void
initContext(HMAC_CTX* aCtx, const String& aKey, const String& aAlg)
{
  if (aAlg == "sha1" || aAlg == "SHA1")
  {
    HMAC_Init(aCtx, aKey.c_str(), aKey.length(), EVP_sha1());
  }
  else if (aAlg == "sha256" || aAlg == "SHA256")
  {
    HMAC_Init(aCtx, aKey.c_str(), aKey.length(), EVP_sha256());
  }
  else if (aAlg == "md5" || aAlg == "MD5")
  {
    HMAC_Init(aCtx, aKey.c_str(), aKey.length(), EVP_md5());
  } 
  else
  {
    std::ostringstream lMsg;
    lMsg << aAlg << ": unsupported hash algorithm";
    throw USER_EXCEPTION(
        HMACModule::getItemFactory()->createQName(
        "http://zorba.io/modules/hmac", "unsupported-algorithm"),
        lMsg.str());
  }
}

zorba::ItemSequence_t
HMACComputeFunction::evaluate(const Arguments_t& aArgs) const
{
  zorba::Item lItem = getOneItemArgument(aArgs, 0);

  String lKey = getOneStringArgument(aArgs, 1);
  String lAlg = getOneStringArgument(aArgs, 2);

  HMAC_CTX      ctx;
  unsigned int  len;
  unsigned char out[32]; // reserve max digest length for sha256

  initContext(&ctx, lKey, lAlg);
   
  if (lItem.isStreamable())
  {
    std::istream& lStream = lItem.getStream();
    char lBuf[1024];
    while (lStream.good())
    {
      lStream.read(lBuf, 1024);
      HMAC_Update(
          &ctx,
          reinterpret_cast<const unsigned char*>(&lBuf[0]),
          lStream.gcount()
        );
    }
  }
  else
  {
    String lString = lItem.getStringValue();
    HMAC_Update(
        &ctx,
        reinterpret_cast<const unsigned char*>(lString.c_str()),
        lString.length());
  }
  HMAC_Final(&ctx, out, &len);
  HMAC_cleanup(&ctx);

  return zorba::ItemSequence_t(
    new zorba::SingletonItemSequence(
      theModule->getItemFactory()->createBase64Binary(
        reinterpret_cast<char const*>(&out[0]), len, false
      )
    )
  );
}

zorba::ItemSequence_t
HMACComputeBinaryFunction::evaluate(const Arguments_t& aArgs) const
{
  zorba::Item lItem = getOneItemArgument(aArgs, 0);

  String lKey = getOneStringArgument(aArgs, 1);
  String lAlg = getOneStringArgument(aArgs, 2);

  HMAC_CTX      ctx;
  unsigned int  len;
  unsigned char out[32]; // reserve max digest length for sha256

  initContext(&ctx, lKey, lAlg);

  if (lItem.isStreamable())
  {
    std::istream& lStream = lItem.getStream();
    bool lDecoderAttached = false;

    if (lItem.isEncoded())
    {
      base64::attach(lStream);
      lDecoderAttached = true;
    }
    char lBuf[1024];
    while (lStream.good())
    {
      lStream.read(lBuf, 1024);
      HMAC_Update(
          &ctx,
          reinterpret_cast<const unsigned char*>(&lBuf[0]),
          lStream.gcount());
    }
    if (lDecoderAttached)
    {
      base64::detach(lStream);
    }
  }
  else
  {
    String lTmpDecodedBuf;
    size_t lSize;
    const char* lMsg = lItem.getBase64BinaryValue(lSize);
    if (lItem.isEncoded())
    {
      String lTmpEncoded;
      // lTmpDecodedBuf is used to make sure lMsg is still alive during HMAC_Update
      base64::decode(lMsg, lSize, &lTmpDecodedBuf);
      lMsg = lTmpDecodedBuf.c_str();
      lSize = lTmpDecodedBuf.size();
    }
    HMAC_Update(
        &ctx,
        reinterpret_cast<const unsigned char*>(lMsg),
        lSize);
  }
  HMAC_Final(&ctx, out, &len);
  HMAC_cleanup(&ctx);

  return zorba::ItemSequence_t(
    new zorba::SingletonItemSequence(
      theModule->getItemFactory()->createBase64Binary(
        reinterpret_cast<char const*>(&out[0]), len, false
      )
    )
  );
}

} /* namespace security */ } /* namespace zorba */

#ifdef WIN32
#  define DLL_EXPORT __declspec(dllexport)
#else
#  define DLL_EXPORT __attribute__ ((visibility("default")))
#endif

extern "C" DLL_EXPORT zorba::ExternalModule* createModule() {
  return new zorba::security::HMACModule();
}

/* vim:set et sw=2 ts=2: */
