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

#ifndef ZORBA_SECURITY_HASH_H
#define ZORBA_SECURITY_HASH_H

#include <map>

#include <zorba/zorba.h>
#include <zorba/external_module.h>
#include <zorba/function.h>
#include <zorba/util/base64_stream.h>

namespace zorba { namespace security {

class HashModule : public ExternalModule
{
    private:
    static ItemFactory* theFactory;
    
    protected:
    class ltstr
    {
    public:
      bool
      operator()(const String& s1, const String& s2) const
      {
        return s1.compare(s2) < 0;
      }
    };
    
    typedef std::map<String, ExternalFunction*, ltstr> FuncMap_t;
    FuncMap_t theFunctions;
    
    public:
    virtual ~HashModule();
    
    virtual String
    getURI() const { return "http://www.zorba-xquery.com/modules/cryptography/hash"; }
    
    virtual ExternalFunction*
    getExternalFunction(const String& aLocalname);
    
    virtual void
    destroy();

    static String
    getStringArgument(const ExternalFunction::Arguments_t& aArgs, int aIndex);

    static Item
    getItemArgument(const ExternalFunction::Arguments_t& aArgs, int aIndex);
    
    static ItemFactory*
    getItemFactory()
    {
      if(!theFactory)
        theFactory = Zorba::getInstance(0)->getItemFactory();
      return theFactory;
    }

    zorba::ItemSequence_t
    hash(const ExternalFunction::Arguments_t& aArgs) const;

    template <class CONTEXT, int DIGEST_LENGTH> zorba::ItemSequence_t
    hash(
        int(*init)(CONTEXT*),
        int(*update)(CONTEXT*, const void*, size_t),
        int(*final)(unsigned char*, CONTEXT*),
        unsigned char*(hash)(const unsigned char*, size_t, unsigned char*),
        zorba::Item& aMessage,
        bool aDecode = false
      ) const
    {
      unsigned char lBuf[DIGEST_LENGTH];

      CONTEXT lCtx;

      if (aMessage.isStreamable())
      {
        std::istream& lStream = aMessage.getStream();

        bool lDecoderAttached = false;

        if (aDecode)
        {
          base64::attach(lStream);
          lDecoderAttached = true;
        }

        (*init)(&lCtx);

        char lBuf2[1024];
        while (lStream.good())
        {
          lStream.read(lBuf2, 1024);
          (*update)(&lCtx, &lBuf2[0], lStream.gcount());
        }

        if (lDecoderAttached)
        {
          base64::detach(lStream);
        }

        (*final)(&lBuf[0], &lCtx);
      }
      else
      {
        if (aMessage.getTypeCode() == store::XS_BASE64BINARY)
        {
          String lTmpDecodedBuf;
          size_t lLen;
          const char* lTmp = aMessage.getBase64BinaryValue(lLen);
          if (aDecode)
          {
            String lTmpEncoded;
            // lTmpDecodedBuf is used to make sure lMsg is still alive during HMAC_Update
            lTmpDecodedBuf = base64::decode(lTmp, lLen, &lTmpDecodedBuf);
            lTmp = lTmpDecodedBuf.c_str();
            lLen = lTmpDecodedBuf.size();
          }
          (*hash)(
            reinterpret_cast<const unsigned char*>(lTmp),
            lLen,
            &lBuf[0]
          );
        }
        else
        {
          String lTmp = aMessage.getStringValue();
          (*hash)(
            reinterpret_cast<const unsigned char*>(lTmp.data()),
            lTmp.size(),
            &lBuf[0]
          );
        }
      }
      return zorba::ItemSequence_t(
        new zorba::SingletonItemSequence(
          getItemFactory()->createBase64Binary(
            reinterpret_cast<char const*>(&lBuf[0]), DIGEST_LENGTH, false
          )
        )
      );
    }
  };

  class HashFunction : public NonContextualExternalFunction
  {
  protected:
    const HashModule* theModule;
  
  public:
    HashFunction(const HashModule* aModule): theModule(aModule){}
    ~HashFunction(){}
  
    virtual String
    getLocalName() const { return "hash"; }
  
    virtual zorba::ItemSequence_t
    evaluate(const Arguments_t& aArgs) const;

    virtual String
    getURI() const
    {
      return theModule->getURI();
    }
  
  };

  class HashBinaryFunction : public NonContextualExternalFunction
  {
  protected:
    const HashModule* theModule;
  
  public:
    HashBinaryFunction(const HashModule* aModule): theModule(aModule){}
    ~HashBinaryFunction(){}
  
    virtual String
    getLocalName() const { return "hash-binary"; }
  
    virtual zorba::ItemSequence_t
    evaluate(const Arguments_t& aArgs) const;

    virtual String
    getURI() const
    {
      return theModule->getURI();
    }
  
  };

} /* namespace security */ 
} /* namespace zorba */

#endif
/* vim:set et sw=2 ts=2: */
