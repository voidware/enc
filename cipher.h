/**
 * Copyright (c) 2015 Voidware Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 * 
 * contact@voidware.com
 */

#ifndef __cipher_h__
#define __cipher_h__

extern unsigned int* md5(const char*);

// base class 
struct Cipher
{
    char baseKey[256];
    char keyBuf[256];
    unsigned int md5Key[4];
    
    void getBaseKey(std::istream& in, const char* msg)
    {
        if (msg) 
        {
            std::cerr << msg;
            std::cerr.flush();
        }
        in.getline(baseKey, sizeof(baseKey));
    }

    void setBaseKey(const char* pw)
    {
        strcpy(baseKey, pw);
    }

    void getMD5Key(const char* nonce)
    {
        // combine the existing `baseKey' buffer with a `nonce'
        // to make a unique `keyBuf'
        // apply MD5 to scramble bit pattern into 128 bit `md5Key'
        
        strcpy(keyBuf, baseKey);
        if (nonce) strncat(keyBuf, nonce, sizeof(keyBuf)-1);
        memcpy(md5Key, md5(keyBuf), 16);
    }

    virtual void init() = 0;
    virtual void setKey64(unsigned int a, unsigned int b) = 0;
    virtual void setKey128(unsigned int* a) = 0;
    virtual unsigned int next() = 0;
};


#endif // __cipher_h__
