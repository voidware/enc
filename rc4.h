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

#ifndef __rc4_h__
#define __rc4_h__

#include "cipher.h"

struct RC4: public Cipher
{
    unsigned char SBox[256];
    unsigned char KBox[256];
    unsigned int  key[4];
    unsigned int  keySizeWords;

    unsigned char si, sj;

    RC4()
    {
        keySizeWords = 0;
    }

    // Compliance

    void init()
    {
        unsigned int i, j;
        for (i = 0; i < 256; ++i) SBox[i] = i;

        //for (i = 0; i < 32; ++i) memcpy(KBox + i * 8, key, 8);
        j = 64/keySizeWords;
        for (i = 0; i < j; ++i)
            memcpy(KBox + i*keySizeWords*4, key, keySizeWords*4);
        
        j = 0;
        for (i = 0; i < 256; ++i) 
        {
            j = (j + SBox[i] + KBox[i]) & 0xff;
            unsigned int t = SBox[i];
            SBox[i] = SBox[j];
            SBox[j] = t;
        }

        si = 0;
        sj = 0;
    }

    unsigned int next()
    {
        /* generate the next key value */
        unsigned char ti, tj;
        
        ti = SBox[++si];
        sj += ti;
        tj = SBox[sj];

        SBox[si] = tj;
        SBox[sj] = ti;
        
        ti += tj;
        return SBox[ti];
    }
    
    void setKey64(unsigned int a, unsigned int b)
    {
        key[0] = a;
        key[1] = b;
        keySizeWords = 2;
    }

    void setKey128(unsigned int* k)
    {
        keySizeWords = 4;
        for (int i = 0; i < keySizeWords; ++i)
            key[i] = k[i];
    }
};


#endif // __rc4_h__
