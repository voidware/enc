/**
 * Copyright (c) 2012-2015 Voidware Ltd.
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
 */

#include        <iostream>
#include 	<fstream>
#include        <assert.h>
#include        <windows.h>

#include        "random.h"
#include        "rc4.h"
#include        "md5.h"

#define         LATEST_VERSION  2
#define         HEADER_VERSION 0

/* versions:
 *
 * 2: uses 128 bits of MD5 hash key.
 *    saves name of the original file
 * 1: uses 64 bit key.
 */

#define TEXT_IN         1
#define TEXT_OUT        2
#define LINE_SIZE       70

typedef int KBits;
typedef __int64 int64;

#define BUFSIZE 1024*1024


static bool debug = false;

struct Buf
{
    unsigned char*      _data;
    size_t              _size;
    size_t              _space;

    Buf()
    {
        _data = 0;
        _space = 0;
        _size = 0;
    }

    ~Buf() { delete [] _data; }

    void spaceFor(size_t sz)
    {
        if (sz > _space)
        {
            _space = sz;
            unsigned char* buf = new unsigned char[_space];
            if (_data)
            {
                memcpy(buf, _data, _size);
                delete [] _data;
            }
            _data = buf;
        }
    }

    void sizeTo(size_t sz)
    {
        spaceFor(sz);
        _size = sz;
    }

    void growBy(size_t sz)
    {
        // same as `sizeTo' but grow more than we need in expectation.
        const size_t chunkSize = 4096;

        // round up to chunks
        size_t a = (_size + sz + chunkSize - 1) & ~(chunkSize-1);
        spaceFor(a);
        _size += sz;
    }

    bool read(HANDLE fh, int n)
    {
        DWORD nRead = 0;
        assert(n <= _space);
        bool res = ReadFile(fh, _data, n, &nRead, 0) != 0 && nRead == n;

        if (res)
            _size = n;
        else
            std::cerr << "Read Error\n";            
        
        return res;
    }

    bool write(HANDLE fh)
    {
        DWORD nWrote;
        bool res = WriteFile(fh, _data, _size, &nWrote, 0) != 0 &&
            nWrote == _size;
        if (!res)
            std::cerr << "Write Error\n";
        return res;
    }

    void remove(unsigned int m)
    {
        // discard first m
        if (m > _size) m = _size;
        _size -= m;
        memmove(_data, _data + m, _size);
    }

    void packByte(unsigned int v)
    {
        growBy(1);
        unsigned char* dp = _data + _size - 1;
        *dp = v;
    }

    static void unpackByte(unsigned char*& s, int* d)
    {
        *d = *s++;
    }

    void packShort(unsigned int v)
    {
        packByte(v);
        packByte(v >> 8);
    }

    static void unpackShort(unsigned char*& s, int* d)
    {
        int lo, hi;
        unpackByte(s, &lo);
        unpackByte(s, &hi);
        *d = (hi << 8) + lo;
    }

    void packData(const unsigned char* data, size_t sz)
    {
        growBy(sz);
        unsigned char* dp = _data + _size - sz;
        memcpy(dp, data, sz);
    }

    void packString(const char* s)
    {
        packData((unsigned char*)s, strlen(s)+1);
    }

    static void unpackString(unsigned char*& s, char* d)
    {
        while (*d++ = *s++) ;
    }
};

struct MetaData
{
    int         _metaVersion;
    int         _size;
    int         _encoderVersion;

    char        _filename[256];
    char        _basefilename[256];
    char        _scrambledName[256];
    char        _filepath[256];
    bool        _hasSuffix;

    MetaData()
    {
        _metaVersion = HEADER_VERSION;
        _size = 0;
        _encoderVersion = LATEST_VERSION;
        _filename[0] = 0;
        _basefilename[0] = 0;
        _filepath[0] = 0;
        _hasSuffix = false;
    }

    void makeScrambledName()
    {
        strcpy(_scrambledName, _filename);
    }

    void setFilename(const char* s)
    {
        // find filename at the end of any path
        const char* sp = strrchr(s, '\\');
        if (!sp) sp = strrchr(s, '/');
        if (sp) ++sp;
        else sp = s;

        // take just the filename without path
        strcpy(_filename, s);

        // take path, eg "foo/bar.zip" -> "foo/"
        memcpy(_filepath, s, sp - s);
        _filepath[sp - s] = 0;
        
        strcpy(_basefilename, _filename);
        _hasSuffix = false;

        // now look for any ".e*" suffix and remove it.
        char* ep = strrchr(_basefilename, '.');
        if (ep && ep[1] == 'e')
        {
            _hasSuffix = true;

            _encoderVersion = 1;
            if (isdigit(ep[2]))
                _encoderVersion = atoi(ep + 2);
                
            *ep = 0; // truncate .e* suffix
        }
    }

    void        pack(Buf& buf)
    {
        // pack into given `buf'fer
        buf.packByte(_metaVersion);
        buf.packShort(_size);
        buf.packShort(_encoderVersion);
        buf.packString(_basefilename);
        
        // now patch the original size to be the current buffer size
        _size = buf._size;
        unsigned char* dp = buf._data;
        ++dp; // skip version
        *dp++ = _size;
        *dp = _size >> 8;
    }

    void unpack(unsigned char* data)
    {
        // retrieve meta from buffer
        unsigned char* sp = data;
        
        Buf::unpackByte(sp, &_metaVersion);
        Buf::unpackShort(sp, &_size);
        Buf::unpackShort(sp, &_encoderVersion);
        Buf::unpackString(sp, _basefilename);
    }
};

static MetaData meta;
static RC4 rc4;
static Cipher* cipher = &rc4;

static void codeData(unsigned char* inBuf, unsigned int size)
{
    while (size--) 
    {
        *inBuf = (*inBuf ^ cipher->next());
        ++inBuf;
    }
}

static unsigned int dataAsText(unsigned char* inBuf,
                               unsigned int size,
                               unsigned int writeCount)
{
    /* XXX convert to hex */
    unsigned int nb = (size * 2)/ LINE_SIZE;
    unsigned char* p = inBuf + size * 2 + nb;
    unsigned int r = (writeCount + size * 2) % LINE_SIZE;

    static char asHex[] = "0123456789ABCDEF";

    unsigned char* q = inBuf + size;
    unsigned int bc = 0;
    while (q > inBuf) 
    {
        assert(q <= p);
        --p;
        --q;
        if (!r) {
            *p-- = '\n';
            ++bc;
            r = LINE_SIZE - 2;
        }
        else r -= 2;
        
        *p = asHex[*q & 0xf];
        --p;
        *p = asHex[*q >> 4];
    }
    
    assert(bc == nb);
    return size * 2 + nb;
}

static unsigned int fromHex(unsigned int c)
{
    unsigned int v = c - '0';
    if (v > 9) v = c - 'A' + 10;
    return v;
}

static unsigned int dataFromText(unsigned char* inBuf,
                                 unsigned int n)
{
    unsigned char* p = inBuf;
    unsigned char* q = inBuf;
    while (q < inBuf + n) 
    {
        if (*q != '\n' && *q != 10) 
        {
            unsigned int v = fromHex(*q) << 4;
            ++q;
            v |= fromHex(*q);
            *p = v;
            ++p;
        }
        ++q;
    }
    return p - inBuf;
}

static bool seekto(HANDLE fh, int64 pos)
{
    LARGE_INTEGER off;
    off.QuadPart = pos;
    unsigned int v = 
        SetFilePointer(fh, off.LowPart, &off.HighPart, FILE_BEGIN);
    if (v == INVALID_SET_FILE_POINTER) 
    {
        DWORD e = GetLastError();
        if (e != NO_ERROR) 
        {
            std::cerr << "output seek failed.\n";
            return false;
        }
    }
    return true;
}



static int codeFile(MetaData md,
                    unsigned int bufSize,
                    bool inplace,
                    const char* outname,
                    unsigned int textOptions,
                    int seed, 
                    bool encode) // or decode
{
    HANDLE outH;
    bool closeOut = false;

    if (!inplace)
    {
        if (!strcmp(outname, "-"))
        {
            /* Output goes to stdout */
            outH = GetStdHandle(STD_OUTPUT_HANDLE);
            assert(outH != INVALID_HANDLE_VALUE);
        }
        else
        {
            DeleteFile(outname);
            DWORD rw = GENERIC_WRITE;
            outH = CreateFile(outname,
                            rw,
                              0,
                              0,
                              CREATE_ALWAYS,
                              0,
                              0);

            if (outH == INVALID_HANDLE_VALUE)
            {
                std::cerr << "Unable to create output file '"
                          << outname << "'\n";
                return -1;
            }
            
            closeOut = true;
        }
    }

    HANDLE fh;
    bool closeIn = false;
    int res = -1;

    char filename[256];
    strcat(strcpy(filename, md._filepath), md._filename);
 
    if (!filename[0])
    {
        fh = GetStdHandle(STD_INPUT_HANDLE);
    }
    else 
    {
        DWORD rw = GENERIC_READ;

        if (inplace) rw |= GENERIC_WRITE;
        fh = CreateFile(filename,
                           rw,
                           0,
                           0,
                           OPEN_EXISTING,
                           0,
                           0);
        closeIn = true;
    }

    if (fh != INVALID_HANDLE_VALUE) 
    {
        if (inplace) outH = fh;

        unsigned int bufSpace;
        if (textOptions) 
        {
            bufSpace = bufSize * 2;
            bufSpace += (bufSpace / LINE_SIZE + 1) * 2;
        }
        else bufSpace = bufSize;

        // double buffer
        Buf inBuf[2];
        int buf = 0;
        
        inBuf[0].spaceFor(bufSpace);
        inBuf[1].spaceFor(bufSpace);

        LARGE_INTEGER sz;
        if (!GetFileSizeEx(fh, &sz)) 
        {
            std::cerr << "Failed to size file\n";
            return res;
        }
            
        int64 dataSize = sz.QuadPart;
        int64 roffset = 0;
        int64 woffset = 0;
        int64 writeCount = 0;
        
        for (;;)
        {
            int64 n = n = dataSize - roffset;
            if (bufSize < n) n = bufSize;

            if (inplace && !seekto(fh, roffset))
                break;

            Buf* bp = inBuf + buf;

            bool ok = bp->read(fh, n);
            if (ok)
            {
                roffset += n;
                
                if (!woffset)
                {
                    // first time in, read second buffer
                    int64 n = n = dataSize - roffset;
                    if (bufSize < n) n = bufSize;
                    
                    buf = 1 - buf;
                    ok = inBuf[buf].read(fh, n);
                    if (ok) roffset += n;
                }
            }

            if (!ok)
            {
                std::cerr << "Read error.\n";
                break;
            }

            // swap buffers. now points to the drain buffer
            buf = 1-buf;
            bp = inBuf + buf;

            // empty buffer means all done
            if (!bp->_size)
            {
                if (inplace && !encode)
                {
                    // file gets smaller, so we must truncate
                    if (!seekto(outH, woffset))                    
                        break;

                    // truncate
                    if (!SetEndOfFile(outH))
                    {
                        std::cerr << "Failed to truncate file\n";
                        break;
                    }
                }

                res = 0; // done!
                break;
            }

            if (!woffset && encode)
            {
                // add `seed' random bytes of padding. 
                // this is to prevent "crib" guessing the plaintext start

                Buf padding;

                padding.sizeTo(seed + 1);
                unsigned char* wp = padding._data;
                
                *wp++ = seed;

                // fill `seed' bytes of random padding
                for (int i = 0; i < seed; ++i) *wp++ = getRandom();

                // encode
                codeData(padding._data, padding._size);

                if (debug)
                    std::cerr << "emitting " << padding._size << " padding\n";

                if (inplace && !seekto(outH, woffset))
                    break;

                if (!padding.write(outH)) 
                    break;
                
                woffset += padding._size;

                // pack meta data after padding
                Buf header;
                md.pack(header);
                
                codeData(header._data, header._size);

                if (debug)
                    std::cerr << "emitting " << header._size << " metadata\n";
                
                if (!header.write(outH)) 
                    break;
                
                woffset += header._size;
            }

            std::cerr << '<'; std::cerr.flush();
            
            if (textOptions & TEXT_IN) 
                n = dataFromText(bp->_data, bp->_size);

            /* encode/decode binary */
            codeData(bp->_data, bp->_size);

            if (!encode && !woffset)
            {
                // first read for decode. discard padding

                // first byte is the number of padding bytes
                unsigned int wc = bp->_data[0];

                // +1 for counter itself
                ++wc;
                
                if (debug)
                    std::cerr << "removing " << wc << " padding\n";

                md.unpack(bp->_data + wc);

                if (debug)
                {
                    std::cerr << "removing " << md._size << " meta\n";
                    std::cerr << "original file name '" << md._basefilename << "'\n";
                }

                bp->remove(wc + md._size);
            }

            if (textOptions & TEXT_OUT) 
                n = dataAsText(bp->_data, bp->_size, writeCount);

            if (inplace && !seekto(outH, woffset))
                break;
            
            if (!bp->write(outH))
                break;

            woffset += bp->_size;
            std::cerr << '>'; std::cerr.flush();
            writeCount += bp->_size;
        }

        if (closeIn) CloseHandle(fh);
        if (closeOut) CloseHandle(outH);
    }
    else 
        std::cerr << "Unable to open '" << filename << "'\n";

    return res;
}


unsigned int* md5(const char* t)
{
    MD5_CTX ctx;
    MD5Init(&ctx);
    static unsigned int digest[4];
    
    MD5Update(&ctx, (unsigned char*)t, strlen(t));
    MD5Final((unsigned char*)digest, &ctx);
    return digest;
}

#if 0
static unsigned int crc32(const char* s)
{
    /* Use x^32 +x^7 + x^5 + x^3 +x^2 + x + 1 */

    int crc = 0;
    int n = strlen(s);
    for (unsigned int i = 0; i < n; ++i) 
    {
        unsigned int c = s[i];
        crc = crc ^ (c << 24);
        for (unsigned int j = 0; j < 8; ++j) 
        {
            if (crc < 0) 
                crc = (crc << 1) ^ 0xaf;
            else crc <<= 1;
        }
    }
    return (unsigned int)crc;
}
#endif


int main(int argc, char** argv)
{
    std::cerr << argv[0] << " version " << LATEST_VERSION << std::endl;
        
    if (argc == 1)
    {
        std::cerr << "Usage: " << argv[0] << " [-d] [-e] [-inplace] [-ti] [-to] [-k=keyfile] [-p=password] [-checkrandom] [-debug] [-v<version#>] <filename>...\n";
        return 0;
    }

    bool inplace = false;
    unsigned int textOptions = 0;
    bool encode = false;
    bool decode = false;
    const char* keyfile = 0;
    int version = LATEST_VERSION;
    const char* password = 0;

    for (int i = 1; i < argc; ++i) 
    {
        if (argv[i][0] != '-') continue;
        
        if (!strcmp(argv[i], "-inplace")) inplace = true;
        else if (!strcmp(argv[i], "-ti")) textOptions |= TEXT_IN;
        else if (!strcmp(argv[i], "-to")) textOptions |= TEXT_OUT;
        else if (!strcmp(argv[i], "-d")) decode = true;
        else if (!strcmp(argv[i], "-e")) encode = true;
        else if (!strncmp(argv[i], "-k=", 3))
        {
            keyfile = argv[i] + 3;
        }
        else if (!strcmp(argv[i], "-checkrandom"))
        {
            // test the random seed generator
            bool ok = true;
            for (int i = 0; i < 100; ++i)
            {
                int v = getRandom();
                if (v < 0)
                {
                    ok = false;
                    break;
                }
                else
                    printf("%02X ", v);
            }
            printf("\n");

            if (!ok)
            {
                std::cerr << "random number failed\n";
                return -1;
            }
            return 0;
        }
        else if (!strncmp(argv[i], "-v", 2))
        {
            int v = atoi(argv[i] + 2);
            if (v >= 1 && v <= LATEST_VERSION)
            {
                version = v;
                if (debug)
                    std::cerr << "Using version " << version << std::endl;
            }
        }
        else if (!strcmp(argv[i], "-debug"))
        {
            std::cerr << "running in debug mode\n";
            debug = true;
        }
        else if (!strncmp(argv[i], "-p=", 3))
        {
            password = argv[i] + 3;
        }
        else
        {
            std::cerr << "unrecognised option '" << argv[i] << "'\n";
            return -1;
        }
    }

    if (encode == decode)
    {
        std::cerr << "Expect either '-d' to decode or '-e' to encode\n";
        return -1;
    }

    if (inplace && textOptions) 
    {
        std::cerr << "Cannot be inplace with any text options" << std::endl;
        return -1;
    }

    if (password)
    {
        cipher->setBaseKey(password);
    }
    else
    {
        if (keyfile)
        {
            std::ifstream infile(keyfile, std::ios::in);
            if (!infile.good()) 
            {
                std::cout << "Can't open keyfile " << keyfile << std::endl;
                return -1;
            }
            cipher->getBaseKey(infile, 0);
        }
        else
        {
            cipher->getBaseKey(std::cin, "Passphrase: ");
        }
    }

    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-') continue; // skip options

        MetaData md;
        md.setFilename(argv[i]);

        if (decode && md._hasSuffix && md._encoderVersion != version)
        {
            // use version from file name, if given
            version = md._encoderVersion;
            std::cerr << "using version " << version << " for " << md._filename << std::endl;
        }
        else
            md._encoderVersion = version;
        
        // we don't add the filename as the nonce when encoding
        // non-inplace because we don't know the output filename, and
        // therefore this cannot be recovered on decode.
        // However, if we are decoding non-inplace AND we have a ".e*" 
        // suffix, assume this was encoded inplace and is therefore the nonce.
        if (inplace || (decode && md._hasSuffix))
        {
            // combine the base file name with the base key to make
            // per-file key, then MD5
            cipher->getMD5Key(md._basefilename);
        }
     
        if (debug)
            std::cerr << "Using Key: " << cipher->keyBuf << std::endl;
        
        if (version == 1)
            cipher->setKey64(cipher->md5Key[3], cipher->md5Key[2]);
        else
        {
            cipher->setKey128(cipher->md5Key);
        }

        cipher->init();
        
        // warm up the keystream generator
        // NB: some keystreams (eg RC4) suffer from initial short term bias.
        for (int j = 1; j < 257; ++j) cipher->next();

        int seed = -1;
        if (encode)
        {
            seed = getRandom();
            if (seed < 0)
            {
                std::cerr << "Random seed failed\n";
                return -1;
            }
        }

        // rename file
        char newname[256];

        if (encode)
        {
            // invent a name
            md.makeScrambledName();
                    
            // add ".e<veresion>" suffix
            strcat(strcpy(newname, md._filepath), md._scrambledName);
            sprintf(newname + strlen(newname), ".e%d", version);
        }
        else
        {
            // name without the suffix
            strcat(strcpy(newname, md._filepath), md._basefilename);
        }
        
        if (!codeFile(md, BUFSIZE, inplace, newname, textOptions, seed, encode))
        {
            if (inplace)
            {
                DeleteFile(newname);
                if (!MoveFile(argv[i], newname))
                {
                    std::cerr << "WARNING: could not rename " << argv[i]
                              << " to " << newname << std::endl;
                }
            }
        }
    }
    return 0;
}

