/*
    ei++.h

    Author:   Serge Aleynikov
    Created:  2003/07/10

    Description:
    ============
    C++ wrapper around C ei library distributed with Erlang.

    LICENSE:
    ========
    Copyright (C) 2003 Serge Aleynikov <saleyn@gmail.com>

    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

      1. Redistributions of source code must retain the above copyright notice,
         this list of conditions and the following disclaimer.

      2. Redistributions in binary form must reproduce the above copyright
         notice, this list of conditions and the following disclaimer in
         the documentation and/or other materials provided with the distribution.

      3. The names of the authors may not be used to endorse or promote products
         derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
    FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
    INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
    OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
    EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _EMARSHAL_H_
#define _EMARSHAL_H_

#include <ei.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <iostream>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <assert.h>

#define NEW_FLOAT_EXT 'F'

namespace ei {
    typedef unsigned char byte;

    /// Looks up a <cmd> in the <cmds> array.
    /// @param <cmds> an array that either ends with a NULL element or has <size> number of elements.
    /// @param <cmd> string to find.
    /// @param <firstIdx> the mapping of the first element in the array. If != 0, then the return
    ///                   value will be based on this starting index.
    /// @param <size> optional size of the <cmds> array.
    /// @return an offset <cmd> in the cmds array starting with <firstIdx> value. On failure
    ///         returns <firstIdx>-1.
    int stringIndex(const char** cmds, const std::string& cmd, int firstIdx = 0, int size = INT_MAX);

    /// Class for stack-based (and on-demand heap based) memory allocation
    /// of string buffers.  It's very efficient for strings not exceeding <N>
    /// bytes as it doesn't allocate heap memory.
    template < int N, class Allocator = std::allocator<char> >
    class StringBuffer
    {
        char        m_buff[N];
        char*       m_buffer;
        size_t      m_size;
        int         m_minAlloc;
        int         m_headerSize;
        size_t      m_maxMsgSize;
        Allocator   m_alloc;    // allocator to use

        char*       base()          { return m_buffer + m_headerSize; }
        const char* base() const    { return m_buffer + m_headerSize; }
        char* write( int pos, const char* fmt, va_list vargs ) {
            char s[512];
            vsnprintf(s, sizeof(s), fmt, vargs);
            return copy( s, pos );
        }

    public:
        enum { DEF_QUANTUM = 512 };

        StringBuffer(int _headerSz = 0, int _quantumSz = DEF_QUANTUM)
            : m_buffer(m_buff), m_size(N), m_minAlloc(_quantumSz)
        { m_buff[0] = '\0'; packetHeaderSize(_headerSz); }

        StringBuffer( const char (&s)[N] )
            : m_buffer(m_buff), m_size(N), m_minAlloc(DEF_QUANTUM), m_headerSize(0), m_maxMsgSize(0)
        { copy(s); }

        StringBuffer( const std::string& s)
            : m_buffer(m_buff), m_size(N), m_minAlloc(DEF_QUANTUM), m_headerSize(0), m_maxMsgSize(0)
        { copy(s.c_str(), 0, s.size()); }

        ~StringBuffer() { reset(); }

        /// Buffer allocation quantum
        int    quantum()    const               { return m_minAlloc; }
        void   quantum(int n)                   { m_minAlloc = n; }
        /// Defines a prefix space in the buffer used for encoding packet size.
        int    packetHeaderSize()               { return m_headerSize; }
        void   packetHeaderSize(size_t sz) {
            assert(sz == 0 || sz == 1 || sz == 2 || sz == 4);
            m_headerSize = sz;
            m_maxMsgSize = (1u << (8*m_headerSize)) - 1;
        }
        /// Does the buffer have memory allocated on heap?
        bool   allocated()  const               { return m_buffer != m_buff; }
        size_t capacity()   const               { return m_size - m_headerSize; }
        size_t length()     const               { return strlen(base()); }
        void   clear()                          { m_buffer[m_headerSize] = '\0'; }
        /// Free heap allocated memory and shrink buffer to original statically allocated size.
        void   reset()                          { if (allocated()) m_alloc.deallocate(m_buffer, m_size); m_buffer = m_buff; clear(); }
        /// Pointer to a mutable char string of size <capacity()>.
        const char*  c_str() const              { return base(); }
        char*  c_str()                          { return base(); }
        char*  append( const char* s )          { return copy( s, length() ); }
        char*  append( const std::string& s )   { return copy( s.c_str(), length() ); }
        char*  append( const char* fmt, ... ) {
            va_list vargs;
            va_start (vargs, fmt);
            char* ret = write(length(), fmt, vargs);
            va_end   (vargs);
            return ret;
        }

        char* operator[] ( int i )                        { assert( i < (m_size-m_headerSize) ); return base()[i]; }
        char* operator() ()                               { return base(); }
        char* operator& ()                                { return base(); }
        const char* operator& ()                    const { return base(); }
        bool  operator== ( const char* rhs )        const { return strncmp(base(), rhs, m_size) == 0; }
        bool  operator== ( const std::string& rhs ) const { return  operator== ( rhs.c_str() ); }
        bool  operator!= ( const std::string& rhs ) const { return !operator== ( rhs.c_str() ); }
        bool  operator!= ( const char* rhs )        const { return !operator== ( rhs ); }

        size_t      headerSize()                    const { return m_headerSize; }
        const char* header()                              { return m_buffer; }

        size_t read_header() {
            size_t sz = (byte)m_buffer[m_headerSize-1];
            for(int i=m_headerSize-2; i >= 0; i--)
                sz |= (byte)m_buffer[i] << (8*(m_headerSize-i-1));
            return sz;
        }

        int write_header(size_t sz) {
            if (sz > m_maxMsgSize)
                return -1;
            byte b[4] = { (byte)((sz >> 24) & 0xff), (byte)((sz >> 16) & 0xff),
                          (byte)((sz >> 8)  & 0xff), (byte)(sz & 0xff) };
            memcpy(m_buffer, b + 4 - m_headerSize, m_headerSize);
            return 0;
        }

        char* write( const char* fmt, ... ) {
            va_list vargs;
            va_start (vargs, fmt);
            char* ret = write(0, fmt, vargs);
            va_end   (vargs);
            return ret;
        }

        char* copy( const char* s, size_t pos=0 )
        {
            if ( resize( strlen(s) + pos + 1, pos != 0 ) == NULL )
                return NULL;
            assert( pos < m_size );
            strcpy( base() + pos, s );
            return base();
        }
        char* copy( const std::string& s, size_t pos=0 )
        {
            if ( resize( length(s) + pos + 1, pos != 0 ) == NULL )
                return NULL;
            assert( pos < m_size );
            strcpy( base() + pos, s.c_str() );
            return base();
        }

        char* copy( const char* s, size_t pos, size_t len)
        {
            assert( pos >= 0 && len > 0 && (pos+len) < m_size );
            if ( resize( len + pos + 1, pos != 0 ) == NULL )
                return NULL;
            memcpy( base() + pos, s, len );
            return base();
        }

        char* resize( size_t size, bool reallocate = false )
        {
            char*           old    = m_buffer;
            const size_t    old_sz = m_size;
            const size_t    new_sz = size + m_headerSize;

            if ( new_sz <= m_size ) {
                return m_buffer;
            } else
                m_size = std::max((const size_t)m_size + m_headerSize + m_minAlloc, new_sz);

            if ( (m_buffer = m_alloc.allocate(m_size)) == NULL ) {
                m_buffer = old;
                m_size   = old_sz;
                return (char*) NULL;
            }
            //fprintf(stderr, "Allocated: x1 = %p, x2=%p (m_size=%d)\r\n", m_buffer, m_buff, m_size);
            if ( reallocate && old != m_buffer )
                memcpy(m_buffer, old, old_sz);
            if ( old != m_buff ) {
                m_alloc.deallocate(old, old_sz);
            }
            return base();
        }

    };

    template<int N> std::ostream& operator<< ( std::ostream& os, StringBuffer<N>& buf ) {
        return os << buf.c_str();
    }

    template<int N> StringBuffer<N>& operator<< ( StringBuffer<N>& buf, const std::string& s ) {
        size_t n = buf.length();
        buf.resize( n + s.size() + 1 );
        strcpy( buf.c_str() + n, s.c_str() );
        return buf;
    }

    /// A helper class for dealing with 'struct timeval' structure. This class adds ability
    /// to perform arithmetic with the structure leaving the same footprint.
    class TimeVal
    {
        struct timeval m_tv;

        void normalize() {
            if (m_tv.tv_usec >= 1000000)
                do { ++m_tv.tv_sec; m_tv.tv_usec -= 1000000; } while (m_tv.tv_usec >= 1000000);
            else if (m_tv.tv_usec <= -1000000)
                do { --m_tv.tv_sec; m_tv.tv_usec += 1000000; } while (m_tv.tv_usec <= -1000000);

            if      (m_tv.tv_sec >= 1 && m_tv.tv_usec < 0) { --m_tv.tv_sec; m_tv.tv_usec += 1000000; }
            else if (m_tv.tv_sec <  0 && m_tv.tv_usec > 0) { ++m_tv.tv_sec; m_tv.tv_usec -= 1000000; }
        }

    public:
        enum TimeType { NOW, RELATIVE };

        TimeVal()                   { m_tv.tv_sec=0; m_tv.tv_usec=0; }
        TimeVal(int _s, int _us)    { m_tv.tv_sec=_s; m_tv.tv_usec=_us; normalize(); }
        TimeVal(const TimeVal& tv, int _s=0, int _us=0) { set(tv, _s, _us); }
        TimeVal(const struct timeval& tv) { m_tv.tv_sec=tv.tv_sec; m_tv.tv_usec=tv.tv_usec; normalize(); }
        TimeVal(TimeType tp, int _s=0, int _us=0);

        struct timeval&       timeval()       { return m_tv; }
        const struct timeval& timeval() const { return m_tv; }
        int32_t sec()      const   { return m_tv.tv_sec;  }
        int32_t usec()     const   { return m_tv.tv_usec; }
        int64_t microsec() const   { return (int64_t)m_tv.tv_sec*1000000ull + (int64_t)m_tv.tv_usec; }
        void sec (int32_t _sec)    { m_tv.tv_sec  = _sec;  }
        void usec(int32_t _usec)   { m_tv.tv_usec = _usec; normalize(); }
        void microsec(int32_t _m)  { m_tv.tv_sec = _m / 1000000ull; m_tv.tv_usec = _m % 1000000ull; }

        void set(const TimeVal& tv, int _s=0, int _us=0) {
            m_tv.tv_sec = tv.sec() + _s; m_tv.tv_usec = tv.usec() + _us; normalize();
        }

        double diff(const TimeVal& t) const {
            TimeVal tv(this->timeval());
            tv -= t;
            return (double)tv.sec() + (double)tv.usec() / 1000000.0;
        }

        void clear()                { m_tv.tv_sec = 0; m_tv.tv_usec = 0; }
        bool zero()                 { return sec() == 0 && usec() == 0; }
        void add(int _sec, int _us) { m_tv.tv_sec += _sec; m_tv.tv_usec += _us; if (_sec || _us) normalize(); }
        TimeVal& now(int addS=0, int addUS=0)   { gettimeofday(&m_tv, NULL); add(addS, addUS); return *this; }

        void operator-= (const TimeVal& tv) {
            m_tv.tv_sec -= tv.sec(); m_tv.tv_usec -= tv.usec(); normalize();
        }
        void operator+= (const TimeVal& tv) {
            m_tv.tv_sec += tv.sec(); m_tv.tv_usec += tv.usec(); normalize();
        }
        void operator+= (int32_t _sec)      { m_tv.tv_sec += _sec; }
        void operator+= (int64_t _microsec) {
            m_tv.tv_sec  += (_microsec / 1000000ll);
            m_tv.tv_usec += (_microsec % 1000000ll);
            normalize();
        }
        TimeVal& operator= (const TimeVal& t)     { m_tv.tv_sec = t.sec(); m_tv.tv_usec = t.usec(); return *this; }
        struct timeval* operator& ()              { return &m_tv; }
        bool operator== (const TimeVal& tv) const { return sec() == tv.sec() && usec() == tv.usec(); }
        bool operator!= (const TimeVal& tv) const { return !operator== (tv); }
        bool operator<  (const TimeVal& tv) const {
            return sec() < tv.sec() || (sec() == tv.sec() && usec() < tv.usec());
        }
        bool operator<= (const TimeVal& tv) const {
            return sec() <= tv.sec() && usec() <= tv.usec();
        }
    };

    TimeVal operator- (const TimeVal& t1, const TimeVal& t2);
    TimeVal operator+ (const TimeVal& t1, const TimeVal& t2);

    struct atom_t: public std::string {
        typedef std::string BaseT;
        atom_t()                    : BaseT() {}
        atom_t(const char* s)       : BaseT(s) {}
        atom_t(const atom_t& a)     : BaseT(reinterpret_cast<const BaseT&>(a)) {}
        atom_t(const std::string& s): BaseT(s) {}
    };

    enum ErlTypeT {
          etSmallInt    = ERL_SMALL_INTEGER_EXT // 'a'
        , etInt         = ERL_INTEGER_EXT       // 'b'
        , etFloatOld    = ERL_FLOAT_EXT         // 'c'
        , etFloat       = NEW_FLOAT_EXT         // 'F'
        , etAtom        = ERL_ATOM_EXT          // 'd'
        , etRefOld      = ERL_REFERENCE_EXT     // 'e'
        , etRef         = ERL_NEW_REFERENCE_EXT // 'r'
        , etPort        = ERL_PORT_EXT          // 'f'
        , etPid         = ERL_PID_EXT           // 'g'
        , etTuple       = ERL_SMALL_TUPLE_EXT   // 'h'
        , etTupleLarge  = ERL_LARGE_TUPLE_EXT   // 'i'
        , etNil         = ERL_NIL_EXT           // 'j'
        , etString      = ERL_STRING_EXT        // 'k'
        , etList        = ERL_LIST_EXT          // 'l'
        , etBinary      = ERL_BINARY_EXT        // 'm'
        , etBignum      = ERL_SMALL_BIG_EXT     // 'n'
        , etBignumLarge = ERL_LARGE_BIG_EXT     // 'o'
        , etFun         = ERL_NEW_FUN_EXT       // 'p'
        , etFunOld      = ERL_FUN_EXT           // 'u'
        , etNewCache    = ERL_NEW_CACHE         // 'N' /* c nodes don't know these two */
        , etAtomCached  = ERL_CACHED_ATOM       // 'C'
    };

    /// Erlang term serializer/deserializer C++ wrapper around C ei library included in
    /// Erlang distribution.
    class Serializer
    {
        StringBuffer<1024> m_wbuf;  // for writing output commands
        StringBuffer<1024> m_rbuf;  // for reading input commands
        size_t  m_readOffset,   m_writeOffset;
        size_t  m_readPacketSz, m_writePacketSz;
        int     m_wIdx, m_rIdx;
        int     m_fin,  m_fout;
        bool    m_debug;

        void wcheck(int n) {
            if (m_wbuf.resize(m_wIdx + n + 16, true) == NULL)
                throw "out of memory";
        }
        static int ei_decode_double(const char *buf, int *m_wIdx, double *p);
        static int ei_encode_double(char *buf, int *m_wIdx, double p);
        static int ei_x_encode_double(ei_x_buff* x, double d);
        static int read_exact (int fd, char *buf, size_t len, size_t& offset);
        static int write_exact(int fd, const char *buf, size_t len, size_t& offset);
    public:

        Serializer(int _headerSz = 2)
            : m_wbuf(_headerSz), m_rbuf(_headerSz)
            , m_readOffset(0), m_writeOffset(0)
            , m_readPacketSz(0), m_writePacketSz(0)
            , m_wIdx(0), m_rIdx(0)
            , m_fin(0), m_fout(1), m_debug(false)
            , tuple(*this)
        {
            ei_encode_version(&m_wbuf, &m_wIdx);
        }

        void reset_rbuf(bool _saveVersion=true) {
            m_rIdx = _saveVersion ? 1 : 0;
            m_readPacketSz = m_readOffset = 0;
        }
        void reset_wbuf(bool _saveVersion=true) {
            m_wIdx = _saveVersion ? 1 : 0;
            m_writePacketSz = m_writeOffset = 0;
        }
        void reset(bool _saveVersion=true) {
            reset_rbuf(_saveVersion);
            reset_wbuf(_saveVersion);
        }
        void debug(bool _enable)            { m_debug = _enable; }

        // This is a helper class for encoding tuples using streaming operator.
        // Example: encode {ok, 123, "test"}
        //
        //   Serializer ser;
        //   ser.tuple << atom_t("ok") << 123 << "test";
        //
        class Tuple {
            Serializer& m_parent;

            class Temp {
                Tuple& m_tuple;
                mutable int    m_idx;  // offset to the tuple's size in m_parent.m_wbuf
                mutable int    m_size;
                mutable bool   m_last;
            public:
                template<typename T>
                Temp(Tuple& t, const T& v)
                    : m_tuple(t), m_idx(m_tuple.m_parent.m_wIdx+1), m_size(1), m_last(true)
                {
                    m_tuple.m_parent.encodeTupleSize(1);
                    m_tuple.m_parent.encode(v);
                }

                Temp(const Temp& o)
                    : m_tuple(o.m_tuple), m_idx(o.m_idx), m_size(o.m_size+1), m_last(o.m_last)
                {
                    o.m_last = false;
                }

                ~Temp() {
                    if (m_last) {
                        // This is the end of the tuple being streamed to this class. Update tuple size.
                        if (m_size > 255)
                            throw "Use of operator<< only allowed for tuples with less than 256 items!";
                        else if (m_size > 1) {
                            char* sz = &m_tuple.m_parent.m_wbuf + m_idx;
                            *sz = m_size;
                        }
                    }
                }
                template<typename T>
                Temp operator<< (const T& v) {
                    Temp t(*this);
                    m_tuple.m_parent.encode(v);
                    return t;
                }
            };

        public:
            Tuple(Serializer& s) : m_parent(s) {}

            template<typename T>
            Temp operator<< (const T& v) {
                Temp t(*this, v);
                return t;
            }
        };

        /// Helper class for encoding/decoding tuples using streaming operator.
        Tuple tuple;

        void encode(const char* s)          { wcheck(strlen(s)+1); ei_encode_string(&m_wbuf, &m_wIdx, s); }
        void encode(char v)                 { wcheck(2);           ei_encode_char(&m_wbuf, &m_wIdx, v);   }
        void encode(int i)                  { wcheck(sizeof(i));   ei_encode_long(&m_wbuf, &m_wIdx, i);   }
        void encode(unsigned int i)         { wcheck(8);           ei_encode_ulong(&m_wbuf, &m_wIdx, i);  }
        void encode(long l)                 { wcheck(sizeof(l));   ei_encode_long(&m_wbuf, &m_wIdx, l);   }
        void encode(unsigned long l)        { wcheck(sizeof(l));   ei_encode_ulong(&m_wbuf, &m_wIdx, l);  }
        void encode(long long i)            { int n=0; ei_encode_longlong (NULL,&n,i); wcheck(n); ei_encode_longlong(&m_wbuf,&m_wIdx,i); }
        void encode(unsigned long long i)   { int n=0; ei_encode_ulonglong(NULL,&n,i); wcheck(n); ei_encode_ulonglong(&m_wbuf,&m_wIdx,i); }
        void encode(bool b)                 { wcheck(8);           ei_encode_boolean(&m_wbuf, &m_wIdx, b); }
        void encode(double v)               { wcheck(9);           ei_encode_double(&m_wbuf, &m_wIdx, v);  }
        void encode(const std::string& s)   { wcheck(s.size()+1);  ei_encode_string(&m_wbuf, &m_wIdx, s.c_str()); }
        void encode(const atom_t& a)        { wcheck(a.size()+1);  ei_encode_atom(&m_wbuf, &m_wIdx, a.c_str()); }
        void encode(const erlang_pid& p)    { int n=0; ei_encode_pid(NULL, &n, &p); wcheck(n); ei_encode_pid(&m_wbuf, &m_wIdx, &p); }
        void encode(const void* p, int sz)  { wcheck(sz+4);        ei_encode_binary(&m_wbuf, &m_wIdx, p, sz); }
        void encodeTupleSize(int sz)        { wcheck(5);           ei_encode_tuple_header(&m_wbuf, &m_wIdx, sz); }
        void encodeListSize(int sz)         { wcheck(5);           ei_encode_list_header(&m_wbuf, &m_wIdx, sz); }
        void encodeListEnd()                { wcheck(1);           ei_encode_empty_list(&m_wbuf, &m_wIdx); }

        int  encodeListBegin()              { wcheck(5); int n=m_wIdx; ei_encode_list_header(&m_wbuf, &m_wIdx, 1); return n; }
        /// This function for encoding the list size after all elements are encoded.
        /// @param sz is the number of elements in the list.
        /// @param idx is the index position of the beginning of the list.
        // E.g.
        // Serializer se;
        // int n = 0;
        // int idx = se.encodeListBegin();
        // se.encode(1);     n++;
        // se.encode("abc"); n++;
        // se.encodeListEnd(n, idx);
        void encodeListEnd(int sz,int idx)  { ei_encode_list_header(&m_wbuf, &idx, sz); encodeListEnd(); }

        ErlTypeT decodeType(int& size)      { int t;  return (ErlTypeT)(ei_get_type(&m_rbuf, &m_rIdx, &t, &size) < 0 ? -1 : t); }
        int  decodeInt(int&  v)             { long l, ret = decodeInt(l); v = l; return ret; }
        int  decodeInt(long& v)             { return (ei_decode_long(&m_rbuf, &m_rIdx, &v) < 0) ? -1 : 0; }
        int  decodeUInt(unsigned int&  v)   { unsigned long l, ret = decodeUInt(l); v = l; return ret; }
        int  decodeUInt(unsigned long& v)   { return (ei_decode_ulong(&m_rbuf, &m_rIdx, &v) < 0) ? -1 : 0; }
        int  decodeTupleSize()              { int v;  return (ei_decode_tuple_header(&m_rbuf,&m_rIdx,&v) < 0) ? -1 : v; }
        int  decodeListSize()               { int v;  return (ei_decode_list_header(&m_rbuf,&m_rIdx,&v) < 0) ? -1 : v; }
        int  decodeListEnd()                { bool b = *(m_rbuf.c_str()+m_rIdx) == ERL_NIL_EXT; if (b) { m_rIdx++; return 0; } else return -1; }
        int  decodeAtom(std::string& a)     { char s[MAXATOMLEN]; if (ei_decode_atom(&m_rbuf,&m_rIdx,s) < 0) return -1; a=s; return 0; }
        int  decodeBool(bool& a) {
            std::string s;
            if (decodeAtom(s) < 0) return -1;
            else if (s == "true")  { a = true;  return 0; }
            else if (s == "false") { a = false; return 0; }
            else return -1;
        }

        int  decodeString(std::string& a) {
            StringBuffer<256> s;
            if (decodeString(s) < 0)
                return -1;
            a = s.c_str();
            return 0;
        }
        template <int N>
        int  decodeString(StringBuffer<N>& s) {
            int size;
            if (decodeType(size) != etString || !s.resize(size+1) || ei_decode_string(&m_rbuf, &m_rIdx, s.c_str()))
                return -1;
            return size;
        }

        int decodeBinary(std::string& data) {
            int size;
            if (decodeType(size) != etBinary) return -1;
            data.resize(size);
            long sz;
            if (ei_decode_binary(&m_rbuf, &m_rIdx, (void*)data.c_str(), &sz) < 0) return -1;
            return sz;
        }

        /// Print input buffer to stream
        int print(std::ostream& os, const std::string& header = "");

        /// Assumes the command is encoded as an atom. This function takes an
        /// array of strings and matches the atom to it. The index of the matched
        /// string in the <cmds> array is returned.
        template <int M>
        int decodeAtomIndex(const char* (&cmds)[M], std::string& cmd, int firstIdx = 0) {
            if (decodeAtom(cmd) < 0) return -1;
            return stringIndex(cmds, cmd, firstIdx, M);
        }

        /// Same as previous version but <cmds> array must have the last element being NULL
        int decodeAtomIndex(const char** cmds, std::string& cmd, int firstIdx = 0) {
            if (decodeAtom(cmd) < 0) return -1;
            return stringIndex(cmds, cmd, firstIdx);
        }

        int  set_handles(int in, int out, bool non_blocking = false);
        void close_handles()                { ::close(m_fin); ::close(m_fout); }

        int  read_handle()                  { return m_fin; }
        int  write_handle()                 { return m_fout; }

        const char* read_buffer()     const { return &m_rbuf; }
        const char* write_buffer()    const { return &m_wbuf; }
        int*        read_index()            { return &m_rIdx; }
        int*        write_index()           { return &m_wIdx; }
        int         read_idx()        const { return m_rIdx; }
        int         write_idx()       const { return m_wIdx; }

        /// Read command from <m_fin> into the internal buffer
        int  read();
        /// Write command from <m_fout> into the internal buffer
        int  write();

        /// Copy the content of write buffer from another serializer
        int  wcopy( const Serializer& ser)  { return m_wbuf.copy( ser.write_buffer(), 0, ser.write_idx()) != 0 ? 0 : -1; }
        /// Copy the content of read buffer from another serializer
        int  rcopy( const Serializer& ser)  { return m_rbuf.copy( ser.read_buffer(), 0, ser.read_idx() ) != 0 ? 0 : -1; }

        void set_rbuf(const char* a_bytes, size_t a_sz) {
            m_rbuf.reset();
            m_rbuf.copy(a_bytes, 0, a_sz);
        }

        /// dump read/write buffer's content to stream
        std::ostream& dump(std::ostream& os, bool outWriteBuffer);
    };

    /// Dump content of internal buffer to stream.
    std::ostream& dump(std::ostream& out, const unsigned char* a_buf = NULL, int n = 0, bool eol = true);
    // Write ei_x_buff to stream
    std::ostream& operator<< (std::ostream& os, const ei_x_buff& buf);
    bool dump(const char* header, std::ostream& out, const ei_x_buff& buf, bool condition);

} // namespace

#endif

