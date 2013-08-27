#include <unistd.h>
#include <fcntl.h>
#include <sstream>
#include <iomanip>
#include "ei++.hpp"

using namespace ei;

//-----------------------------------------------------------------------------
bool ei::dump ( const char* header, std::ostream& os, const ei_x_buff& buf, bool condition )
{
    if ( !condition ) os << (header ? header : "") << buf;
    return condition;
}

//-----------------------------------------------------------------------------
std::ostream& ei::dump (std::ostream& os, const unsigned char* buf, int n, bool eol)
{
    std::stringstream s;
    for(int i=0; i < n; i++)
        s << (i == 0 ? "<<" : ",") << (int) (buf[i]);
    s << (n == 0 ? "<<>>" : ">>");
    if (eol) s << std::endl;
    return os << s.str();
}

//-----------------------------------------------------------------------------
std::ostream& ei::operator<< (std::ostream& os, const ei_x_buff& buf)
{
    return dump(os, (const unsigned char*)buf.buff, buf.index);
}

//-----------------------------------------------------------------------------
int ei::stringIndex(const char** cmds, const std::string& cmd, int firstIdx, int size)
{
    for (int i=firstIdx; cmds != NULL && i < size; i++, cmds++)
        if (cmd == *cmds)
            return i;
    return firstIdx-1;
}

//-----------------------------------------------------------------------------
std::ostream& ei::Serializer::dump (std::ostream& os, bool outWriteBuffer)
{
    if (outWriteBuffer) {
        size_t len = m_wbuf.read_header();
        if (!len) len = m_wIdx;
        os << "--Erl-<-C--[" << std::setw(len < 10000 ? 4 : 9) << len << "]: ";
        return ::dump(os, (const unsigned char*)&m_wbuf, len, false) << "\r\n";
    } else {
        size_t len = m_rbuf.read_header();
        os << "--Erl->-C--[" << std::setw(len < 10000 ? 4 : 9) << len << "]: ";
        return ::dump(os, (const unsigned char*)&m_rbuf, len, false) << "\r\n";
    }
}

//-----------------------------------------------------------------------------
int ei::Serializer::print (std::ostream& os, const std::string& header)
{
    char* s   = NULL;
    int   idx = 0;
    if (ei_s_print_term(&s, &m_rbuf, &idx) < 0)
        return -1;
    if (!header.empty())
        os << header << s << std::endl;
    else
        os << s << std::endl;

    if (s)
        free(s);

    return 0;
}

//-----------------------------------------------------------------------------
TimeVal ei::operator- (const TimeVal& t1, const TimeVal& t2) {
    TimeVal t = t1; t -= t2;
    return t;
}

//-----------------------------------------------------------------------------
TimeVal ei::operator+ (const TimeVal& t1, const TimeVal& t2) {
    TimeVal t = t1; t += t2;
    return t;
}

//-----------------------------------------------------------------------------
TimeVal::TimeVal(TimeType tp, int _s, int _us)
{
    switch (tp) {
        case NOW:
            gettimeofday(&m_tv, NULL);
            break;
        case RELATIVE:
            new (this) TimeVal();
    }
    if (_s != 0 || _us != 0) add(_s, _us);
}

//-----------------------------------------------------------------------------
int Serializer::set_handles(int in, int out, bool non_blocking)
{
    m_fin = in;
    m_fout = out;
    if (non_blocking) {
        return fcntl(m_fin,  F_SETFL, fcntl(m_fin,  F_GETFL) | O_NONBLOCK)
            || fcntl(m_fout, F_SETFL, fcntl(m_fout, F_GETFL) | O_NONBLOCK);
    } else
        return 0;
}

//-----------------------------------------------------------------------------
int Serializer::read()
{
    if (m_readPacketSz == 0) {
        int size = m_rbuf.headerSize();
        if (read_exact(m_fin, &m_rbuf.c_str()[-size], size, m_readOffset) < size)
            return -1;

        m_readPacketSz = m_rbuf.read_header();
        m_readOffset   = 0;

        if (m_debug)
            std::cerr << "Serializer::read() - message size: " << m_readPacketSz << '\r' << std::endl;

        if (!m_rbuf.resize(m_readPacketSz))
            return -2;
    }

    int total = m_readPacketSz - m_readOffset;
    if (read_exact(m_fin, &m_rbuf, m_readPacketSz, m_readOffset) < total)
        return -3;

    m_rIdx = 0;

    if (m_debug)
        dump(std::cerr, false);

    int len = m_readPacketSz;
    m_readOffset = m_readPacketSz = 0;

    /* Ensure that we are receiving the binary term by reading and
     * stripping the version byte */
    int version;
    if (ei_decode_version(&m_rbuf, &m_rIdx, &version))
        return -4;

    return len;
}

//-----------------------------------------------------------------------------
int Serializer::write()
{
    if (m_writePacketSz == 0) {
        m_wbuf.write_header(static_cast<size_t>(m_wIdx));
        if (m_debug)
            dump(std::cerr, true);

        m_writePacketSz = m_wIdx+m_wbuf.headerSize();
        m_writeOffset = 0;
    }

    int total = m_writePacketSz - m_writeOffset;
    if (write_exact(m_fout, m_wbuf.header(), m_writePacketSz, m_writeOffset) < total)
        return -1;

    int len = m_writePacketSz;
    m_writeOffset = m_writePacketSz = 0;

    return len;
}

//-----------------------------------------------------------------------------
int Serializer::read_exact(int fd, char *buf, size_t len, size_t& got)
{
    int i;

    while (got < len) {
        int size = len-got;
        while ((i = ::read(fd, (void*)(buf+got), size)) < size && errno == EINTR)
            if (i > 0)
                got += i;

        if (i <= 0)
            return i;
        got += i;
    }

    return len;
}

//-----------------------------------------------------------------------------
int Serializer::write_exact(int fd, const char *buf, size_t len, size_t& wrote)
{
    int i;

    while (wrote < len) {
        int size = len-wrote;
        while ((i = ::write(fd, buf+wrote, size)) < size && errno == EINTR)
            if (i > 0)
                wrote += i;

        if (i <= 0)
            return i;
        wrote += i;
    }

    return wrote;
}


#define get8(s)    ((s) += 1, ((unsigned char *)(s))[-1] & 0xff)
#define put8(s,n) do { (s)[0] = (char)((n) & 0xff); (s) += 1; } while (0)

#define put64be(s,n) do {  \
      (s)[0] = ((n) >>  56) & 0xff; \
      (s)[1] = ((n) >>  48) & 0xff; \
      (s)[2] = ((n) >>  40) & 0xff; \
      (s)[3] = ((n) >>  32) & 0xff; \
      (s)[4] = ((n) >>  24) & 0xff; \
      (s)[5] = ((n) >>  16) & 0xff; \
      (s)[6] = ((n) >>  8)  & 0xff; \
      (s)[7] = (n) & 0xff; \
      (s) += 8; \
    } while (0)

#define get64be(s) \
     ((s) += 8, \
      (((unsigned long long)((unsigned char *)(s))[-8] << 56) | \
       ((unsigned long long)((unsigned char *)(s))[-7] << 48) | \
       ((unsigned long long)((unsigned char *)(s))[-6] << 40) | \
       ((unsigned long long)((unsigned char *)(s))[-5] << 32) | \
       ((unsigned long long)((unsigned char *)(s))[-4] << 24) | \
       ((unsigned long long)((unsigned char *)(s))[-3] << 16) | \
       ((unsigned long long)((unsigned char *)(s))[-2] << 8)  | \
        (unsigned long long)((unsigned char *)(s))[-1]))

int Serializer::ei_decode_double(const char *buf, int *index, double *p)
{
  const char *s = buf + *index;
  const char *s0 = s;
  double f;

  switch (get8(s)) {
    case ERL_FLOAT_EXT:
      if (sscanf(s, "%lf", &f) != 1) return -1;
      s += 31;
      break;
    case NEW_FLOAT_EXT: {
      // IEEE 754 decoder
      const unsigned int bits    = 64;
      const unsigned int expbits = 11;
      const unsigned int significantbits = bits - expbits - 1; // -1 for sign bit
      unsigned long long i = get64be(s);
      long long shift;
      unsigned bias;

      if (!p)
        break;
      else if (i == 0)
        f = 0.0;
      else {
        // get the significant
        f  = (i & ((1LL << significantbits)-1)); // mask
        f /= (1LL << significantbits);           // convert back to float
        f += 1.0f;                               // add the one back on

        // get the exponent
        bias  = (1 << (expbits-1)) - 1;
        shift = ((i >> significantbits) & ((1LL << expbits)-1)) - bias;
        while (shift > 0) { f *= 2.0; shift--; }
        while (shift < 0) { f /= 2.0; shift++; }

        // signness
        f *= (i >> (bits-1)) & 1 ? -1.0: 1.0;
      }
      break;
    }
    default:
      return -1;
  }

  if (p) *p = f;
  *index += s-s0;
  return 0;
}

int Serializer::ei_encode_double(char *buf, int *index, double p)
{
  char *s = buf + *index;
  char *s0 = s;

  if (!buf)
    s = s+9;
  else { /* use IEEE 754 format */
    const unsigned int  bits    = 64;
    const unsigned int  expbits = 11;
    const unsigned int  significantbits = bits - expbits - 1; // -1 for sign bit
    long long           sign, exp, significant;
    long double         norm;
    int                 shift;

    put8(s, NEW_FLOAT_EXT);
    memset(s, 0, 8);

    if (p == 0.0)
      s += 8;
    else {
      // check sign and begin normalization
      if (p < 0) { sign = 1; norm = -p; }
      else       { sign = 0; norm =  p; }

      // get the normalized form of p and track the exponent
      shift = 0;
      while(norm >= 2.0) { norm /= 2.0; shift++; }
      while(norm < 1.0)  { norm *= 2.0; shift--; }
      norm = norm - 1.0;

      // calculate the binary form (non-float) of the significant data
      significant = (long long) ( norm * ((1LL << significantbits) + 0.5f) );

      // get the biased exponent
      exp = shift + ((1 << (expbits-1)) - 1); // shift + bias

      // get the final answer
      exp = (sign << (bits-1)) | (exp << (bits-expbits-1)) | significant;
      put64be(s, exp);
    }
  }

  *index += s-s0;
  return 0;
}

int x_fix_buff(ei_x_buff* x, int szneeded)
{
    int sz = szneeded + 100;
    if (sz > x->buffsz) {
        sz += 100;   /* to avoid reallocating each and every time */
        x->buffsz = sz;
        x->buff = (char*)realloc(x->buff, sz);
    }
    return x->buff != NULL;
}

int Serializer::ei_x_encode_double(ei_x_buff* x, double dbl)
{
    int i = x->index;
    ei_encode_double(NULL, &i, dbl);
    if (!x_fix_buff(x, i))
    return -1;
    return ei_encode_double(x->buff, &x->index, dbl);
}

