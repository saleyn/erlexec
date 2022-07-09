// idea from:
// https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/ttymodes.h

#define TTY_OP_ISPEED 128
#define TTY_OP_OSPEED 129

/* name, atom */
TTYCHAR(VINTR,    "vintr")
TTYCHAR(VQUIT,    "vquit")
TTYCHAR(VERASE,   "verase")
#if defined(VKILL)
TTYCHAR(VKILL,    "vkill")
#endif /* VKILL */
TTYCHAR(VEOF,     "veof")
#if defined(VEOL)
TTYCHAR(VEOL,     "veol")
#endif /* VEOL */
#ifdef VEOL2
TTYCHAR(VEOL2,    "veol2")
#endif /* VEOL2 */
TTYCHAR(VSTART,   "vstart")
TTYCHAR(VSTOP,    "vstop")
#if defined(VSUSP)
TTYCHAR(VSUSP,    "vsusp")
#endif /* VSUSP */
#if defined(VDSUSP)
TTYCHAR(VDSUSP,   "vdsusp")
#endif /* VDSUSP */
#if defined(VREPRINT)
TTYCHAR(VREPRINT, "vreprint")
#endif /* VREPRINT */
#if defined(VWERASE)
TTYCHAR(VWERASE,  "vwerase")
#endif /* VWERASE */
#if defined(VLNEXT)
TTYCHAR(VLNEXT,   "vlnext")
#endif /* VLNEXT */
#if defined(VFLUSH)
TTYCHAR(VFLUSH,   "vflush")
#endif /* VFLUSH */
#ifdef VSWTCH
TTYCHAR(VSWTCH,   "vswtch")
#endif /* VSWTCH */
#if defined(VSTATUS)
TTYCHAR(VSTATUS,  "vstatus")
#endif /* VSTATUS */
#ifdef VDISCARD
TTYCHAR(VDISCARD, "vdiscard")
#endif /* VDISCARD */

/* name, field, atom */
TTYMODE(IGNPAR,  c_iflag, "ignpar")
TTYMODE(PARMRK,  c_iflag, "parmrk")
TTYMODE(INPCK,   c_iflag, "inpck")
TTYMODE(ISTRIP,  c_iflag, "istrip")
TTYMODE(INLCR,   c_iflag, "inlcr")
TTYMODE(IGNCR,   c_iflag, "igncr")
TTYMODE(ICRNL,   c_iflag, "icrnl")
#if defined(IUCLC)
TTYMODE(IUCLC,   c_iflag, "iuclc")
#endif
TTYMODE(IXON,    c_iflag, "ixon")
TTYMODE(IXANY,   c_iflag, "ixany")
TTYMODE(IXOFF,   c_iflag, "ixoff")
#ifdef IMAXBEL
TTYMODE(IMAXBEL, c_iflag, "imaxbel")
#endif /* IMAXBEL */
#ifdef IUTF8
TTYMODE(IUTF8,   c_iflag, "iutf8")
#endif /* IUTF8 */

TTYMODE(ISIG,    c_lflag, "isig")
TTYMODE(ICANON,  c_lflag, "icanon")
#ifdef XCASE
TTYMODE(XCASE,   c_lflag, "xcase")
#endif
TTYMODE(ECHO,    c_lflag, "echo")
TTYMODE(ECHOE,   c_lflag, "echoe")
TTYMODE(ECHOK,   c_lflag, "echok")
TTYMODE(ECHONL,  c_lflag, "echonl")
TTYMODE(NOFLSH,  c_lflag, "noflsh")
TTYMODE(TOSTOP,  c_lflag, "tostop")
#ifdef IEXTEN
TTYMODE(IEXTEN,  c_lflag, "iexten")
#endif /* IEXTEN */
#if defined(ECHOCTL)
TTYMODE(ECHOCTL, c_lflag, "echoctl")
#endif /* ECHOCTL */
#ifdef ECHOKE
TTYMODE(ECHOKE,  c_lflag, "echoke")
#endif /* ECHOKE */
#if defined(PENDIN)
TTYMODE(PENDIN,  c_lflag, "pendin")
#endif /* PENDIN */

TTYMODE(OPOST,   c_oflag, "opost")
#if defined(OLCUC)
TTYMODE(OLCUC,   c_oflag, "olcuc")
#endif
#ifdef ONLCR
TTYMODE(ONLCR,   c_oflag, "onlcr")
#endif
#ifdef OCRNL
TTYMODE(OCRNL,   c_oflag, "ocrnl")
#endif
#ifdef ONOCR
TTYMODE(ONOCR,   c_oflag, "onocr")
#endif
#ifdef ONLRET
TTYMODE(ONLRET,  c_oflag, "onlret")
#endif

TTYMODE(CS7,     c_cflag, "cs7")
TTYMODE(CS8,     c_cflag, "cs8")
TTYMODE(PARENB,  c_cflag, "parenb")
TTYMODE(PARODD,  c_cflag, "parodd")

/* speed */
#ifdef B0
TTYSPEED(B0)
#endif
#ifdef B50
TTYSPEED(B50)
#endif
#ifdef B75
TTYSPEED(B75)
#endif
#ifdef B110
TTYSPEED(B110)
#endif
#ifdef B134
TTYSPEED(B134)
#endif
#ifdef B150
TTYSPEED(B150)
#endif
#ifdef B200
TTYSPEED(B200)
#endif
#ifdef B300
TTYSPEED(B300)
#endif
#ifdef B600
TTYSPEED(B600)
#endif
#ifdef B1200
TTYSPEED(B1200)
#endif
#ifdef B1800
TTYSPEED(B1800)
#endif
#ifdef B2400
TTYSPEED(B2400)
#endif
#ifdef B4800
TTYSPEED(B4800)
#endif
#ifdef B9600
TTYSPEED(B9600)
#endif
#ifdef B19200
TTYSPEED(B19200)
#endif
#ifdef B38400
TTYSPEED(B38400)
#endif
#ifdef B57600
TTYSPEED(B57600)
#endif
#ifdef B115200
TTYSPEED(B115200)
#endif
#ifdef B230400
TTYSPEED(B230400)
#endif
#ifdef B460800
TTYSPEED(B460800)
#endif
#ifdef B500000
TTYSPEED(B500000)
#endif
#ifdef B576000
TTYSPEED(B576000)
#endif
#ifdef B921600
TTYSPEED(B921600)
#endif
#ifdef B1000000
TTYSPEED(B1000000)
#endif
#ifdef B1152000
TTYSPEED(B1152000)
#endif
#ifdef B1500000
TTYSPEED(B1500000)
#endif
#ifdef B200000
TTYSPEED(B2000000)
#endif