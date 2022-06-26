// idea from:
// https://github.com/openssh/openssh-portable/blob/2dc328023f60212cd29504fc05d849133ae47355/ttymodes.h

#define TTY_OP_ISPEED 128
#define TTY_OP_OSPEED 129

/* name, atom */
TTYCHAR(VINTR, "vintr")
TTYCHAR(VQUIT, "vquit")
TTYCHAR(VERASE, "verase")
#if defined(VKILL)
TTYCHAR(VKILL, "vkill")
#endif /* VKILL */
TTYCHAR(VEOF, "veof")
#if defined(VEOL)
TTYCHAR(VEOL, "veol")
#endif /* VEOL */
#ifdef VEOL2
TTYCHAR(VEOL2, "veol2")
#endif /* VEOL2 */
TTYCHAR(VSTART, "vstart")
TTYCHAR(VSTOP, "vstop")
#if defined(VSUSP)
TTYCHAR(VSUSP, "vsusp")
#endif /* VSUSP */
#if defined(VDSUSP)
TTYCHAR(VDSUSP, "vdsusp")
#endif /* VDSUSP */
#if defined(VREPRINT)
TTYCHAR(VREPRINT, "vreprint")
#endif /* VREPRINT */
#if defined(VWERASE)
TTYCHAR(VWERASE, "vwerase")
#endif /* VWERASE */
#if defined(VLNEXT)
TTYCHAR(VLNEXT, "vlnext")
#endif /* VLNEXT */
#if defined(VFLUSH)
TTYCHAR(VFLUSH, "vflush")
#endif /* VFLUSH */
#ifdef VSWTCH
TTYCHAR(VSWTCH, "vswtch")
#endif /* VSWTCH */
#if defined(VSTATUS)
TTYCHAR(VSTATUS, "vstatus")
#endif /* VSTATUS */
#ifdef VDISCARD
TTYCHAR(VDISCARD, "vdiscard")
#endif /* VDISCARD */

/* name, field, atom */
TTYMODE(IGNPAR, c_iflag, "ignpar")
TTYMODE(PARMRK, c_iflag, "parmrk")
TTYMODE(INPCK, c_iflag, "inpck")
TTYMODE(ISTRIP, c_iflag, "istrip")
TTYMODE(INLCR, c_iflag, "inlcr")
TTYMODE(IGNCR, c_iflag, "igncr")
TTYMODE(ICRNL, c_iflag, "icrnl")
#if defined(IUCLC)
TTYMODE(IUCLC, c_iflag, "iuclc")
#endif
TTYMODE(IXON, c_iflag, "ixon")
TTYMODE(IXANY, c_iflag, "ixany")
TTYMODE(IXOFF, c_iflag, "ixoff")
#ifdef IMAXBEL
TTYMODE(IMAXBEL, c_iflag, "imaxbel")
#endif /* IMAXBEL */
#ifdef IUTF8
TTYMODE(IUTF8, c_iflag, "iutf8")
#endif /* IUTF8 */

TTYMODE(ISIG, c_lflag, "isig")
TTYMODE(ICANON, c_lflag, "icanon")
#ifdef XCASE
TTYMODE(XCASE, c_lflag, "xcase")
#endif
TTYMODE(ECHO, c_lflag, "echo")
TTYMODE(ECHOE, c_lflag, "echoe")
TTYMODE(ECHOK, c_lflag, "echok")
TTYMODE(ECHONL, c_lflag, "echonl")
TTYMODE(NOFLSH, c_lflag, "noflsh")
TTYMODE(TOSTOP, c_lflag, "tostop")
#ifdef IEXTEN
TTYMODE(IEXTEN, c_lflag, "iexten")
#endif /* IEXTEN */
#if defined(ECHOCTL)
TTYMODE(ECHOCTL, c_lflag, "echoctl")
#endif /* ECHOCTL */
#ifdef ECHOKE
TTYMODE(ECHOKE, c_lflag, "echoke")
#endif /* ECHOKE */
#if defined(PENDIN)
TTYMODE(PENDIN, c_lflag, "pendin")
#endif /* PENDIN */

TTYMODE(OPOST, c_oflag, "opost")
#if defined(OLCUC)
TTYMODE(OLCUC, c_oflag, "olcuc")
#endif
#ifdef ONLCR
TTYMODE(ONLCR, c_oflag, "onlcr")
#endif
#ifdef OCRNL
TTYMODE(OCRNL, c_oflag, "ocrnl")
#endif
#ifdef ONOCR
TTYMODE(ONOCR, c_oflag, "onocr")
#endif
#ifdef ONLRET
TTYMODE(ONLRET, c_oflag, "onlret")
#endif

TTYMODE(CS7, c_cflag, "cs7")
TTYMODE(CS8, c_cflag, "cs8")
TTYMODE(PARENB, c_cflag, "parenb")
TTYMODE(PARODD, c_cflag, "parodd")

/* name, field, atom */
TTYSPEED(TTY_OP_ISPEED, c_ispeed, "tty_op_ispeed")
TTYSPEED(TTY_OP_OSPEED, c_ospeed, "tty_op_ospeed")