## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Clone of p0f passive OS fingerprinting
"""

import time
import struct
import os
import socket
import random

from scapy.data import KnowledgeBase
from scapy.config import conf
from scapy.layers.inet import IP, TCP, TCPOptions
from scapy.layers.inet6 import IPv6
from scapy.packet import NoPayload, Packet
from scapy.error import warning, Scapy_Exception, log_runtime
from scapy.volatile import RandInt, RandByte, RandChoice, RandNum, RandShort, RandString
from scapy.sendrecv import sniff
if conf.route is None:
    # unused import, only to initialize conf.route
    import scapy.route

conf.p0f_base ="/etc/p0f/p0f.fp"
conf.p0fa_base ="/etc/p0f/p0fa.fp"
conf.p0fr_base ="/etc/p0f/p0fr.fp"
conf.p0fo_base ="/etc/p0f/p0fo.fp"


###############
## p0f stuff ##
###############

# File format (according to p0f.fp) :
#
# wwww:ttt:D:ss:OOO...:QQ:OS:Details
#
# wwww    - window size
# ttt     - initial TTL
# D       - don't fragment bit  (0=unset, 1=set) 
# ss      - overall SYN packet size
# OOO     - option value and order specification
# QQ      - quirks list
# OS      - OS genre
# details - OS description

class p0fKnowledgeBase(KnowledgeBase):
    def __init__(self, filename):
        KnowledgeBase.__init__(self, filename)
        #self.ttl_range=[255]
    def lazy_init(self):
        try:
            f=open(self.filename)
        except IOError:
            warning("Can't open base %s" % self.filename)
            return
        try:
            self.base = []
            for l in f:
                if l[0] in ["#","\n"]:
                    continue
                l = tuple(l.split(":"))
                if len(l) < 8:
                    continue
                def a2i(x):
                    if x.isdigit():
                        return int(x)
                    return x
                li = [a2i(e) for e in l[1:4]]
                #if li[0] not in self.ttl_range:
                #    self.ttl_range.append(li[0])
                #    self.ttl_range.sort()
                self.base.append((l[0], li[0], li[1], li[2], l[4], l[5], l[6], l[7][:-1]))
        except:
            warning("Can't parse p0f database (new p0f version ?)")
            self.base = None
        f.close()

p0f_kdb = p0fKnowledgeBase(conf.p0f_base)
p0fa_kdb = p0fKnowledgeBase(conf.p0fa_base)
p0fr_kdb = p0fKnowledgeBase(conf.p0fr_base)
p0fo_kdb = p0fKnowledgeBase(conf.p0fo_base)

def p0f_selectdb(flags):
    # tested flags: S, R, A
    if flags & 0x16 == 0x2:
        # SYN
        return p0f_kdb
    elif flags & 0x16 == 0x12:
        # SYN/ACK
        return p0fa_kdb
    elif flags & 0x16 in [ 0x4, 0x14 ]:
        # RST RST/ACK
        return p0fr_kdb
    elif flags & 0x16 == 0x10:
        # ACK
        return p0fo_kdb
    else:
        return None

def packet2p0f(pkt):
    pkt = pkt.copy()
    pkt = pkt.__class__(str(pkt))
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload
    
    if not isinstance(pkt, IP) or not isinstance(pkt.payload, TCP):
        raise TypeError("Not a TCP/IP packet")
    #if pkt.payload.flags & 0x7 != 0x02: #S,!F,!R
    #    raise TypeError("Not a SYN or SYN/ACK packet")
    
    db = p0f_selectdb(pkt.payload.flags)
    
    #t = p0f_kdb.ttl_range[:]
    #t += [pkt.ttl]
    #t.sort()
    #ttl=t[t.index(pkt.ttl)+1]
    ttl = pkt.ttl
    
    df = (pkt.flags & 2) / 2
    ss = len(pkt)
    # from p0f/config.h : PACKET_BIG = 100
    if ss > 100:
        if db == p0fr_kdb:
            # p0fr.fp: "Packet size may be wildcarded. The meaning of
            #           wildcard is, however, hardcoded as 'size >
            #           PACKET_BIG'"
            ss = '*'
        else:
            ss = 0
    if db == p0fo_kdb:
        # p0fo.fp: "Packet size MUST be wildcarded."
        ss = '*'
    
    ooo = ""
    mss = -1
    qqT = False
    qqP = False
    #qqBroken = False
    ilen = (pkt.payload.dataofs << 2) - 20 # from p0f.c
    for option in pkt.payload.options:
        ilen -= 1
        if option[0] == "MSS":
            ooo += "M" + str(option[1]) + ","
            mss = option[1]
            # FIXME: qqBroken
            ilen -= 3
        elif option[0] == "WScale":
            ooo += "W" + str(option[1]) + ","
            # FIXME: qqBroken
            ilen -= 2
        elif option[0] == "Timestamp":
            if option[1][0] == 0:
                ooo += "T0,"
            else:
                ooo += "T,"
            if option[1][1] != 0:
                qqT = True
            ilen -= 9
        elif option[0] == "SAckOK":
            ooo += "S,"
            ilen -= 1
        elif option[0] == "NOP":
            ooo += "N,"
        elif option[0] == "EOL":
            ooo += "E,"
            if ilen > 0:
                qqP = True
        else:
            if isinstance(option[0], str):
                ooo += "?%i," % TCPOptions[1][option[0]]
            else:
                ooo += "?%i," % option[0]
            # FIXME: ilen
    ooo = ooo[:-1]
    if ooo == "": ooo = "."
    
    win = pkt.payload.window
    if mss != -1:
        if mss != 0 and win % mss == 0:
            win = "S" + str(win/mss)
        elif win % (mss + 40) == 0:
            win = "T" + str(win/(mss+40))
    win = str(win)
    
    qq = ""
    
    if db == p0fr_kdb:
        if pkt.payload.flags & 0x10 == 0x10:
            # p0fr.fp: "A new quirk, 'K', is introduced to denote
            #           RST+ACK packets"
            qq += "K"
    # The two next cases should also be only for p0f*r*, but although
    # it's not documented (or I have not noticed), p0f seems to
    # support the '0' and 'Q' quirks on any databases (or at the least
    # "classical" p0f.fp).
    if pkt.payload.seq == pkt.payload.ack:
        # p0fr.fp: "A new quirk, 'Q', is used to denote SEQ number
        #           equal to ACK number."
        qq += "Q"
    if pkt.payload.seq == 0:
        # p0fr.fp: "A new quirk, '0', is used to denote packets
        #           with SEQ number set to 0."
        qq += "0"
    if qqP:
        qq += "P"
    if pkt.id == 0:
        qq += "Z"
    if pkt.options != []:
        qq += "I"
    if pkt.payload.urgptr != 0:
        qq += "U"
    if pkt.payload.reserved != 0:
        qq += "X"
    if pkt.payload.ack != 0:
        qq += "A"
    if qqT:
        qq += "T"
    if db == p0fo_kdb:
        if pkt.payload.flags & 0x20 != 0:
            # U
            # p0fo.fp: "PUSH flag is excluded from 'F' quirk checks"
            qq += "F"
    else:
        if pkt.payload.flags & 0x28 != 0:
            # U or P
            qq += "F"
    if db != p0fo_kdb and not isinstance(pkt.payload.payload, NoPayload):
        # p0fo.fp: "'D' quirk is not checked for."
        qq += "D"
    # FIXME : "!" - broken options segment: not handled yet

    if qq == "":
        qq = "."

    return (db, (win, ttl, df, ss, ooo, qq))

def p0f_correl(x,y):
    d = 0
    # wwww can be "*" or "%nn". "Tnn" and "Snn" should work fine with
    # the x[0] == y[0] test.
    d += (x[0] == y[0] or y[0] == "*" or (y[0][0] == "%" and x[0].isdigit() and (int(x[0]) % int(y[0][1:])) == 0))
    # ttl
    d += (y[1] >= x[1] and y[1] - x[1] < 32)
    for i in [2, 5]:
        d += (x[i] == y[i] or y[i] == '*')
    # '*' has a special meaning for ss
    d += x[3] == y[3]
    xopt = x[4].split(",")
    yopt = y[4].split(",")
    if len(xopt) == len(yopt):
        same = True
        for i in xrange(len(xopt)):
            if not (xopt[i] == yopt[i] or
                    (len(yopt[i]) == 2 and len(xopt[i]) > 1 and
                     yopt[i][1] == "*" and xopt[i][0] == yopt[i][0]) or
                    (len(yopt[i]) > 2 and len(xopt[i]) > 1 and
                     yopt[i][1] == "%" and xopt[i][0] == yopt[i][0] and
                     int(xopt[i][1:]) % int(yopt[i][2:]) == 0)):
                same = False
                break
        if same:
            d += len(xopt)
    return d


@conf.commands.register
def p0f(pkt):
    """Passive OS fingerprinting: which OS emitted this TCP packet ?
p0f(packet) -> accuracy, [list of guesses]
"""
    db, sig = packet2p0f(pkt)
    if db:
        pb = db.get_base()
    else:
        pb = []
    if not pb:
        warning("p0f base empty.")
        return []
    #s = len(pb[0][0])
    r = []
    max = len(sig[4].split(",")) + 5
    for b in pb:
        d = p0f_correl(sig,b)
        if d == max:
            r.append((b[6], b[7], b[1] - pkt[IP].ttl))
    return r

def prnp0f(pkt):
    # we should print which DB we use
    try:
        r = p0f(pkt)
    except:
        return
    if r == []:
        r = ("UNKNOWN", "[" + ":".join(map(str, packet2p0f(pkt)[1])) + ":?:?]", None)
    else:
        r = r[0]
    uptime = None
    try:
        uptime = pkt2uptime(pkt)
    except:
        pass
    if uptime == 0:
        uptime = None
    res = pkt.sprintf("%IP.src%:%TCP.sport% - " + r[0] + " " + r[1])
    if uptime is not None:
        res += pkt.sprintf(" (up: " + str(uptime/3600) + " hrs)\n  -> %IP.dst%:%TCP.dport% (%TCP.flags%)")
    else:
        res += pkt.sprintf("\n  -> %IP.dst%:%TCP.dport% (%TCP.flags%)")
    if r[2] is not None:
        res += " (distance " + str(r[2]) + ")"
    print res

@conf.commands.register
def pkt2uptime(pkt, HZ=100):
    """Calculate the date the machine which emitted the packet booted using TCP timestamp 
pkt2uptime(pkt, [HZ=100])"""
    if not isinstance(pkt, Packet):
        raise TypeError("Not a TCP packet")
    if isinstance(pkt,NoPayload):
        raise TypeError("Not a TCP packet")
    if not isinstance(pkt, TCP):
        return pkt2uptime(pkt.payload)
    for opt in pkt.options:
        if opt[0] == "Timestamp":
            #t = pkt.time - opt[1][0] * 1.0/HZ
            #return time.ctime(t)
            t = opt[1][0] / HZ
            return t
    raise TypeError("No timestamp option")

def p0f_impersonate(pkt, osgenre=None, osdetails=None, signature=None,
                    extrahops=0, mtu=1500, uptime=None):
    """Modifies pkt so that p0f will think it has been sent by a
specific OS.  If osdetails is None, then we randomly pick up a
personality matching osgenre. If osgenre and signature are also None,
we use a local signature (using p0f_getlocalsigs). If signature is
specified (as a tuple), we use the signature.

For now, only TCP Syn packets are supported.
Some specifications of the p0f.fp file are not (yet) implemented."""
    pkt = pkt.copy()
    #pkt = pkt.__class__(str(pkt))
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload
    
    if not isinstance(pkt, IP) or not isinstance(pkt.payload, TCP):
        raise TypeError("Not a TCP/IP packet")
    
    if uptime is None:
        uptime = random.randint(120,100*60*60*24*365)
    
    db = p0f_selectdb(pkt.payload.flags)
    if osgenre:
        pb = db.get_base()
        if pb is None:
            pb = []
        pb = filter(lambda x: x[6] == osgenre, pb)
        if osdetails:
            pb = filter(lambda x: x[7] == osdetails, pb)
    elif signature:
        pb = [signature]
    else:
        pb = p0f_getlocalsigs()[db]
    if db == p0fr_kdb:
        # 'K' quirk <=> RST+ACK
        if pkt.payload.flags & 0x4 == 0x4:
            pb = filter(lambda x: 'K' in x[5], pb)
        else:
            pb = filter(lambda x: 'K' not in x[5], pb)
    if not pb:
        raise Scapy_Exception("No match in the p0f database")
    pers = pb[random.randint(0, len(pb) - 1)]
    
    # options (we start with options because of MSS)
    ## TODO: let the options already set if they are valid
    options = []
    if pers[4] != '.':
        for opt in pers[4].split(','):
            if opt[0] == 'M':
                # MSS might have a maximum size because of window size
                # specification
                if pers[0][0] == 'S':
                    maxmss = (2**16-1) / int(pers[0][1:])
                else:
                    maxmss = (2**16-1)
                # If we have to randomly pick up a value, we cannot use
                # scapy RandXXX() functions, because the value has to be
                # set in case we need it for the window size value. That's
                # why we use random.randint()
                if opt[1:] == '*':
                    options.append(('MSS', random.randint(1,maxmss)))
                elif opt[1] == '%':
                    coef = int(opt[2:])
                    options.append(('MSS', coef*random.randint(1,maxmss/coef)))
                else:
                    options.append(('MSS', int(opt[1:])))
            elif opt[0] == 'W':
                if opt[1:] == '*':
                    options.append(('WScale', RandByte()))
                elif opt[1] == '%':
                    coef = int(opt[2:])
                    options.append(('WScale', coef*RandNum(min=1,
                                                           max=(2**8-1)/coef)))
                else:
                    options.append(('WScale', int(opt[1:])))
            elif opt == 'T0':
                options.append(('Timestamp', (0, 0)))
            elif opt == 'T':
                if 'T' in pers[5]:
                    # FIXME: RandInt() here does not work (bug (?) in
                    # TCPOptionsField.m2i often raises "OverflowError:
                    # long int too large to convert to int" in:
                    #    oval = struct.pack(ofmt, *oval)"
                    # Actually, this is enough to often raise the error:
                    #    struct.pack('I', RandInt())
                    options.append(('Timestamp', (uptime, random.randint(1,2**32-1))))
                else:
                    options.append(('Timestamp', (uptime, 0)))
            elif opt == 'S':
                options.append(('SAckOK', ''))
            elif opt == 'N':
                options.append(('NOP', None))
            elif opt == 'E':
                options.append(('EOL', None))
            elif opt[0] == '?':
                if int(opt[1:]) in TCPOptions[0]:
                    optname = TCPOptions[0][int(opt[1:])][0]
                    optstruct = TCPOptions[0][int(opt[1:])][1]
                    options.append((optname,
                                    struct.unpack(optstruct,
                                                  RandString(struct.calcsize(optstruct))._fix())))
                else:
                    options.append((int(opt[1:]), ''))
            ## FIXME: qqP not handled
            else:
                warning("unhandled TCP option " + opt)
            pkt.payload.options = options
    
    # window size
    if pers[0] == '*':
        pkt.payload.window = RandShort()
    elif pers[0].isdigit():
        pkt.payload.window = int(pers[0])
    elif pers[0][0] == '%':
        coef = int(pers[0][1:])
        pkt.payload.window = coef * RandNum(min=1,max=(2**16-1)/coef)
    elif pers[0][0] == 'T':
        pkt.payload.window = mtu * int(pers[0][1:])
    elif pers[0][0] == 'S':
        ## needs MSS set
        MSS = filter(lambda x: x[0] == 'MSS', options)
        if not filter(lambda x: x[0] == 'MSS', options):
            raise Scapy_Exception("TCP window value requires MSS, and MSS option not set")
        pkt.payload.window = filter(lambda x: x[0] == 'MSS', options)[0][1] * int(pers[0][1:])
    else:
        raise Scapy_Exception('Unhandled window size specification')
    
    # ttl
    pkt.ttl = pers[1]-extrahops
    # DF flag
    pkt.flags |= (2 * pers[2])
    ## FIXME: ss (packet size) not handled (how ? may be with D quirk
    ## if present)
    # Quirks
    if pers[5] != '.':
        for qq in pers[5]:
            ## FIXME: not handled: P, I, X, !
            # T handled with the Timestamp option
            if qq == 'Z': pkt.id = 0
            elif qq == 'U': pkt.payload.urgptr = RandShort()
            elif qq == 'A': pkt.payload.ack = RandInt()
            elif qq == 'F':
                if db == p0fo_kdb:
                    pkt.payload.flags |= 0x20 # U
                else:
                    pkt.payload.flags |= RandChoice(8, 32, 40) #P / U / PU
            elif qq == 'D' and db != p0fo_kdb:
                pkt /= conf.raw_layer(load=RandString(random.randint(1, 10))) # XXX p0fo.fp
            elif qq == 'Q': pkt.payload.seq = pkt.payload.ack
            #elif qq == '0': pkt.payload.seq = 0
        #if db == p0fr_kdb:
        # '0' quirk is actually not only for p0fr.fp (see
        # packet2p0f())
    if '0' in pers[5]:
        pkt.payload.seq = 0
    elif pkt.payload.seq == 0:
        pkt.payload.seq = RandInt()
    
    while pkt.underlayer:
        pkt = pkt.underlayer
    return pkt

def p0f_getlocalsigs():
    """This function returns a dictionary of signatures indexed by p0f
db (e.g., p0f_kdb, p0fa_kdb, ...) for the local TCP/IP stack.

You need to have your firewall at least accepting the TCP packets
from/to a high port (30000 <= x <= 40000) on your loopback interface.

Please note that the generated signatures come from the loopback
interface and may (are likely to) be different than those generated on
"normal" interfaces."""
    pid = os.fork()
    port = random.randint(30000, 40000)
    if pid > 0:
        # parent: sniff
        result = {}
        def addresult(res):
            # TODO: wildcard window size in some cases? and maybe some
            # other values?
            if res[0] not in result:
                result[res[0]] = [res[1]]
            else:
                if res[1] not in result[res[0]]:
                    result[res[0]].append(res[1])
        # XXX could we try with a "normal" interface using other hosts
        iface = conf.route.route('127.0.0.1')[0]
        # each packet is seen twice: S + RA, S + SA + A + FA + A
        # XXX are the packets also seen twice on non Linux systems ?
        count=14
        pl = sniff(iface=iface, filter='tcp and port ' + str(port), count = count, timeout=3)
        for pkt in pl:
            for elt in packet2p0f(pkt):
                addresult(elt)
        os.waitpid(pid,0)
    elif pid < 0:
        log_runtime.error("fork error")
    else:
        # child: send
        # XXX erk
        time.sleep(1)
        s1 = socket.socket(socket.AF_INET, type = socket.SOCK_STREAM)
        # S & RA
        try:
            s1.connect(('127.0.0.1', port))
        except socket.error:
            pass
        # S, SA, A, FA, A
        s1.bind(('127.0.0.1', port))
        s1.connect(('127.0.0.1', port))
        # howto: get an RST w/o ACK packet
        s1.close()
        os._exit(0)
    return result

# Old p0f 2 format
# File format (according to p0f.fp) :
#
# wwww:ttt:D:ss:OOO...:QQ:OS:Details
#
# wwww    - window size
# ttt     - initial TTL
# D       - don't fragment bit  (0=unset, 1=set)
# ss      - overall SYN packet size
# OOO     - option value and order specification
# QQ      - quirks list
# OS      - OS genre
# details - OS description

# New p0f3 format
#
#File format :
#
# ipversion:ttl:mss:winscale:tcpolayout:quirks:winsize:ipolength:payloadsize
#
# ipversion   - IP version: 4 / 6
# ttl         - Initial TTL
# mss         - maximum segment Can be a constant or *.
# winscale    - Window Scale: window scale specified during the three way handshake. Can be a constant or *.
# tcpolayout  - TCP options layout: list of TCP options in the order they are seen in a TCP packet.
# quirks      - comma separated list of unusual things
# winsize     - Window Size: window size specified in the TCP header.
# ipolength   - IP options length: OK
# payloadsize -  class: TCP payload size. Can be 0 (no data), + (1 or more bytes of data) or *.
def p0f3_impersonate(pkt, signature, extrahops=0):
    """For now, only TCP Syn packets are supported.
Some specifications of the p0f.fp file are not (yet) implemented."""

    pkt = pkt.copy()
    while pkt.haslayer(IP) and pkt.haslayer(TCP):
        pkt = pkt.getlayer(IP)
        if isinstance(pkt.payload, TCP):
            break
        pkt = pkt.payload

    # IPversion
    if signature[0] == '4':
        if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            pkt = IP() / pkt
        if pkt.haslayer(IPv6):
            raise TypeError("IPv4 specified in signature but ipv6 packet was given as parameter")

    elif signature[0] == '6':
        if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
            pkt = IPv6() / pkt
        if pkt.haslayer(IP):
            raise TypeError("IPv6 specified in signature but ipv4 packet was given as parameter")
    else:
        raise TypeError(("Only IPv4 or IPv6 is allowed, not : %s") % signature[0])

    # TTL
    if signature[1].isdigit():
        pkt.ttl = int(signature[1]) - extrahops
    elif signature[1].find("-") != -1:
        diff1, diff2 = signature[1].split("-")
        pkt.ttl = int(diff1) - int(diff2)

    # IP options length
    if signature[2] != '0' and signature[2] != '.':
        if signature[2].isdigit():
            pkt.getlayer(IP).options = urandom(int(signature[2]))
            pass
        raise TypeError("IP option length not recognized, must be . * or digit")

    # TCP Payload
    if signature[7] != '0' and signature != '.':
        if signature[7].isdigit():
            load = RandString(random.randint(1, int(signature[7])))
            pkt.payload.payload = load
        elif signature[7] == '*':
            load = RandString(random.randint(1, 10))
            pkt.payload.payload = load
        else:
            raise TypeError("Payload size in signature is not valid")

    # Options
    options = []
    if signature[5] != '.':
        for opt in signature[5].split(','):
            if opt == 'mss':
                # MSS might have a maximum size because of window size
                # specification
                if signature[4].split(",")[0].isdigit() and not signature[3].isdigit():
                    maxmss = (2L ** 16 - 1) / int(signature[4].split(",")[0])
                elif signature[3].isdigit():
                    maxmss = int(signature[3])
                else:
                    raise TypeError(("Coefficient window size not implemented: %s") % signature[4])
                options.append(('MSS', random.randint(1, maxmss)))
            elif opt == 'ws':
                if signature[4].split(",")[1].isdigit() and not signature[6].find('exws') != -1:
                    options.append(('WScale', int(signature[4].split(",")[1])))
                if signature[6].find('exws') != -1:
                    options.append(('WScale', 14))
                else:
                    options.append(('WScale', RandByte()))
            elif opt == 'sok':
                options.append(('SAckOK', ''))
            elif opt == 'sack':
                options.append(('SAck', ''))
            elif opt == 'ts':
                options.append(('Timestamp', (0, 0)))
                if signature[6].find("ts1-") != -1:
                    options.append(('Timestamp', (0, 0)))
                if signature[6].find("ts2+") != -1:
                    options.append(('Timestamp', RandInt()))
            elif opt == 'nop':
                options.append(('NOP', None))
            elif opt.find('eol+') != -1:  #
                options.append(('EOL', None))
            else:
                warning("unhandled TCP option " + opt)

            pkt.payload.options = options

    # MSS
    if signature[3].isdigit():
        if not filter(lambda x: x[0] == 'MSS', options):
            raise Scapy_Exception("Requires MSS, and MSS option not set")
    elif signature[3] == '*':
        if not filter(lambda x: x[0] == 'MSS', options):
            raise Scapy_Exception("Requires MSS, and MSS option not set")

    # Window scale
    if signature[5].isdigit():
        if not filter(lambda x: x[0] == 'WScale', options):
            raise Scapy_Exception("Requires WScale, and WScale option not set")
    elif signature[5] == '*':
        if not filter(lambda x: x[0] == 'WScale', options):
            raise Scapy_Exception("Requires WScale, and WScale option not set")

    # Window Size
    # TODO : ADD COEF SUPPORT
    if signature[4].split(",")[0] == '*':
        pkt.payload.window = RandShort()
    elif signature[4].split(",")[0].isdigit():
        pkt.payload.window = int(signature[4].split(",")[0])
    elif (signature[4].split(",")[0]).find("*") or signature[4].find("%"):
        raise TypeError("Coefficient window size not implemented: %s" % signature[4])

    # Quirks description :
    # df: don't fragment bit is set in the IP header
    # id+: df bit is set and IP identification field is non zero
    # id-: df bit is not set and IP identification is zero
    # ecn: explicit congestion flag is set
    # 0+: reserved ("must be zero") field in IP header is not actually zero
    # flow: flow label in IPv6 header is non-zero
    # seq-: sequence number is zero
    # ack+: ACK field is non-zero but ACK flag is not set
    # ack-: ACK field is zero but ACK flag is set
    # uptr+: URG field is non-zero but URG flag not set
    # urgf+: URG flag is set
    # pushf+: PUSH flag is set
    # ts1-: timestamp 1 is zero
    # ts2+: timestamp 2 is non-zero in a SYN packet
    # opt+: non-zero data in options segment
    # exws: excessive window scaling factor (window scale greater than 14)
    # bad: malformed TCP options
    # flags: can be FSRPAUECN  ip DF MF evil
    # Quirks
    if signature[6] != '.':
        for qq in signature[6].split(","):
            if qq == 'df':
                pkt.flags = 'DF'
            elif qq == 'id+':
                pkt.flags = 'DF'
                pkt.id = RandShort()
            elif qq == 'id-':
                pkt.flags = 0
                pkt.id = 0
            elif qq == 'ecn':
                pkt.flags = 'evil'
            elif qq == '0+':
                pkt.flags = 1
            elif qq == 'flow':
                if signature[0] == '6':
                    pkt.getlayer(IPv6).fl = 1
                    pass
                else:
                    raise TypeError("flow set but IPv4 packet")
            elif qq == 'seq-':
                pkt.payload.seq = 0
            elif qq == 'ack+':
                pkt.payload.ack = RandInt()
            elif qq == 'ack-':
                pkt.payload.ack = 0
                pkt.payload.flags += 'A'
            elif qq == 'uptr+':
                pkt.payload.urgptr = RandShort()
            elif qq == 'urgf+':
                pkt.payload.flags += 'U'
            elif qq == 'pushf+':
                pkt.payload.flags += 'P'
            elif qq == 'opt+':
                if signature[5] == '.':
                    raise TypeError("Asked for non zero data in tcp option but no options specified in sign")
            elif qq == 'bad':
                load = RandString(random.randint(1, 10))
                pkt.payload.option = load

    while pkt.underlayer:
        pkt = pkt.underlayer
    return pkt
