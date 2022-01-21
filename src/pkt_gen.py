from scapy.all import * 
import random
import argparse

load_layer("http")

protocol = {'TCP': 6,
            'UDP':17
           }

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tcp','-t', action="store_true", help='TCP')
    parser.add_argument('--udp','-u', action="store_true", help='UDP')
    parser.add_argument('--conn', action="store_true", help='Establish connection')
    parser.add_argument('--port','-p', type=int, help='port number')
    parser.add_argument('--sip','-s', type=str, help='source ip')
    parser.add_argument('--dip','-d', type=str, help='destionation ip')
    parser.add_argument('--syn', action="store_true", help='SYN')
    parser.add_argument('--ack', action="store_true", help='ACK')
    parser.add_argument('--count','-c', type=int, help='packet count')
    return parser.parse_args()

def pkt_send():
    pkt = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(dport=8080)
    res = sr1(pkt)

    print(res.getlayer("TCP").flags)

    if res.haslayer("TCP") and res.getlayer("TCP").flags == 0x12:
        pkt = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(dport=8080, flags='A')
        pkt.getlayer("TCP").seq = res.getlayer("TCP").ack
        pkt.getlayer("TCP").ack = res.getlayer("TCP").seq + 1 
        send(pkt)

        #pkt = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(dport=8080, flags='PA') / HTTPRequest()
        pkt = pkt / ('Hello You!\n')
        #pkt = pkt / HTTPRequest()
        res = send(pkt)

        pkt = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(dport=8080, flags='FA')
        res = send(pkt)
        #res.show()

def _pkt_construct(sip: str, dip:str, port:int, proto:str, count:int, conn:bool):

   sport = random.randint(10, 65535)
   pkt = IP(src=sip, dst=dip)/TCP(sport=sport, dport=port)
   res = sr1(pkt)

   print(res.getlayer("TCP").flags)

   if res.haslayer("TCP") and res.getlayer("TCP").flags == 0x12:
       pkt = IP(src=sip, dst=dip)/TCP(sport=sport,dport=port, flags='A')
       pkt.getlayer("TCP").seq = res.getlayer("TCP").ack
       pkt.getlayer("TCP").ack = res.getlayer("TCP").seq + 1
       send(pkt)

       #pkt = pkt / HTTPRequest()
       pkt = pkt / ('Hello You!\n')
       res = send(pkt)

       pkt = IP(src=sip, dst=dip)/TCP(sport=sport, dport=port, flags='FA')
       res = send(pkt)
       #res.show() 
def conn_send(sip: str, dip:str, sport:int, port:int):
    #Send SYN packet
    pkt = IP(src=sip, dst=dip)/TCP(sport=sport, dport=port)
    res = sr1(pkt)

    # Receive SA packet
    if res.haslayer("TCP") and res.getlayer("TCP").flags == 0x12:
        pkt = IP(src=sip, dst=dip)/TCP(sport=sport,dport=port, flags='A')
        pkt.getlayer("TCP").seq = res.getlayer("TCP").ack
        pkt.getlayer("TCP").ack = res.getlayer("TCP").seq + 1
        # Send ACK packet
        send(pkt)

       #pkt = pkt / HTTPRequest()
    # PSH DATA
    pkt = pkt / ('Hello You!\n')
    res = send(pkt)

    # FA packet
    pkt = IP(src=sip, dst=dip)/TCP(sport=sport, dport=port, flags='FA')
    res = send(pkt)

def pkt_construct(sip: str, dip:str, port:int, proto:str, count:int, conn:bool, flag:str):

    sport = random.randint(10, 65535)
    pkt = IP(src=sip, dst=dip)

    if (proto == 'TCP'):
        if (flag == 'S' or flag == 'A'):
            pkt = pkt/TCP(sport=sport,dport=port, flags=flag)
        elif (conn == True):
            conn_send(sip, dip, sport, port)
            return
    elif (proto == 'UDP'):
        pkt = IP(src=sip, dst=dip)/UDP(sport=sport,dport=port) / ('Hello You! UDP\n')

    res = send(pkt, count=count)

if __name__ == '__main__':
    args = parse_args()
    print("sip:{}, dip:{} ".format(args.sip, args.dip))
    proto=''
    conn=False
    flag = ''
    if (args.tcp):
        proto = 'TCP'
    elif (args.udp):
        proto = 'UDP'

    if (args.conn):
        conn=True

    if (args.syn):
        flag = 'S'
    elif (args.ack):
        flag = 'A'

    pkt_construct(args.sip, args.dip, args.port, proto, args.count, conn, flag)
    #pkt_send()
