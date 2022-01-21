# Pkt_gen
###### tags: `git_log`

Practice Python project.

Using Scapy to implement a packet generator as an experiment tool.

### Execute command

```
cd pkt_gen
python3 src/pkt_gen.py [-h]
```

### parameter

optional arguments:
    -h, --help                 show this help message and exit
    --tcp, -t                  TCP
    --udp, -u                  UDP
    --conn                     Establish connection
    --port PORT, -p PORT       port number
    --sip SIP, -s SIP          source ip
    --dip DIP, -d DIP          destionation ip
    --count COUNT, -c COUNT    packet count
    --syn                      SYN
    --ack                      ACK
