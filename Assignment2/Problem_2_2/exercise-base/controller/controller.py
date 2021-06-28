#!/usr/bin/env python2
import argparse
import os
from time import sleep

import switch_control

LA_port = 511
def main(p4info_file_path, bmv2_file_path):
    switches = []

    try:
        switches.append(switch_control.SwitchControl("s1", '127.0.0.1:50051', 0, p4info_file_path, bmv2_file_path))
        switches.append(switch_control.SwitchControl("s2", '127.0.0.1:50052', 1, p4info_file_path, bmv2_file_path))


        # switch 1
        switches[0].writeIPv4LPMrule("10.0.1.1", 32, "00:00:00:00:01:01", 1)
        switches[0].writeIPv4LPMrule("10.0.2.2", 32, "00:00:00:02:02:00",LA_port)
        switches[0].writeFlowAggregationRule("10.0.2.2", 32, 6, "MyIngress.hashPortTCP")
        switches[0].writeFlowAggregationRule("10.0.2.2", 32, 17, "MyIngress.hashPortUDP")

        # switch 2
        switches[1].writeIPv4LPMrule("10.0.1.1", 32, "00:00:00:01:01:00",LA_port)
        switches[1].writeFlowAggregationRule("10.0.1.1", 32, 6, "MyIngress.reverseHashPortTCP")
        switches[1].writeFlowAggregationRule("10.0.1.1", 32, 17, "MyIngress.reverseHashPortUDP")
        switches[1].writeIPv4LPMrule("10.0.2.2", 32, "00:00:00:00:02:02", 1)


        while True:
            for switch_id in range(2):
                for port_id in range(1,4):
                    print("Switch {switch} Port {port}: Sent {bytes} Bytes, {packets} Packets".format(switch= switch_id +1, port = port_id, bytes = switches[switch_id].getCounterBytes("sent_counts",port_id), packets = switches[switch_id].getCounterPackets("sent_counts",port_id)))
                    print("Switch {switch} Port {port}: Received {bytes} Bytes, {packets} Packets".format(switch= switch_id +1, port = port_id, bytes = switches[switch_id].getCounterBytes("rec_counts",port_id), packets = switches[switch_id].getCounterPackets("rec_counts",port_id)))
            sleep(2)

    except KeyboardInterrupt:
        print " Shutting down."

    for switch in switches:
        switch.teardown()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
