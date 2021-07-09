#!/usr/bin/env python2
import argparse
import os
from time import sleep

import switch_control


def main(p4info_file_path, bmv2_file_path):
    switches = []

    protection = True

    try:
        switches.append(switch_control.SwitchControl("s1", '127.0.0.1:50051', 0, p4info_file_path, bmv2_file_path))
        switches.append(switch_control.SwitchControl("s2", '127.0.0.1:50052', 1, p4info_file_path, bmv2_file_path))
        switches.append(switch_control.SwitchControl("s3", '127.0.0.1:50053', 2, p4info_file_path, bmv2_file_path))

        # switch 1
        switches[0].writeIPv4LPMrule("10.0.1.1", 32, "00:00:00:00:01:01", 1)
        switches[0].writeDeTunnelrule("10.1.0.1")

        # switch 2
        switches[1].writeIPv4LPMrule("10.0.1.1", 32, "00:00:00:01:01:00", 1)
        switches[1].writeIPv4LPMrule("10.1.0.1", 32, "00:00:00:01:01:00", 1)
        switches[1].writeIPv4LPMrule("10.0.3.2", 32, "00:00:00:03:03:00", 2)
        switches[1].writeIPv4LPMrule("10.3.0.3", 32, "00:00:00:03:03:00", 2)

        #switch 3
        switches[2].writeIPv4LPMrule("10.0.3.2", 32, "00:00:00:00:03:02", 1)
        switches[2].writeDeTunnelrule("10.3.0.3")

        # protection enabled
        if protection:
            # switch 1
            switches[0].writeTunnelrule("10.0.3.2", 32, "10.3.0.3", "00:00:00:03:03:00", 3,1)
            switches[0].writeCloneRule("10.3.0.3","00:00:00:02:02:00",2)
            #switch 3
            switches[2].writeTunnelrule("10.0.1.1", 32, "10.1.0.1" , "00:00:00:01:01:00", 2,1)
            switches[2].writeCloneRule("10.1.0.1","00:00:00:02:02:00",3)
        else:
            # switch 1
            switches[0].writeTunnelrule("10.0.3.2", 32, "10.3.0.3", "00:00:00:03:03:00", 3,0)

            #switch 3
            switches[2].writeTunnelrule("10.0.1.1", 32, "10.1.0.1" , "00:00:00:01:01:00", 2,0)

        while True:
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
