# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
import scapy
import sys
import os
import threading

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper

class SwitchControl:
    def __init__(self, name, address, device_id, p4info_file_path, bmv2_file_path):
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.packet_in_thread = None

        # Create a switch connection object
        # this is backed by a P4Runtime gRPC connection.
        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=name,
            address=address,
            device_id=device_id)

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        self.switch.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        self.switch.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
            bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on %s" % self.switch.name

    def teardown(self):
        # Stop the 'packet in' thread
        self.switch.ShutdownAllSwitchConnections()

    def response_callback(self, switch, response):
        # Check if the message received from the switch contains a payload

        if response.packet.payload:
            self.packet_in_callback(switch, response.packet.payload)
        else:
            pass

    def packet_in_callback(self, switch, packet_in):

        print "Received packet in from switch %s" % self.switch.name
        print packet_in

    def transform_ipv6(self,ipv6_address):
        a = bytes(bytearray.fromhex(ipv6_address))
        return a


    def writeIPv4LPMrule(self, dstAddr, dstPrefix, dstMac, port):
        # Assemble the table entry
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dstAddr, dstPrefix)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dstMac,
                "port": port
            })

        # Write the table entry
        self.switch.WriteTableEntry(table_entry)
        print "Installed IPv4 LPM rule on switch %s" % self.switch.name

    def writeIPv6LPMrule(self, dstAddr, dstPrefix, dstMac, port):
        dstAddr = bytes(bytearray.fromhex(dstAddr))
        # Assemble the table entry
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv6_lpm",
            match_fields={
                "hdr.ipv6.dstAddr": (dstAddr, dstPrefix)
            },
            action_name="MyIngress.ipv6_forward",
            action_params={
                "dstAddr": dstMac,
                "port": port
            })

        # Write the table entry
        self.switch.WriteTableEntry(table_entry)
        print "Installed IPv4 LPM rule on switch %s" % self.switch.name


    def writeTunnelrule(self, dstAddr, dstPrefix, dstAddrSwitch, dstMac, port):
        # Assemble the table entry
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv6_lpm",
            match_fields={
                "hdr.ipv6.dstAddr": (self.transform_ipv6(dstAddr), dstPrefix)
            },
            action_name="MyIngress.tunnel",
            action_params={
                "dstAddrSwitch" : dstAddrSwitch,
                "dstAddr": dstMac,
                "port": port,
            })

        # Write the table entry
        self.switch.WriteTableEntry(table_entry)
        print "Installed Tunnel rule on switch %s" % self.switch.name

    def writeDeTunnelrule(self, dstAddr, dstPrefix):
        # Assemble the table entry
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dstAddr, dstPrefix)
            },
            action_name="MyIngress.detunnel",
            action_params={
            })
        # Write the table entry
        self.switch.WriteTableEntry(table_entry)
        print "Installed DeTunnel rule on switch %s" % self.switch.name

    def getCounterPackets(self, counter_name, index):
        """Returns the value of a packet counter at a specific index

        :param counter_name: name of the counter
        :param index: index of the counter field
        :return: number. packet count
        """
        for response in self.switch.ReadCounters(self.p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry

                # only return first
                return counter.data.packet_count

    def getCounterBytes(self, counter_name, index):
        """Returns the value of a byte counter at a specific index

        :param counter_name: name of the counter
        :param index: index of the counter field
        :return: number. byte count
        """
        for response in self.switch.ReadCounters(self.p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry

                # only return first
                return counter.data.byte_count
