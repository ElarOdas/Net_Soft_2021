/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<9> LAP_PORT = 511;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<9> LA_port;
    bit<14> flow_hash;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

#define REGISTER_SIZE 1
register<bit<9>>(REGISTER_SIZE) r;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/



control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action hashPortTCP(bit<16> hash_base, bit<16> hash_count) {
        hash(
            meta.flow_hash,
            HashAlgorithm.crc16,
            hash_base,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort
            },
            hash_count
            );
        standard_metadata.egress_spec = (bit<9>) meta.flow_hash;
    }
    action reverseHashPortTCP(bit<16> hash_base, bit<16> hash_count){
        hash(
            meta.flow_hash,
            HashAlgorithm.crc16,
            hash_base,
            {
                hdr.ipv4.dstAddr,
                hdr.ipv4.srcAddr,
                hdr.ipv4.protocol,
                hdr.tcp.dstPort,
                hdr.tcp.srcPort
            },
            hash_count
            );
        standard_metadata.egress_spec = (bit<9>) meta.flow_hash;
    }
    action hashPortUDP(bit<16> hash_base, bit<16> hash_count) {
        hash(
            meta.flow_hash,
            HashAlgorithm.crc16,
            hash_base,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                hdr.udp.srcPort,
                hdr.udp.dstPort
            },
            hash_count
            );
        standard_metadata.egress_spec = (bit<9>) meta.flow_hash;
    }
    action reverseHashPortUDP(bit<16> hash_base, bit<16> hash_count){
        hash(
            meta.flow_hash,
            HashAlgorithm.crc16,
            hash_base,
            {
                hdr.ipv4.dstAddr,
                hdr.ipv4.srcAddr,
                hdr.ipv4.protocol,
                hdr.udp.dstPort,
                hdr.udp.srcPort
            },
            hash_count
            );
        standard_metadata.egress_spec = (bit<9>) meta.flow_hash;
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table flowBasedAgg {
        key = {
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            hashPortTCP;
            hashPortUDP;
            reverseHashPortTCP;
            reverseHashPortUDP;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
       		ipv4_lpm.apply();
            if (standard_metadata.egress_spec == LAP_PORT){
                r.read(meta.LA_port,0);
                if (meta.LA_port == 2) {
                    r.write(0,3);
                    standard_metadata.egress_spec = meta.LA_port;
                }
                else{
                    r.write(0,2);
                    standard_metadata.egress_spec = meta.LA_port;
                }
            }

            if (hdr.tcp.isValid() || hdr.udp.isValid()){
                flowBasedAgg.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    /*action changeLAP_PORT(){
        standard_metadata.egress_spec = meta.LA_port;
    }
    table ipv4_LAP{
        key =  {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            changeLAP_PORT;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {

        if (standard_metadata.egress_spec == LAP_PORT){
            r.read(meta.LA_port,0);
            //ipv4_LAP.apply();
            if (meta.LA_port == 2) {
                r.write(0,3);
            }
            else{
                r.write(0,2);
            }
        }
     }*/
     apply{}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;