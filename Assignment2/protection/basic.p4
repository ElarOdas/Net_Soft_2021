/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<32> INSTANCE_TYPE_EGRESS_CLONE  = 2;
#define IS_E2E_CLONE(standard_metadata) (standard_metadata.instance_type == INSTANCE_TYPE_EGRESS_CLONE)
const bit<32> E2E_CLONE_SESSION_ID = 3;

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

header tunnel_t {
    bit<8> protocol;
    bit<16> sequence;
}

struct metadata {
    bit<16> incSeq;
    bit<16> outSeq;
    bit<2> protection;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_t       inner_ipv4;
    tunnel_t     tunnel;
}

#define REGISTER_SIZE 2
//index 0 is outSeq and 1 is incSeq
register<bit<16>>(REGISTER_SIZE) sequence;

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
            61: parse_tunnel;
            default: accept;
        }
    }
    state parse_tunnel {
        packet.extract(hdr.tunnel);
        packet.extract(hdr.inner_ipv4);
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
    action tunnel(ip4Addr_t dstAddrSwitch,macAddr_t dstAddr, egressSpec_t port, bit<2> protection) {
        //create Tunnel
        hdr.tunnel.setValid();
        sequence.read(meta.outSeq,0);
        hdr.tunnel.protocol = 4;
        meta.outSeq = meta.outSeq + 1;
        hdr.tunnel.sequence = meta.outSeq;
        sequence.write(0,meta.outSeq);

        //create Ipv4
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.ipv4.dstAddr = dstAddrSwitch;
        hdr.ipv4.protocol = 61;

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        meta.protection = protection;
    }

    action detunnel() {
        sequence.write(1, meta.incSeq+1);
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.tunnel.setInvalid();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            tunnel;
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table detunnel_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            detunnel;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.tunnel.isValid()){
                sequence.read(meta.incSeq,1);
                if(hdr.tunnel.sequence == meta.incSeq + 1){
                    detunnel_exact.apply();
                }
                    ipv4_lpm.apply();

            }
            else{
                ipv4_lpm.apply();
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


    action cloneProtection(macAddr_t dstAddr, egressSpec_t port){
                hdr.ethernet.dstAddr = dstAddr;
                standard_metadata.egress_spec = port;
    }

    table oneplusone{
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            cloneProtection;
            NoAction;
        }
        size = 1024;
    }
    apply {
        if(hdr.ipv4.isValid()){
            if (IS_E2E_CLONE(standard_metadata)){
                oneplusone.apply();
            }
            else {
                if (meta.protection == 1){
                    clone(CloneType.E2E, E2E_CLONE_SESSION_ID);
                }
            }
        }

     }
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
    update_checksum(
	    hdr.inner_ipv4.isValid(),
            { hdr.inner_ipv4.version,
	          hdr.inner_ipv4.ihl,
              hdr.inner_ipv4.diffserv,
              hdr.inner_ipv4.totalLen,
              hdr.inner_ipv4.identification,
              hdr.inner_ipv4.flags,
              hdr.inner_ipv4.fragOffset,
              hdr.inner_ipv4.ttl,
              hdr.inner_ipv4.protocol,
              hdr.inner_ipv4.srcAddr,
              hdr.inner_ipv4.dstAddr },
            hdr.inner_ipv4.hdrChecksum,
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
        packet.emit(hdr.tunnel);
        packet.emit(hdr.inner_ipv4);
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
