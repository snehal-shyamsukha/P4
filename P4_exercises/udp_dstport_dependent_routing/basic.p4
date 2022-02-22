/* -*- P4_16 -*- */
/* This line includes definitions of packet_in and packet_out */
#include <core.p4>
/* includes architecture of V1 model Switch */
#include <v1model.p4>
/* This declaration tells the parser that it is an ipv4 packet when it parses the ethernet frame*/
const bit<16> TYPE_IPV4 = 0x800;
/*defining protocols icmp as 0x01 and udp as 0x11*/
const bit<8> TYPE_UDP = 0x11;
/* defining ip addresses of h1 h2 and h3 in hexadecimal format */
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
/* defines macAddr_t is of 48 bit ,ip4Addr_t as 32 bit and egressSpec_t as 9 bit */
/* instead of using bit field in the program we can use egressSpec_t,macAddr_t,ip4Addr_t wherever it is */
/* required in the program*/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* Defines standard Ethernet header which contains source and destination mac address in its frame*/
/*dstAddr and srcAddr are of 48 bits and ethertype of 16 bit field */
/* ether type defines which type of protocol is encapsulated in the payload of ethernet frame*/
/* ether type can include IPv6,IPX,ARP etc protocols so type field defines protocol present in the packet*/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
/* standard ipv4 header definition */
/*different fields present in the ipv4 header */
/* version(4 bits) indicates ipv4,ihl(4 bits) ip header length*/
/*diffserv(TOS-8bits) type of services-low delay,throughput,reliability,totalLen(16 bits) datagram length*/
/*identification(16 bits) unique packet id given to fragments of a single ip packet*/
/*flags(3 bits) refer to kind of fragmentation,ttl(8bits) datagram's lifetime(time to live)*/
/*protocol(8 bits) TCP,UDP, srcAddr,dstAddr(32bits) indicates source and destination ip addresses*/
/* hdrChecksum(16bits) check for errors in the datagram header*/

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

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}


struct metadata {
    /* empty */
}
/* unordered collection of different headers(ethernet and ipv4) that can be used */
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
/* defining interface for parser*/
/*It reads input from the incoming packet packet_in, it extracts headers and data from the packet*/
/* inout indicates the direction of the dataflow */
/* it has predefined states:start,accept,reject */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
/* starts packet processing*/
    state start {
        /* goes to parse ethernet header */
        transition parse_ethernet; 
    }
/* starts parsing ethernet header*/
/* after extracting ethernet header it checks for the ethernet type field if it is 0x800 it parses ipv4*/
/* else it accepts the packet*/

  state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
            transition select(hdr.ipv4.protocol){
                TYPE_UDP: parse_udp;
                default: accept;

            }
        }
    state parse_udp{
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
/*Match action processing based on table entries is done here */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
/* action to drop metadata */    
    action drop() {
        mark_to_drop(standard_metadata);
    }
/* Basic ipv4 forwarding */
/* updates the source and the destination address based on the match action table*/
/* the srcAddr of the next switch is set to the dstAddr of the present switch*/
/*it also updates the next hop address(dstAddr) comes from the lpm algorithm*/
/* updates the the port to which the packet has to be sent(egress_spec)*/
/* decrements the ttl by 1 each time it forwards the packet in network layer */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec=port;
        hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr=dstAddr;
        hdr.ipv4.ttl=hdr.ipv4.ttl-1;
    }
/*match action table processing using longest prefix match algorithm to find the next hop address*/
/*hdr.ipv4.dstAddr is the match field and lpm is algorithm*/
    table ipv4_lpm1 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
/* actions to be taken for packet forwarding after finding next dstAddr*/
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
/*size indicates no of table entries */
        size = 1024;
/* if no table entry matches it drops the packet */
        default_action = NoAction();
    }

   table ipv4_lpm2 {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
/* actions to be taken for packet forwarding after finding next dstAddr*/
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
/*size indicates no of table entries */
        size = 1024;
/* if no table entry matches it drops the packet */
        default_action = NoAction();
    }
    
    apply {
  if(hdr.udp.dst_port==5000)
        {           ipv4_lpm1.apply();
        }
     else   if(hdr.udp.dst_port==6000)
        {
           ipv4_lpm2.apply();
        
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
/* deparser puts back the ethernet and ipv4 headers to the outgoing packet*/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
/* instantiate different functions in processing*/
V1Switch(
/* header extraction */
MyParser(),
/* validates the packet for errors*/
MyVerifyChecksum(),
/* match action processing */
MyIngress(),
MyEgress(),
MyComputeChecksum(),
/* emits the ethernet and ip headers in the outgoing packet */
MyDeparser()
) main;
