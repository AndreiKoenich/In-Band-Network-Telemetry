/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_INT_PAI = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

const bit<32> MTU = 1500;
const bit<32> TAMANHO_INT_PAI_BYTES = 9;
const bit<32> TAMANHO_INT_FILHO_BYTES = 13;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<32> identifier;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header int_pai_t {
    bit<32> Tamanho_Filho;
    bit<32> Quantidade_Filhos;
    bit <1> MTU_overflow;
    bit <7> padding; // O tamanho do cabecalho em bits deve ser multiplo de 8
}

header int_filho_t {
  bit<32> ID_Switch;
  bit<9> Porta_Entrada;
  bit<9> Porta_Saida;
  bit<48> Timestamp;
  bit<6> padding; // O tamanho do cabecalho em bits deve ser multiplo de 8
}

struct metadata {
    bit<48> ingress_timestamp;
    bit<32> packet_length;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    tcp_t         tcp;
    int_pai_t     int_pai;
    int_filho_t   int_filho;
}

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
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_tcp;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT_PAI: parse_pai;
            TYPE_IPV4: accept;
            default: accept;
        }
    }

    state parse_pai {
        packet.extract(hdr.int_pai);
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
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = TYPE_INT_PAI;
        hdr.ipv4.ttl = hdr.ipv4.ttl-1;
    }

    action add_int_pai() {
        hdr.int_pai.setValid();
        hdr.int_pai.Tamanho_Filho = 0;
        hdr.int_pai.Quantidade_Filhos = 0;
        hdr.int_pai.MTU_overflow = 0;
    }

    action update_int_pai() {
        hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos+1;
        hdr.int_pai.Tamanho_Filho = hdr.int_pai.Quantidade_Filhos*TAMANHO_INT_FILHO_BYTES;
    }

    action add_int_filho(identifier id) {
        hdr.int_filho.setValid();
        hdr.int_filho.ID_Switch = id; // Configurado externamente
        hdr.int_filho.Porta_Entrada = standard_metadata.ingress_port;
        hdr.int_filho.Porta_Saida = standard_metadata.egress_spec;
        hdr.int_filho.Timestamp = standard_metadata.ingress_global_timestamp;
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
        default_action = drop();
    }

    table new_int_filho {
        actions = {
          add_int_filho;
          drop;
        }
        default_action = drop();
    }

    apply {

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if (!(hdr.int_pai.isValid())) {
            add_int_pai();
        }

        if (hdr.int_pai.MTU_overflow == 0) {
            if ((standard_metadata.packet_length+TAMANHO_INT_FILHO_BYTES) <= MTU) {
                new_int_filho.apply();
                update_int_pai();
            }
            else {
                hdr.int_pai.MTU_overflow = 1;
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
    apply {  }
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
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filho);
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
