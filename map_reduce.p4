#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
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
    bit<16> length;
    bit<16> checksum;
}

struct metadata_t {
    bit<8> mapper_id; // To store the selected mapper id
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser Parser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) 
{
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType)
        {
            0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) 
        {
            6: parse_tcp;
            17: parse_udp;
            default accept;
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

// Registers for dynamic mapper handling
register<bit<8>>(8) mapper_weights;     // Max 8 mappers, weights stored here
register<bit<8>>(8) mapper_counters;    // Max 8 mappers, counters stored here
register<bit<8>>(1) current_mapper_idx; // Current mapper index
register<bit<8>>(1) num_mappers;        // Current number of active mappers

// Weighted Round Robin logic for mapper selection
action select_mapper(inout metadata_t meta) {
    bit<8> mapper_idx = current_mapper_idx.read(0);

    // Read and decrement the counter for the selected mapper
    bit<8> remaining_weight = mapper_counters.read(mapper_idx);
    remaining_weight = remaining_weight - 1;
    mapper_counters.write(mapper_idx, remaining_weight);

    // Read the current number of active mappers
    bit<8> active_mappers = num_mappers.read(0); // Will be dynamically updated by the control plane

    // If the counter reaches zero, move to the next mapper
    if (remaining_weight == 0) {
        mapper_idx = (mapper_idx + 1) % active_mappers; // Loop over active mappers
        current_mapper_idx.write(0, mapper_idx);
    }

    // Update metadata with the selected mapper ID
    meta.mapper_id = mapper_idx;
}

// Action to reset counters when all mappers' counters are 0
action reset_counters() {
    bit<8> active_mappers = num_mappers.read(0);
    for (bit<8> i = 0; i < active_mappers; i++) {
        mapper_counters.write(i, mapper_weights.read(i));
    }
}

control Ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    table wrr_mapper_table {
        actions = { select_mapper; }
        size = 1;
        default_action = select_mapper();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            wrr_mapper_table.apply();
        }

        // Check if all mappers' counters are zero and reset if necessary
        bit<8> active_mappers = num_mappers.read(0); // Dynamically updated
        bit<8> all_counters_zero = 1;

        for (bit<8> i = 0; i < active_mappers; i++) {
            if (mapper_counters.read(i) != 0) {
                all_counters_zero = 0;
                break;
            }
        }

        if (all_counters_zero == 1) {
            // Reset all counters to their original weights
            for (bit<8> i = 0; i < active_mappers; i++) {
                mapper_counters.write(i, mapper_weights.read(i));
            }
        }
    }
    //TODO: call the resetCounter() fucntion with num_activemappers
}

control Egress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action set_egress_port(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    action drop_packet() {
        standard_metadata.egress_spec = 0;
    }

    table mapper_egress_table {
        key = {
            meta.mapper_id : exact;
        }
        actions = {
            set_egress_port;
            drop_packet;
        }
        size = 8; // Adjust based on the number of active mappers
    }

    apply {
        if (hdr.ipv4.isValid()) {
            mapper_egress_table.apply();
        }
    }
}

control Deparser() {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    Parser(),
    Ingress(),
    Egress(),
    Deparser()
) main;
