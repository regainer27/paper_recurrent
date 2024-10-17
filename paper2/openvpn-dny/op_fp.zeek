@load base/frameworks/notice


# Opcode-based Fingerprinting: Initialize some variables to store opcode data
global opcode_data: vector of string;

event zeek_init() {
    #print "Opcode-based Fingerprinting started...";
}

# Function to fingerprint based on opcode sequence
function fingerprint_opcode() {
    local CR: string = opcode_data[0];
    local SR: string = opcode_data[1];
    #print CR, SR;
    local op_set: set[string] = set(CR, SR);
    local op_reset: set[string] = set(CR, SR);
    local i = +2;
    #print |opcode_data|;
    while ( i < 100 && i < |opcode_data|) {
        if ( opcode_data[i] in op_reset && |op_set| >= 4)
            break;
        add op_set[opcode_data[i]];
        i += 1;
    }
    #print op_set;
    if ( i == 100 && |op_set| >= 4 && |op_set| <= 10 ) {
        NOTICE([$note=Weird::Activity, $msg="OpenVPN traffic detected via Opcode-based Fingerprinting", $sub="OpenVPN Detection"]);
        print "OpenVPN traffic";
    }
}

# for all udp packets, extract opcodes  
redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;

event udp_contents(u: connection, is_orig: bool, contents: string) {
    if ( |contents| > 0 ) {
        local opcode: string = fmt("%s", contents[0]);
        #print opcode;
	opcode_data += opcode;
    }
}

# Handle each TCP packet and extract opcodes  
event tcp_packet(c: connection, is_orig: bool, flags: string , seq: count, ack: count, len: count, payload: string) {
    if ( len > 0 && |payload| > 0 ) {
        local opcode: string = fmt("%s", payload[2]);
        #print opcode;
	opcode_data += opcode;
    }

}

event zeek_done() {
    #print opcode_data;
    # Call the fingerprinting function
    fingerprint_opcode();
    #print "Opcode-based Fingerprinting completed.";
}
