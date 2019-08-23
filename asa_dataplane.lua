-- This software is licensed under the GPL v2 license, as published by the FSF
-- http://www.gnu.org/licenses/gpl-2.0.txt

-- declare our protocol
asa_dataplane_proto = Proto("asa_dataplane","Cisco ASA Dataplane Protocol");

-- create a function to dissect it
function asa_dataplane_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "asa_dataplane"

    local subtree = nil
	if buffer:len() < 16 then
		subtree = tree:add(asa_dataplane_proto,nil,"Error: Malformed packet - not enough data")
		return
	end
	
    local length = buffer(2,1):uint()
	
    if length == 4 then
    	subtree = tree:add(asa_dataplane_proto,buffer(0,16),"Cisco ASA Dataplane Protocol")
    elseif length == 5 then
    	subtree = tree:add(asa_dataplane_proto,buffer(0,20),"Cisco ASA Dataplane Protocol")
	else
		subtree = tree:add(asa_dataplane_proto,nil,"Error: Malformed packet - incorrect length")
		return
    end
    subtree:add(buffer(0,1),"Byte      1; Version: " .. buffer(0,1))
    subtree:add(buffer(1,1),"Byte      2; Unknown meaning - Observed values: 0x00 and 0x02. Actual value: 0x" .. buffer(1,1))
    if length == 4 then
    	subtree:add(buffer(2,1),"Byte      3; Header Length: 16 bytes")
    elseif length == 5 then
    	subtree:add(buffer(2,1),"Byte      3; Header Length: 20 bytes")
    end
    subtree:add(buffer(3,1),"Byte      4; Unknown meaning - Observed values: 0x00. Actual value: 0x" .. buffer(3,1))
    subtree:add(buffer(4,4),"Bytes   5-8; Connection ID: " .. buffer(4,4))
    subtree:add(buffer(8,2),"Bytes  9-10; Unknown meaning - Observed values: 0x00 and 0x0080. Actual value: 0x" .. buffer(8,2))
    subtree:add(buffer(10,1),"Byte     11; Unknown meaning - Observed values: 0x00 and 0x80. Actual value: 0x" .. buffer(10,1))
    subtree:add(buffer(11,3),"Bytes 12-14; Unknown meaning - Actual value: " .. buffer(11,3))
    subtree:add(buffer(14,1),"Byte     15; Unknown meaning - Observed values: 0x00 and 0x80. Actual value: 0x" .. buffer(14,1))
    subtree:add(buffer(15,1),"Byte     16; Unknown meaning - Observed values: 0x04 and 0x08. Actual value: 0x" .. buffer(15,1))
    if length == 5 then
    	subtree = subtree:add(buffer(16,4),"Bytes 17-20: Unknown meaning - Observed values: 0x00. Actual value: 0x".. buffer(16,4))
    end
    
    local eth_dis = Dissector.get("eth")
    if length == 4 then
    	eth_dis:call(buffer(16):tvb(), pinfo, tree)
    elseif length == 5 then
    	eth_dis:call(buffer(20):tvb(), pinfo, tree)
    end
end
-- register our new protocol
local ethertype_table = DissectorTable.get("eth_maybefcs")
ethertype_table:add(0x855e,asa_dataplane_proto)




