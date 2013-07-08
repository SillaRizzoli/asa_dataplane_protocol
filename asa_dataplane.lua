-- This software is licensed under the GPL v2 license, as published by the FSF
-- http://www.gnu.org/licenses/gpl-2.0.txt

-- declare our protocol
asa_dataplane_proto = Proto("asa_dataplane","Cisco ASA Dataplane Protocol");

-- create a function to dissect it
function asa_dataplane_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "asa_dataplane"

    local subtree = nil
    local length = buffer(2,1):uint()
--  print(length)
    if length == 4 then
    	subtree = tree:add(asa_dataplane_proto,buffer(0,16),"Cisco ASA Dataplane Protocol")
    elseif length == 5 then
    	subtree = tree:add(asa_dataplane_proto,buffer(0,20),"Cisco ASA Dataplane Protocol")
    end
    subtree:add(buffer(0,1),"Byte      1; Version: " .. buffer(0,1))
    subtree:add(buffer(1,1),"Byte      2; Unknown meaning - Observed values: 0 and 2. Actual value: " .. buffer(1,1))
    if length == 4 then
    	subtree:add(buffer(2,1),"Byte      3; Header Length: 16 bytes")
    elseif length == 5 then
    	subtree:add(buffer(2,1),"Byte      3; Header Length: 20 bytes")
    end
    subtree:add(buffer(3,1),"Byte      4; Unknown meaning - Observed values: 0. Actual value: " .. buffer(3,1))
    subtree:add(buffer(4,4),"Bytes   5-8; Connection ID: " .. buffer(4,4))
    subtree:add(buffer(8,2),"Bytes  9-10; Unknown meaning - Observed values: 0x00 and 0x0080. Actual value: " .. buffer(8,2))
    subtree:add(buffer(10,1),"Byte     11; Unknown meaning - Observed values: 0 and 128. Actual value: " .. buffer(10,1))
    subtree:add(buffer(11,3),"Bytes 12-14; Unknown meaning - Actual value: " .. buffer(11,3))
    subtree:add(buffer(14,1),"Byte     15; Unknown meaning - Observed values: 0 and 128. Actual value: " .. buffer(14,1))
    subtree:add(buffer(15,1),"Byte     16; Unknown meaning - Observed values: 4 and 8. Actual value: " .. buffer(15,1))
    if length == 5 then
    	subtree = subtree:add(buffer(16,4),"Bytes 17-20: Unknown meaning - Observed values: 0. Actual value: ".. buffer(16,4))
    end
    
    local eth_dis = Dissector.get("eth")
    if length == 4 then
    	eth_dis:call(buffer(16):tvb(), pinfo, tree)
    elseif length == 5 then
    	eth_dis:call(buffer(20):tvb(), pinfo, tree)
    end
end
-- register our new protocol
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x855e,asa_dataplane_proto)




