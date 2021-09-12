oscar_protocol = Proto("OSCAR", "AIM/ICQ OSCAR protocol")

flap_proto_ch = ProtoField.uint8("oscar_protocol.proto_ch", "Channel", base.DEC)
flap_sequence_num = ProtoField.uint8("oscar_protocol.sequence_num", "Datagram Sequence #", base.DEC);
flap_payload_length = ProtoField.uint8("oscar_protocol.payload_length", "Payload Length", base.DEC)

snac_service = ProtoField.uint8("oscar_protocol.snac_service", "Service", base.DEC)
snac_subtype = ProtoField.uint8("oscar_protocol.snac_subtype", "SubType", base.DEC)
snac_flags = ProtoField.uint16("oscar_protocol.snac_flags", "Flags", base.HEX)
snac_request_id = ProtoField.uint32("oscar_protocol.snac_request_id", "Request ID", base.DEC)

oscar_protocol.fields = {
  flap_proto_ch,
  flap_sequence_num,
  flap_payload_length,

  snac_service,
  snac_subtype,
  snac_flags,
  snac_request_id
}

function oscar_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = oscar_protocol.name

  local subtree = tree:add(oscar_protocol, buffer(), "OSCAR Protocol Data")

  local flapHeader = subtree:add(oscar_protocol, buffer(), "FLAP Header")

  flapHeader:add(flap_proto_ch, buffer(1, 1))
  flapHeader:add(flap_sequence_num, buffer(2, 2))
  flapHeader:add(flap_payload_length, buffer(4,2))

  local channel = buffer(1,1):uint()

  if channel == 2 then
    local snacHeader = subtree:add(oscar_protocol, buffer(), "SNAC Header")

    snacHeader:add(snac_service, buffer(6,2))
    snacHeader:add(snac_subtype, buffer(8,2))
    snacHeader:add(snac_flags, buffer(10, 2))
    snacHeader:add(snac_request_id, buffer(12, 4))
  end
end

function heuristic_checker(buffer, pinfo, tree)
  length = buffer:len()
  if length < 6 then return end

  local maybe_flap_header = buffer(0, 1):uint()
  if maybe_flap_header ~= 0x2a then return end

  oscar_protocol.dissector(buffer, pinfo, tree);
end

oscar_protocol:register_heuristic("tcp", heuristic_checker)
