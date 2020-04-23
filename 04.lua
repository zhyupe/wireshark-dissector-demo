local naive_proto = Proto("naive_proto_4", "Naive #4")
local fields = {
  size    = ProtoField.uint32("naive_proto_4.size", "Size", base.DEC),
  content = ProtoField.string("naive_proto_4.content", "Content", base.UNICODE),
}
naive_proto.fields = fields

local dissectPacket, checkPacketLength

function naive_proto.dissector(tvbuf, pktinfo, root)
  local pktlen = tvbuf:len()
  local bytes_consumed = 0

  while bytes_consumed < pktlen do
      local result = dissectPacket(tvbuf, pktinfo, root, bytes_consumed)

      if result > 0 then
          -- we successfully processed a message, of 'result' length
          bytes_consumed = bytes_consumed + result
          -- go again on another while loop
      elseif result == 0 then
          -- If the result is 0, then it means we hit an error of some kind,
          -- so return 0. Returning 0 tells Wireshark this packet is not for
          -- us, and it will try heuristic dissectors or the plain "data"
          -- one, which is what should happen in this case.
          return 0
      else
          -- we need more bytes, so set the desegment_offset to what we
          -- already consumed, and the desegment_len to how many more
          -- are needed
          pktinfo.desegment_offset = bytes_consumed

          -- invert the negative result so it's a positive number
          result = -result

          pktinfo.desegment_len = result

          -- even though we need more bytes, this packet is for us, so we
          -- tell wireshark all of its bytes are for us by returning the
          -- number of Tvb bytes we "successfully processed", namely the
          -- length of the Tvb
          return pktlen
      end        
  end

  return bytes_consumed
end

dissectPacket = function (tvbuf, pktinfo, root, offset)
  local length_val, length_tvbr = checkPacketLength(tvbuf, offset)

  if length_val <= 0 then
      return length_val
  end

  local tree = root:add(naive_proto, tvbuf)
  pktinfo.cols.info:set("Naive #4")

  tree:add_le(fields.size, length_tvbr, length_val)

  local content_tvbr = tvbuf:range(offset + 4, length_val - 4)
  local content_val  = content_tvbr:string(ENC_UTF_8)
  tree:add(fields.content, content_tvbr, content_val)

  return length_val
end

checkPacketLength = function (tvbuf, offset)
  -- "msglen" is the number of bytes remaining in the Tvb buffer which we
  -- have available to dissect in this run
  local msglen = tvbuf:len() - offset

  -- check if capture was only capturing partial packet size
  if msglen ~= tvbuf:reported_length_remaining(offset) then
      -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
      return 0
  end

  -- 4 is the packet header length
  if msglen < 4 then
      -- we need more bytes, so tell the main dissector function that we
      -- didn't dissect anything, and we need an unknown number of more
      -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
      -- return as a negative number
      return -DESEGMENT_ONE_MORE_SEGMENT
  end

  -- if we got here, then we know we have enough bytes in the Tvb buffer
  -- to at least figure out the full length of this messsage (the length
  -- is the 16-bit integer in third and fourth bytes)

  -- get the TvbRange of bytes 3+4
  local length_tvbr = tvbuf:range(offset, 4)
  local length_val  = length_tvbr:le_uint()

  if msglen < length_val then
      -- we need more bytes to get the whole message
      return -(length_val - msglen)
  end

  return length_val, length_tvbr
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(1234, naive_proto)
