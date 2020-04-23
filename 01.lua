local naive_proto = Proto("naive_proto_1", "Naive #1")
local fields = {
  size    = ProtoField.uint32("naive_proto_1.size", "Size", base.DEC),
  content = ProtoField.string("naive_proto_1.content", "Content", base.UNICODE),
}
naive_proto.fields = fields

function naive_proto.dissector(tvbuf, pktinfo, root)
  local tree = root:add(naive_proto, tvbuf)
  pktinfo.cols.info:set("Naive #1")

  local size_tvbr = tvbuf:range(0, 4)
  local size_val  = size_tvbr:le_uint()
  tree:add_le(fields.size, size_tvbr, size_val)

  local content_tvbr = tvbuf:range(4)
  local content_val  = content_tvbr:string(ENC_UTF_8)
  tree:add(fields.content, content_tvbr, content_val)

  return tvbuf:len()
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(1234, naive_proto)
