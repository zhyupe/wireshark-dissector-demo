local naive_proto = Proto("naive_proto_3", "Naive #3")
local fields = {
  magic   = ProtoField.string("naive_proto_3.magic", "Magic"),
  size    = ProtoField.uint32("naive_proto_3.size", "Size", base.DEC),
  content = ProtoField.string("naive_proto_3.content", "Content", base.UNICODE),
}
naive_proto.fields = fields

function naive_proto.dissector(tvbuf, pktinfo, root)
  local tree = root:add(naive_proto, tvbuf)
  pktinfo.cols.info:set("Naive #3")

  local magic_tvbr = tvbuf:range(0, 5)
  local magic_val  = magic_tvbr:string()
  tree:add(fields.magic, magic_tvbr)

  local size_tvbr = tvbuf:range(5, 4)
  local size_val  = size_tvbr:le_uint()
  tree:add_le(fields.size, size_tvbr, size_val)

  local content_tvbr = tvbuf:range(9)
  local content_val  = content_tvbr:string(ENC_UTF_8)
  tree:add(fields.content, content_tvbr, content_val)

  return tvbuf:len()
end

local function heur_dissect(tvbuf, pktinfo, root)
  if tvbuf:len() < 9 then
    return false
  end

  local magic = tvbuf:raw(0,5)
  if magic ~= "naive" then
    return false
  end

  naive_proto.dissector(tvbuf, pktinfo, root)
  pktinfo.conversation = naive_proto

  return true
end

naive_proto:register_heuristic("udp", heur_dissect)