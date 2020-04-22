module.exports = (data) => {
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data)
  }

  const header = Buffer.alloc(4)
  header.writeUInt32LE(data.length + 4)

  return Buffer.concat([header, data])
}
