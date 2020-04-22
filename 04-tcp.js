const net = require('net')
const naive = require('./lib/naive-protocol')

const server = net.createServer(socket => {
  socket.on('data', data => {
    console.log(data)
  })
})
server.listen(1234)

const client = net.createConnection(1234, '127.0.0.1', () => {
  console.log('Connected')

  client.write(Buffer.concat([
    naive('hello'),
    naive('world'),
    naive('a quick brown fox'),
    naive('jumps over the lazy dog')
  ]))

  client.end()
  client.on('end', () => {
    server.close()
  })
})
