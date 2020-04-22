const dgram = require('dgram')
const naive = require('./lib/naive-protocol')

const client = dgram.createSocket('udp4')
client.send(naive('Hello World'), 1234, '127.0.0.1', () => {
  client.close()
})
