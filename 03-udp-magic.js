const dgram = require('dgram')
const naive = require('./lib/naive-protocol')

const client = dgram.createSocket('udp4')
client.send(Buffer.concat([Buffer.from('naive'), naive('hello world')]), 1235, '127.0.0.1', () => {
  client.close()
})
