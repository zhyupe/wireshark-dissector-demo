const net = require('net')
const naive = require('./lib/naive-protocol')

const client = net.createConnection(80, 'www.baidu.com', () => {
  console.log('Connected')

  client.write(naive(`This is really l${'o'.repeat(10240)}ng`))
  client.end()
})
