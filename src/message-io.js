const tls = require('tls');
const crypto = require('crypto');
const net = require('net');
const EventEmitter = require('events').EventEmitter;
const Transform = require('readable-stream').Transform;

const Packet = require('./packet').Packet;
const TYPE = require('./packet').TYPE;
const packetHeaderLength = require('./packet').HEADER_LENGTH;

class ReadablePacketStream extends Transform {
  constructor() {
    super({ objectMode: true });

    this.buffer = new Buffer(0);
    this.position = 0;
  }

  _transform(chunk, encoding, callback) {
    if (this.position === this.buffer.length) {
      // If we have fully consumed the previous buffer,
      // we can just replace it with the new chunk
      this.buffer = chunk;
    } else {
      // If we haven't fully consumed the previous buffer,
      // we simply concatenate the leftovers and the new chunk.
      this.buffer = Buffer.concat([
        this.buffer.slice(this.position), chunk
      ], (this.buffer.length - this.position) + chunk.length);
    }

    this.position = 0;

    // The packet header is always 8 bytes of length.
    while (this.buffer.length >= this.position + packetHeaderLength) {
      // Get the full packet length
      const length = this.buffer.readUInt16BE(this.position + 2);

      if (this.buffer.length >= this.position + length) {
        const data = this.buffer.slice(this.position, this.position + length);
        this.position += length;
        this.push(new Packet(data));
      } else {
        // Not enough data to provide the next packet. Stop here and wait for
        // the next call to `_transform`.
        break;
      }
    }

    callback();
  }
}

class TLSHandler extends EventEmitter {
  constructor(secureContext) {
    super();
    const self = this;
    self.server = net.createServer();

    self.server.listen(0, '127.0.0.1', () => {
      self.cleartext = tls.connect({
        host: '127.0.0.1',
        port: self.server.address().port,
        secureContext: secureContext,
        rejectUnauthorized: false
      })
      self.cleartext.on('secureConnect', () => {
        self.emit('secure')
        self.cleartext.write('')
      })
    })

    const encryptedOnQueue = [];
    self.encrypted = {
      on: (event, cb) => {
        encryptedOnQueue.push([event, cb])
      }
    }

    self.server.on('connection', socket => {
      self.encrypted = socket;
      encryptedOnQueue.forEach(([event, cb]) => {
        self.encrypted.on(event, cb)
      })
      self.server.close()
    })
  }

  destroy() {
    if (this.encrypted.destroy) {
      this.encrypted.removeAllListeners('data');
      //this.encrypted.destroy()
    }
    if (this.cleartext.destroy) {
      this.cleartext.removeAllListeners('data');
      //this.cleartext.destroy()
    }
  }
}

module.exports = class MessageIO extends EventEmitter {
  constructor(socket, _packetSize, debug) {
    super();

    this.socket = socket;
    this._packetSize = _packetSize;
    this.debug = debug;
    this.sendPacket = this.sendPacket.bind(this);

    this.packetStream = new ReadablePacketStream();
    this.packetStream.on('data', (packet) => {
      if (this.socket.destroyed) {
        return
      }
      this.logPacket('Received', packet);
      this.emit('data', packet.data());
      if (packet.isLast()) {
        this.emit('message');
      }
    });

    this.socket.pipe(this.packetStream);
    this.packetDataSize = this._packetSize - packetHeaderLength;
  }

  packetSize(packetSize) {
    if (arguments.length > 0) {
      this.debug.log('Packet size changed from ' + this._packetSize + ' to ' + packetSize);
      this._packetSize = packetSize;
      this.packetDataSize = this._packetSize - packetHeaderLength;
    }
    return this._packetSize;
  }

  startTls(credentialsDetails, hostname, trustServerCertificate) {
    const credentials = tls.createSecureContext ? tls.createSecureContext(credentialsDetails) : crypto.createCredentials(credentialsDetails);

    this.socket.on('close', () => {
      this.closed = true;
      this.tlsHandler.destroy()
    })

    this.tlsHandler = new TLSHandler(credentials)

    //this.securePair = tls.createSecurePair(credentials);
    this.tlsNegotiationComplete = false;

    this.tlsHandler.on('secure', () => {
      const cipher = this.tlsHandler.cleartext.getCipher();

      if (!trustServerCertificate) {
        if (!this.tlsHandler.cleartext.authorized) {
          this.tlsHandler.destroy();
          this.socket.destroy(this.tlsHandler.cleartext.authorizationError);
          return;
        }
      }

      this.debug.log('TLS negotiated (' + cipher.name + ', ' + cipher.version + ')');
      this.emit('secure', this.tlsHandler.cleartext);
      this.encryptAllFutureTraffic();
    });

    this.tlsHandler.encrypted.on('data', (data) => {
      this.sendMessage(TYPE.PRELOGIN, data);
    });
  }

  encryptAllFutureTraffic() {
    this.socket.unpipe(this.packetStream);
    this.tlsHandler.encrypted.removeAllListeners('data');
    this.socket.pipe(this.tlsHandler.encrypted);
    this.tlsHandler.encrypted.pipe(this.socket);
    this.tlsHandler.cleartext.pipe(this.packetStream);
    this.tlsNegotiationComplete = true;
    if (!this.socket.destroyed) {
      // the old SecurePair worked synchronously and fired the
      // 'secure' event before the packet was handled by
      // RedablePacketStream. this is not the case anymore so
      // emit 'message' manually to fire SENT_TLSSSLNEGOTIATION.message again
      this.emit('message');
    }
  }

  tlsHandshakeData(data) {
    this.tlsHandler.encrypted.write(data);
  }

  // TODO listen for 'drain' event when socket.write returns false.
  // TODO implement incomplete request cancelation (2.2.1.6)
  sendMessage(packetType, data, resetConnection) {
    let numberOfPackets;
    if (data) {
      numberOfPackets = (Math.floor((data.length - 1) / this.packetDataSize)) + 1;
    } else {
      numberOfPackets = 1;
      data = new Buffer(0);
    }

    for (let packetNumber = 0; packetNumber < numberOfPackets; packetNumber++) {
      const payloadStart = packetNumber * this.packetDataSize;

      let payloadEnd;
      if (packetNumber < numberOfPackets - 1) {
        payloadEnd = payloadStart + this.packetDataSize;
      } else {
        payloadEnd = data.length;
      }

      const packetPayload = data.slice(payloadStart, payloadEnd);

      const packet = new Packet(packetType);
      packet.last(packetNumber === numberOfPackets - 1);
      packet.resetConnection(resetConnection);
      packet.packetId(packetNumber + 1);
      packet.addData(packetPayload);
      this.sendPacket(packet);
    }
  }

  sendPacket(packet) {
    this.logPacket('Sent', packet);
    if (this.tlsHandler && this.tlsNegotiationComplete) {
      this.tlsHandler.cleartext.write(packet.buffer);
    } else {
      this.socket.write(packet.buffer);
    }
  }

  logPacket(direction, packet) {
    this.debug.packet(direction, packet);
    return this.debug.data(packet);
  }

  // Temporarily suspends the flow of incoming packets.
  pause() {
    this.packetStream.pause();
  }

  // Resumes the flow of incoming packets.
  resume() {
    this.packetStream.resume();
  }
};
