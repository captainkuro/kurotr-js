/**
 * OTR Message Parser
 * behave like a polymorph (properties are defined based on type)
 * 
 * @author Khandar William
 * @namespace Otr
 *
 * 2012-07-04 initial commit
 * 2012-07-05 rough parsing, toString
 * 2012-07-10 use ByteBuffer
 * 2012-11-05 recognize fragmentation
 */

Otr.Message = (function () {
	"use strict";
	/**
	 * @param {String} msg an OTR message
	 */
	function Message(msg) {
		var matches,
			bytebuff;

		if (!msg.match(/^\?OTR/)) {
			// this is plaintext message
			this.type = Message.MSG_PLAIN;
			this.message = msg;
			// @TODO check whitespace tag
		} else if (msg === '?OTRv2?') {
			// this is OTR Query Message
			this.type = Message.MSG_QUERY;
			this.message = msg;
		} else if (matches = msg.match(/^\?OTR Error:(.*)$/)) {
			// this is OTR Error Message
			this.type = Message.MSG_ERROR;
			this.message = matches[1];
		} else if (matches = msg.match(/^\?OTR,(\d+),(\d+),(.+)\.?,$/)) {
			this.type = Message.MSG_FRAGMENT;
			this.message = msg;
		} else if (matches = msg.match(/^\?OTR:([a-zA-Z0-9+\/]+={0,2})\.$/)) {
			// message type is taken from content
			bytebuff = Otr.ByteBuffer.fromBase64(matches[1]);
			this.version = bytebuff.readShort();
			this.type = bytebuff.readByte();
			// parse message components
			// properties name are prefixed with value type
			switch (this.type) {
				case Message.MSG_DH_COMMIT:
					this.dataEncryptedGx = bytebuff.readData();
					this.dataHashedGx    = bytebuff.readData();
					break;

				case Message.MSG_DH_KEY:
					this.mpiGy = bytebuff.readMPI();
					break;

				case Message.MSG_REVEAL_SIGNATURE:
					this.dataRevealedKey        = bytebuff.readData();
					this.dataEncryptedSignature = bytebuff.readData();
					this.macSignature           = bytebuff.readBytes(20);
					break;

				case Message.MSG_SIGNATURE:
					this.dataEncryptedSignature = bytebuff.readData();
					this.macSignature           = bytebuff.readBytes(20);
					break;

				case Message.MSG_DATA:
					this.byteFlags            = bytebuff.readByte();
					this.intSenderKeyid       = bytebuff.readUInt();
					this.intRecipientKeyid    = bytebuff.readUInt();
					this.mpiDHy               = bytebuff.readMPI();
					this.ctr                  = bytebuff.readBytes(8);
					this.dataEncryptedMessage = bytebuff.readData();
					this.macAuthenticator     = bytebuff.readBytes(20);
					this.dataOldMacKeys       = bytebuff.readData();
					break;

				default:
					// unknown/invalid type
					this.type = Message.MSG_UNKNOWN;
					this.message = msg;
			}
		} else {
			// I don't recognize this
			this.type = Message.MSG_UNKNOWN;
			this.message = msg;
		}
	}

	// constants
	Message.MSG_UNKNOWN = -99;
	Message.MSG_QUERY = -1;
	Message.MSG_ERROR = -2;
	Message.MSG_PLAIN = -3;
	Message.MSG_FRAGMENT = -4;
	// specified by protocol:
	Message.MSG_DH_COMMIT = 0x02;
	Message.MSG_DH_KEY = 0x0a;
	Message.MSG_REVEAL_SIGNATURE = 0x11;
	Message.MSG_SIGNATURE = 0x12;
	Message.MSG_DATA = 0x03;

	Message.prototype = {
		type: 0, // SHORT 16-bit unsigned
		version: 2, // BYTE 8-bit unsigned
		message: '',
		// properties are dinamically created based on message type
		// @TODO complete properties

		toString: function () {
			var bytebuff = new Otr.ByteBuffer();

			bytebuff.writeShort(this.version);
			bytebuff.writeByte(this.type);

			switch (this.type) {
				case Message.MSG_ERROR:
					return '?OTR Error:'+this.message;
					
				case Message.MSG_DH_COMMIT:
					bytebuff.writeData(this.dataEncryptedGx);
					bytebuff.writeData(this.dataHashedGx);
					break;
					
				case Message.MSG_DH_KEY:
					bytebuff.writeMPI(this.mpiGy);
					break;
					
				case Message.MSG_REVEAL_SIGNATURE:
					bytebuff.writeData(this.dataRevealedKey);
					bytebuff.writeData(this.dataEncryptedSignature);
					bytebuff.writeBytes(this.macSignature, 20);
					break;
					
				case Message.MSG_SIGNATURE:
					bytebuff.writeData(this.dataEncryptedSignature);
					bytebuff.writeBytes(this.macSignature, 20);
					break;
					
				case Message.MSG_DATA:
					bytebuff.writeByte(this.byteFlags);
					bytebuff.writeUInt(this.intSenderKeyid);
					bytebuff.writeUInt(this.intRecipientKeyid);
					bytebuff.writeMPI(this.mpiDHy);
					bytebuff.writeBytes(this.ctr, 8);
					bytebuff.writeData(this.dataEncryptedMessage);
					bytebuff.writeBytes(this.macAuthenticator, 20);
					bytebuff.writeData(this.dataOldMacKeys);
					break;

				default:
					return this.message;
			}
			return '?OTR:'+(bytebuff.toBase64())+'.';
		}
	};

	return Message;
}());
