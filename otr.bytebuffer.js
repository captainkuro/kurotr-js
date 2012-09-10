/**
 * JavaScript ByteBuffer Implementation
 *
 * Act as both read buffer and write buffer
 * Bytes are stored big-endian
 *
 * @author Khandar William
 * @namespace Otr
 * @require Crypto.lib.WordArray
 *
 * 2012-07-10 initial commit, rewrite of ByteArray
 */

Otr.ByteBuffer = (function () {
	"use strict";

	var b64array = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

	/**
	 * @param {String} data string representation of bytes
	 */
	function ByteBuffer(data) {
		this.data = (typeof data !== "undefined") ? data : '';
	}

	ByteBuffer.prototype = {
		data: '', // internal bytes representation
		pos: 0,
		
		// ============================== STREAM ===============================

		// Byte: 1-byte unsigned integer
		readByte: function () {
			return (this.data.charCodeAt(this.pos++) & 0xFF);
		},
		writeByte: function (b) {
			this.data += String.fromCharCode(b & 0xFF);
			this.pos++;
		},

		// Short: 2-byte unsigned integer
		readShort: function () {
			var data = this.data, pos = (this.pos += 2) - 2;
			return	((data.charCodeAt(pos)   & 0xFF) << 8) |
					 (data.charCodeAt(++pos) & 0xFF);
		},
		writeShort: function (x) {
			this.data += String.fromCharCode(
				(x >> 8) & 0xFF,
				(x) & 0xFF
			);
			this.pos += 2;
		},

		// UInt: 4-byte unsigned integer
		readUInt: function () {
			var data = this.data, pos = (this.pos += 4) - 4;
			var x = ((data.charCodeAt(pos)   & 0xFF) << 24) |
					((data.charCodeAt(++pos) & 0xFF) << 16) |
					((data.charCodeAt(++pos) & 0xFF) << 8) |
					 (data.charCodeAt(++pos) & 0xFF);
			 // javascript bitwise operator treat operands as 32-bit SIGNED INTEGER!!!
			return (x < 0) ? x + 4294967296 : x; 
		},
		writeUInt: function (x) {
			this.data += String.fromCharCode(
				(x >> 24) & 0xFF,
				(x >> 16) & 0xFF,
				(x >> 8) & 0xFF,
				(x) & 0xFF
			);
			this.pos += 4;
		},

		// Bytes: array of byte values
		readBytes: function (length) {
			var x = [];
			while (length--) {
				x.push(this.readByte());
			}
			return x;
		},
		writeBytes: function (bytes, length) {
			var i;

			length = length || bytes.length;

			for (i=0; i<length; ++i) {
				this.writeByte(bytes[i]);
			}
		},

		// Data: Otr.Type.Data
		readData: function () {
			var len = this.readUInt(),
				bytes = this.readBytes(len);
			return new Otr.Type.Data(bytes);
		},
		writeData: function (data) {
			var len = data.getLength();
			this.writeUInt(len);
			this.writeBytes(data.getValue(), len);
		},

		// MPI: Otr.Type.MPI
		readMPI: function () {
			var len = this.readUInt(),
				bytes = this.readBytes(len);
			return new Otr.Type.MPI(bytes);
		},
		writeMPI: function (mpi) {
			var len = mpi.getLength();
			this.writeUInt(len);
			this.writeBytes(mpi.getValue(), len);
		},

		// ============================== OTHER ================================
		reset: function () {
			this.pos = 0;
		},

		getLength: function () {
			return this.data.length;
		},

		byteAt: function (i) {
			return this.data.charCodeAt(i) & 0xFF;
		},

		/**
		 * Return true if this and b have the same bytes
		 * @param {ByteBuffer} b
		 * @return {Boolean}
		 */
		equals: function (b) {
			if (this.getLength() !== b.getLength()) return false;
			var thisprev = this.pos,
				bprev = b.pos,
				len = this.getLength();
			
			this.reset();
			b.reset();
			while (len--) {
				if (this.readByte() !== b.readByte()) {
					this.pos = thisprev;
					b.pos = bprev;
					return false;
				}
			}
			this.pos = thisprev;
			b.pos = bprev;
			return true;
		},

		/**
		 * @return {Array} An array of byte values
		 */
		toByteArray: function () {
			var arr = [],
				len = this.getLength(),
				prevpos = this.pos;

			this.reset();
			while (len--) {
				arr.push(this.readByte());
			}
			this.pos = prevpos;
			return arr;
		},

		/**
		 * @return {CryptoJS.lib.WordArray}
		 */
		toWordArray: function () {
			var arr = [],
				len = this.getLength(),
				prevpos = this.pos;

			this.reset();
			while (len > 0) {
				arr.push(this.readUInt());
				len -= 4;
			}
			this.pos = prevpos;
			return CryptoJS.lib.WordArray.create(arr, this.getLength());
		},

		/**
		 * http://decodebase64.com
		 * @return {String} base64-encoded string of this.data
		 */
		toBase64: function () {
			var input = this.data,
				base64 = "",
				chr1, chr2, chr3,
				enc1, enc2, enc3, enc4,
				i = 0;

		    do {
		        chr1 = input.charCodeAt(i++);
		        if (!isNaN(chr1)) chr1 &= 0xFF;
		        chr2 = input.charCodeAt(i++);
		        if (!isNaN(chr2)) chr2 &= 0xFF;
		        chr3 = input.charCodeAt(i++);
		        if (!isNaN(chr3)) chr3 &= 0xFF;
		    
		        enc1 = chr1 >> 2;
		        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
		        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
		        enc4 = chr3 & 63;
		    
		        if (isNaN(chr2)) {
		            enc3 = enc4 = 64;
		        } else if (isNaN(chr3)) {
		            enc4 = 64;
		        }

		        base64  = base64  +
		            b64array.charAt(enc1) +
		            b64array.charAt(enc2) +
		            b64array.charAt(enc3) +
		            b64array.charAt(enc4);
		        chr1 = chr2 = chr3 = "";
		        enc1 = enc2 = enc3 = enc4 = "";
		    } while (i < input.length);

		    return base64;
		},

		toString: function () {
			return this.data;
		}
	};

	// ================================ STATIC =================================
	/**
	 * @param {Array} arr An array of bytes
	 * @return {ByteBuffer}
	 */
	ByteBuffer.fromByteArray = function (arr) {
		var ba = new ByteBuffer(),
			i, l;

		for (i=0, l=arr.length; i<l; i++) {
			ba.writeByte(arr[i]);
		}
		ba.reset();
		return ba;
	};

	/**
	 * http://decodebase64.com
	 * @param {String} input base64-encoded string
	 * @return {ByteBuffer} 
	 */
	ByteBuffer.fromBase64 = function (input) {
		var output = "",
	    	chr1, chr2, chr3,
    		enc1, enc2, enc3, enc4,
			i = 0;

		do {
	        enc1 = b64array.indexOf(input.charAt(i++));
	        enc2 = b64array.indexOf(input.charAt(i++));
	        enc3 = b64array.indexOf(input.charAt(i++));
	        enc4 = b64array.indexOf(input.charAt(i++));
	        
	        chr1 = (enc1 << 2) | (enc2 >> 4);
	        chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
	        chr3 = ((enc3 & 3) << 6) | enc4;
	        
	        output = output + String.fromCharCode(chr1);
	        
	        if (enc3 != 64) {
	            output = output + String.fromCharCode(chr2);
	        }
	        if (enc4 != 64) {
	            output = output + String.fromCharCode(chr3);
	        }
	    
	        chr1 = chr2 = chr3 = "";
	        enc1 = enc2 = enc3 = enc4 = "";
	    
	    } while (i < input.length);

	    return new ByteBuffer(output);
	};

	return ByteBuffer;
}());