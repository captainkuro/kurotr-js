/**
 * @preserve
 * Adamia 3D Engine v0.1
 * Copyright (c) 2010 Adam R. Smith
 * Licensed under the new BSD License:
 * http://www.opensource.org/licenses/bsd-license.php
 */

/**
 * JavaScript ByteArray Implementation
 * Modified from a3d.js ByteArray
 * http://code.google.com/p/adamia-3d/
 * http://www.adamia.com/blog/high-performance-javascript-port-of-actionscript-byteArray
 *
 * Big Endian only
 * Act as both read buffer and write buffer
 * ByteArray IS NEITHER Data NOR MPI
 *
 * @author Khandar William
 * @namespace Otr
 *
 * 2012-07-03 initial commit, remove little-endian support
 *            add writeByte,Bool,U/Int32, U/Int16, read/writeBytes
 * 2012-07-04 add read/writeData, fromBase64, toBase64
 * 2012-07-06 add fromWordArray & toWordArray
 * 2012-07-09 add byteAt method, bug in writeData, crap I mix ByteArray with Data and MPI
 */

Otr.ByteArray = (function () {
	"use strict";

	var b64array = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

	/**
	 * @param {String} data string representation of ByteArray
	 */
	function ByteArray(data) {
		this.data = (typeof data !== "undefined") ? data : '';
	}

	ByteArray.prototype = {
		data: '',
		pos: 0,
		pow: Math.pow,
		TWOeN23: Math.pow(2, -23),
		TWOeN52: Math.pow(2, -52),

		// ========================= BUFFER READER =============================
		readByte: function () { // UInt8
			return (this.data.charCodeAt(this.pos++) & 0xFF);
		},

		readBool: function () {
			return (this.data.charCodeAt(this.pos++) & 0xFF) ? true : false;
		},

		readUInt32: function () {
			var data = this.data, pos = (this.pos += 4) - 4;
			var x = ((data.charCodeAt(pos)   & 0xFF) << 24) |
					((data.charCodeAt(++pos) & 0xFF) << 16) |
					((data.charCodeAt(++pos) & 0xFF) << 8) |
					 (data.charCodeAt(++pos) & 0xFF);
			 // javascript bitwise operator treat operands as 32-bit SIGNED INTEGER!!!
			return (x < 0) ? x + 4294967296 : x; 
		},
		readInt32: function () {
			var data = this.data, pos = (this.pos += 4) - 4;
			var x =	((data.charCodeAt(pos)   & 0xFF) << 24) |
					((data.charCodeAt(++pos) & 0xFF) << 16) |
					((data.charCodeAt(++pos) & 0xFF) << 8) |
					 (data.charCodeAt(++pos) & 0xFF);
			return (x >= 2147483648) ? x - 4294967296 : x;
		},

		readUInt16: function () {
			var data = this.data, pos = (this.pos += 2) - 2;
			return	((data.charCodeAt(pos)   & 0xFF) << 8) |
					 (data.charCodeAt(++pos) & 0xFF);
		},
		readInt16: function () {
			var data = this.data, pos = (this.pos += 2) - 2;
			var x =	((data.charCodeAt(pos)   & 0xFF) << 8) |
					 (data.charCodeAt(++pos) & 0xFF);
			return (x >= 32768) ? x - 65536 : x;
		},

		readFloat32: function () {
			var data = this.data, pos = (this.pos += 4) - 4;
			var b1 = data.charCodeAt(pos) & 0xFF,
				b2 = data.charCodeAt(++pos) & 0xFF,
				b3 = data.charCodeAt(++pos) & 0xFF,
				b4 = data.charCodeAt(++pos) & 0xFF;
			var sign = 1 - ((b1 >> 7) << 1);                   // sign = bit 0
			var exp = (((b1 << 1) & 0xFF) | (b2 >> 7)) - 127;  // exponent = bits 1..8
			var sig = ((b2 & 0x7F) << 16) | (b3 << 8) | b4;    // significand = bits 9..31
			if (sig == 0 && exp == -127) {
				return 0.0;
			}
			return sign*(1 + this.TWOeN23*sig)*this.pow(2, exp);
		},

		readFloat64: function () {
			var data = this.data, pos = (this.pos += 8) - 8;
			var b1 = data.charCodeAt(pos) & 0xFF,
				b2 = data.charCodeAt(++pos) & 0xFF,
				b3 = data.charCodeAt(++pos) & 0xFF,
				b4 = data.charCodeAt(++pos) & 0xFF,
				b5 = data.charCodeAt(++pos) & 0xFF,
				b6 = data.charCodeAt(++pos) & 0xFF,
				b7 = data.charCodeAt(++pos) & 0xFF,
				b8 = data.charCodeAt(++pos) & 0xFF;
			var sign = 1 - ((b1 >> 7) << 1);									// sign = bit 0
			var exp = (((b1 << 4) & 0x7FF) | (b2 >> 4)) - 1023;					// exponent = bits 1..11

			// This crazy toString() stuff works around the fact that js ints are
			// only 32 bits and signed, giving us 31 bits to work with
			var sig = (((b2 & 0xF) << 16) | (b3 << 8) | b4).toString(2) +
				((b5 >> 7) ? '1' : '0') +
				(((b5 & 0x7F) << 24) | (b6 << 16) | (b7 << 8) | b8).toString(2);	// significand = bits 12..63

			sig = parseInt(sig, 2);
			if (sig == 0 && exp == -1023) {
				return 0.0;
			}
			return sign*(1.0 + this.TWOeN52*sig)*this.pow(2, exp);
		},

		/**
		 * @param {Number} length How many bytes to read
		 * @return {ByteArray}
		 */
		readBytes: function (length) {
			var x = new ByteArray();
			while (length--) {
				x.writeByte(this.readByte());
			}
			x.reset();
			return x;
		},

		/**
		 * "Data" is simply an array of byte
		 * @return {ByteArray}
		 */
		readData: function () {
			var ba = new ByteArray(),
				len = this.readUInt32(),
				bytes = this.readBytes(len);

			ba.writeUInt32(len);
			ba.writeBytes(bytes, len);
			return ba;
		},

		/** 
		 * "MPI" is actually ByteArray
		 * @return {ByteArray}
		 */
		readMPI: function () {
			return this.readData();
		},

		// =========================== BUFFER WRITER ===========================
		// WARNING: all write operations use String APPEND so DON'T MIX reading and writing

		writeByte: function (b) { // UInt8
			this.data += String.fromCharCode(b & 0xFF);
			this.pos++;
		},

		writeBool: function (b) {
			b = b ? 1 : 0;
			this.data += String.fromCharCode(b & 0xFF);
			this.pos++;
		},

		writeUInt32: function (x) {
			this.data += String.fromCharCode(
				(x >> 24) & 0xFF,
				(x >> 16) & 0xFF,
				(x >> 8) & 0xFF,
				(x) & 0xFF
			);
			this.pos += 4;
		},
		writeInt32: function (x) {
			if (x < 0) x += 4294967296;
			this.writeUInt32(x);
		},

		writeUInt16: function (x) {
			this.data += String.fromCharCode(
				(x >> 8) & 0xFF,
				(x) & 0xFF
			);
			this.pos += 2;
		},
		writeInt16: function (x) {
			if (x < 0) x += 65536;
			this.writeUInt16(x);
		},

		/**
		 * @param {ByteArray|String|Array} bytes Byte array representation
		 * @param {Number} length Optional specify how many bytes to write
		 */
		writeBytes: function (bytes, length) {
			var i;
			if (Object.prototype.toString.call(bytes) === "[object Array]") {
				length = length || bytes.length;

				for (i = 0; i < length; i++) {
					this.writeByte(bytes[i]);
				}
			} else {
				if (typeof bytes === "string") {
					bytes = new ByteArray(bytes);
				}
				length = length || bytes.getLength();
				i = length;

				while (i--) {
					this.writeByte(bytes.readByte());
				}
				bytes.pos -= length; // restore pointer
			}
		},

		/**
		 * @param {ByteArray|Array} data Representation of data as array of bytes
		 */
		writeData: function (data) {
			var len;
			if (Object.prototype.toString.call(data) === "[object Array]") {
				data = ByteArray.fromArray(data);
			} 
			data.reset(); // read from start
			len = data.readUInt32();
			
			this.writeUInt32(len);
			this.writeBytes(data, len);
		},

		/**
		 * @Param {ByteArray} mpi Representation of MPI
		 */
		writeMPI: function (mpi) {
			this.writeData(mpi);
		},

		// @TODO writeFloat32 & writeFloat64

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
		 * @param {ByteArray} b
		 * @return {Boolean}
		 */
		equal: function (b) {
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
		toArray: function () {
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

		/**
		 * @return {CryptoJS.lib.WordArray}
		 */
		toWordArray: function () {
			var arr = [],
				len = this.getLength(),
				prevpos = this.pos;

			this.reset();
			while (len > 0) {
				arr.push(this.readUInt32());
				len -= 4;
			}
			this.pos = prevpos;
			return CryptoJS.lib.WordArray.create(arr, this.getLength());
		},

		/**
		 * Treat this ByteArray as MPI
		 * @return {BigInteger}
		 */
		toBigInteger: function () {
			var prevpos = this.pos,
				len, bi;

			this.reset();
			len = this.readUInt32();
			bi = new Otr.BigInteger(this.readBytes(len).toArray());
			this.pos = prevpos;

			return bi;
		},

		toString: function () {
			return this.data;
		}
	};

	// ================================ STATIC =================================
	/**
	 * @param {Array} arr An array of bytes
	 * @return {ByteArray}
	 */
	ByteArray.fromArray = function (arr) {
		var ba = new ByteArray(),
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
	 * @return {ByteArray} 
	 */
	ByteArray.fromBase64 = function (input) {
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

	    return new ByteArray(output);
	};

	/**
	 * @param {CryptoJS.lib.WordArray} wa
	 * @return {ByteArray}
	 */
	ByteArray.fromWordArray = function (wa) {
		var ba = new ByteArray(),
			i, l, word,
			remains = wa.sigBytes;

		for (i=0, l=wa.words.length; i<l; i++) {
			word = wa.words[i];
			if (remains >= 4) {
				ba.writeUInt32(word);
			} else if (remains === 3) {
				ba.writeBytes([
					(word >> 24) & 0xFF,
					(word >> 16) & 0xFF,
					(word >> 8) & 0xFF
				]);
			} else if (remains === 2) {
				ba.writeBytes([
					(word >> 24) & 0xFF,
					(word >> 16) & 0xFF
				]);
			} else if (remains === 1) {
				ba.writeBytes([
					(word >> 24) & 0xFF,
				]);
			} else {
				break;
			}
			remains -= 4;
		}

		ba.reset();
		return ba;
	};

	/**
	 * Produce an MPI
	 * @param {BigInteger} bi
	 * @return {ByteArray} An MPI
	 */
	ByteArray.fromBigInteger = function (bi) {
		var ba = new ByteArray(),
			bytes = bi.toByteArray(),
			len = bytes.length;

		ba.writeUInt32(len);
		ba.writeBytes(bytes, len);
		ba.reset();
		return ba;
	};

	/**
	 * Make a ByteArray to Data (prepend 4 bytes of length)
	 * @param {ByteArray} ba
	 * @return {ByteArray}
	 */
	ByteArray.makeData = function (ba) {

	};

	return ByteArray;
}());