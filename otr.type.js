/**
 * JavaScript OTR Types
 *
 * @author Khandar William
 * @namespace OTR
 *
 * 2012-07-** initial commit, define custom types, create MPI and Data, Pubkey and Sig,
 *            readPubkey and readSig, Sig.toBytes will return 2*20 bytes, add compareTo,
 *            compareTo now use biginteger
 * 2012-08-02 add TLV
 */

Otr.Type = (function () {
	"use strict";

	/**
	 * Data holds an array of bytes
	 * @param {Array} x Array of bytes
	 */
	function Data(x) {
		this.value = x;
	}

	Data.prototype = {
		value: [],

		getLength: function () {
			return this.value.length;
		},

		getValue: function () {
			return this.value;
		},

		equals: function (d) {
			var i, len = this.getLength();

			if (this.getLength() !== d.getLength()) return false;
			for (i=0; i<len; ++i) {
				if (this.value[i] !== d.value[i]) return false;
			}
			return true;
		},

		// Returns array of byte values
		toBytes: function () {
			var bytes = this.value.slice(0),
				len = this.getLength();

			bytes.unshift(
				(len >> 24) & 0xFF,
				(len >> 16) & 0xFF,
				(len >> 8) & 0xFF,
				(len) & 0xFF
			);
			return bytes;
		}
	};

	/**
	 * MPI holds an array of bytes which represents a BigInteger value
	 * @param {Array|BigInteger} x Array of bytes OR BigInteger
	 */
	function MPI(x) {
		if (x instanceof Otr.BigInteger) {
			this.value = x.toByteArray();
		} else {
			this.value = x;
		}
		while (this.value[0] === 0) { // kadang ada padding 0 di awal
			this.value.shift();
		}
	}

	MPI.prototype = {
		value: [],

		getLength: function () {
			return this.value.length;
		},

		getValue: function () {
			return this.value;
		},

		equals: function (m) {
			var i, len = this.getLength();

			if (this.getLength() !== m.getLength()) return false;
			for (i=0; i<len; ++i) {
				if (this.value[i] !== m.value[i]) return false;
			}
			return true;
		},

		// @return < 0 if this < mpi; > 0 if this > mpi; 0 if this == mpi
		compareTo: function (mpi) {
			return this.toBigInteger().compareTo(mpi.toBigInteger());
		},

		// Returns array of byte values
		toBytes: function () {
			var bytes = this.value.slice(0),
				len = this.getLength();

			bytes.unshift(
				(len >> 24) & 0xFF,
				(len >> 16) & 0xFF,
				(len >> 8) & 0xFF,
				(len) & 0xFF
			);
			return bytes;
		},

		// Returns Otr.BigInteger value
		toBigInteger: function () {
			return Otr.BigInteger.fromMagnitude(1, this.value);
		}
	};

	/**
	 * Pubkey holds information about a DSA public key
	 * @param {MPI} p, q, g, y
	 */
	function Pubkey(p, q, g, y) {
		// all MPI
		this.p = p;
		this.q = q;
		this.g = g;
		this.y = y;
	}

	Pubkey.prototype = {
		type: 0x0000, // Short

		toBytes: function () {
			var bytes = [];

			// append type
			bytes.push((this.type >> 8) & 0xFF);
			bytes.push(this.type & 0xFF);
			// append p, q, g, y
			bytes = bytes.concat(
				this.p.toBytes(), 
				this.q.toBytes(),
				this.g.toBytes(),
				this.y.toBytes()
			);
			return bytes;
		}
	};

	// Static: Read a Pubkey from ByteBuffer
	// @param {ByteBuffer} buf
	Pubkey.readPubkey = function (buf) {
		var type = buf.readShort(),
			p = buf.readMPI(),
			q = buf.readMPI(),
			g = buf.readMPI(),
			y = buf.readMPI();
		
		return new Pubkey(p, q, g, y);
	};

	/**
	 * Sig holds information about a DSA signature
	 * @param {BigInteger} r, s
	 */
	function Sig(r, s) {
		// all BigInteger
		this.r = r;
		this.s = s;
	}

	Sig.prototype = {
		toBytes: function () {
			var bar = this.r.toByteArray(),
				bas = this.s.toByteArray();

			// byte length must be 20
			while (bar[0] === 0) bar.shift();
			while (bar.length < 20) bar.unshift(0x00);
			while (bas[0] === 0) bas.shift();
			while (bas.length < 20) bas.unshift(0x00);

			return bar.concat(bas);
		}
	};

	// Static: Read a Sig from ByteBuffer
	// @param {ByteBuffer} buf
	Sig.readSig = function (buf) {
		var r = buf.readBytes(20),
			s = buf.readBytes(20);
		
		return new Sig(Otr.BigInteger.fromMagnitude(1, r), Otr.BigInteger.fromMagnitude(1, s));
	};

	/**
	 * TLV record
	 * @param {Short} type
	 * @param {Short} len
	 * @param {Array} val array of bytes
	 */
	function TLV(type, len, val) {
		this.type = type;
		this.len = len;
		this.val = val;
	}

	TLV.prototype = {

	};

	// TLV Types
	TLV.PADDING = 0;
	TLV.DISCONNECTED = 1;

	// Static: Read a TLV from ByteBuffer
	// @param {ByteBuffer} buf
	TLV.readTLV = function (buf) {
		var type = buf.readShort(), 
			len = buf.readShort(), 
			val = buf.readBytes(len);
		return new TLV(type, len, val);
	};

	var Type = {
		Data: Data,
		MPI: MPI,
		Pubkey: Pubkey,
		Sig: Sig,
		TLV: TLV
	};
	return Type;
}());