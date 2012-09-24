/**
 * Javascript DSA Implementation
 * source: 
 	- http://stackoverflow.com/questions/6005178/problem-in-implementing-dsa-in-java-without-cryptography-library
 	- Bouncycastle DSA Java library
 *
 * @author Khandar William
 * @namespace Otr
 * @require CryptoJS.SHA1
 * 
 * 2012-07-12 initial commit
 * 2012-07-13 try generate param method 2
 * 2012-07-16 port codes from bouncycastle to generate parameter
 * 2012-07-17 remove obsolete methods, sign&verify
 * 2012-07-23 _calculateE
 * 2012-07-24 _calculateE is deleted, sign and verify message don't need hash
 */

Otr.DSA = (function () {
	"use strict";

	var BigInteger = Otr.BigInteger,
		Util = Otr.Util,
		log = window && window.location.href.indexOf('http://localhost') !== -1; // must be FALSE for PRODUCTION

	// mimicking System.arraycopy
	function arraycopy(fromar, fromi, toar, toi, howmany) {
		for (var i = fromi, j = toi, k = 0; k < howmany; ++i, ++j, ++k) {
			toar[j] = fromar[i];
		}
	}

	function DSA() {

	}

	DSA.prototype = {
		// config
		certainty: 20,
		rand: new Otr.SecureRandom(),
		L: 1024, // length of p
		N: 160, // length of q
		// SHA1 hash, @param bytes, @return bytes
		H: function (bytes) {
			var words = CryptoJS.SHA1(Otr.Util.byteArrayToWordArray(bytes));
			return Otr.Util.wordArrayToByteArray(words);
		},

		// parameter
		q: null,
		p: null,
		g: null,
		// key pair public
		y: null,
		// key pair private
		x: null,
		// other
		k: null,

		generateParameters: function () {
			var start, end;

			start = new Date().getTime();
			try {
				this._generatePQ();
			} catch (e) {
				if (log) end = new Date().getTime();
				if (log) console.log('generate params: '+(end-start)+'ms');
				throw e;
			}
			if (log) console.log('q: '+this.q.toString(16));
			if (log) console.log('p: '+this.p.toString(16));

			this.g = this._generateG(this.p, this.q);
			if (log) console.log('g: '+this.g.toString(16));
			if (log) end = new Date().getTime();
			if (log) console.log('generate params: '+(end-start)+'ms');
		},

		generateKey: function () {
			do {
				this.x = new BigInteger(this.q.bitCount(), this.rand);
			} while ((this.x.compareTo(BigInteger.ZERO) <= 0) || (this.x.compareTo(this.q) >= 0));
			// while x <= 0 || x >= q
			// this.y = this.g.modPow(this.x, this.p);
			this.y = Util.powMod(this.g, this.x, this.p);
		},

		// port from org.bouncycastle.crypto.generators.DSAParametersGenerator
		_generatePQ: function () {
			// increment {Array of byte} buf
			function inc(buf) {
				var i, b;

				for (i = buf.length - 1; i >= 0; --i) {
					b = ((buf[i] + 1) & 0xff);
					buf[i] = b;

					if (b != 0) {
						break;
					}
				}
			}

			function logit(msg, start) {
				var end = new Date().getTime();
				console.log(msg+': '+(end-start)+'ms');
				return (end-start);
			}

			var seed = new Array(20), // random bytes
				part1, part2, offset, // another random bytes
				u = new Array(20), // candidate for q
				i, counter, k, // iterator
				q, p, // BigInteger
				n = 6, // (this.L - 1) / 160
				w = new Array(128), // candidate for p, length is this.L / 8
				x, c; // BigInteger

			// var for debugs
			var bigloop = 0;

			for (;;) {
				// debug
				if (log) console.log('bigloop:'+(++bigloop));
				
				this.rand.nextBytes(seed);
				part1 = this.H(seed);
				part2 = seed.slice(0);
				inc(part2);
				part2 = this.H(part2);

				for (i = 0; i != u.length; i++) {
					u[i] = part1[i] ^ part2[i];
				}
				u[0] |= 0x80;
				u[19] |= 0x01;

				q = BigInteger.fromMagnitude(1, u);

				if (!q.isProbablePrime(this.certainty)) {
					// console.log('q is not prime enough');
					continue; // try again with new q
				}

				offset = seed.slice(0);
				inc(offset);

				for (counter = 0; counter < 4096; ++counter) { // try finding p that fits
					for (k = 0; k < n; k++) {
						inc(offset);
						part1 = this.H(offset);
						arraycopy(part1, 0, w, w.length - (k + 1) * part1.length, part1.length);
					}
					inc(offset);
					part1 = this.H(offset);
					arraycopy(part1, part1.length - ((w.length - (n) * part1.length)), w, 0, w.length - n * part1.length);
					w[0] |= 0x80;

					x = BigInteger.fromMagnitude(1, w);
					c = x.mod(q.shiftLeft(1));
					p = x.subtract(c.subtract(BigInteger.ONE));

					if (p.bitLength() != this.L) {
						continue;
					}
					if (p.isProbablePrime(this.certainty)) {
						// we found the p and q
						if (log) console.log('found at counter:'+counter);
						this.p = p;
						this.q = q;
						return;
					}
				}
				if (log) console.log('counter over 4096');
			}
		},

		_generateG: function (p, q) {
			var aux = p.subtract(BigInteger.ONE),
				pow = aux.divide(q),
				gTemp;
			do {
				gTemp = new BigInteger(aux.bitLength(), this.rand);
			} while (gTemp.compareTo(aux) >= 0 || gTemp.compareTo(BigInteger.ONE) <= 0);
			// while (h >= p-1 || h <= 1)

			// return gTemp.modPow(pow, p);
			return Util.powMod(gTemp, pow, p);
		},

		// @param {Array} message Array of bytes
		// @return {r: BigInteger, s: BigInteger}
		generateSignature: function (message) {
			var k, r, s, h;

			// Generate a random per-message value k where 0 < k < q
			do {
				k = new BigInteger(this.q.bitLength(), this.rand);
			} while (k.compareTo(this.q) >= 0 && k.compareTo(BigInteger.ZERO) <= 0);
			// Calculate r = (g^k mod p) mod q
			// In the unlikely case that r = 0, start again with a different random k
			// r = this.g.modPow(k, this.p).mod(this.q);
			r = Util.powMod(this.g, k, this.p).mod(this.q);
			// Calculate s = (k^−1(H(m) + x*r)) mod q
			// In the unlikely case that s = 0, start again with a different random k
			// h = BigInteger.fromMagnitude(1, this.H(message));
			h = BigInteger.fromMagnitude(1, message);
			s = (k.modInverse(this.q).multiply(h.add(this.x.multiply(r)))).mod(this.q);
			// The signature is (r, s)
			return {r:r, s:s};
		},

		// @param {Array} message Array of bytes
		// @return bool
		verifySignature: function (message, r, s) {
			var v, hash, w, u1, u2;

			// Reject the signature if 0 < r < q or 0 < s < q is not satisfied.
			if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(this.q) >= 0) {
				return false;
			}
			if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(this.q) >= 0) {
				return false;
			}
			// hash = BigInteger.fromMagnitude(1, this.H(message));
			hash = BigInteger.fromMagnitude(1, message);
			// Calculate w = s^−1 mod q
			w = s.modInverse(this.q);
			// Calculate u1 = H(m)*w mod q
			u1 = hash.multiply(w).mod(this.q);
			// Calculate u2 = r*w mod q
			u2 = r.multiply(w).mod(this.q);
			// Calculate v = ((g^u1*y^u2) mod p) mod q
			// v = ((this.g.modPow(u1, this.p).multiply(this.y.modPow(u2, this.p))).mod(this.p)).mod(this.q);
			v = ((Util.powMod(this.g, u1, this.p).multiply(Util.powMod(this.y, u2, this.p))).mod(this.p)).mod(this.q);
			// The signature is valid if v = r
			return v.compareTo(r) == 0;
		},

		clone: function () {
			var k, d = new DSA();

			for (k in d) {
				if (this[k] instanceof BigInteger) {
					d[k] = this[k].clone();
				}
			}
			return d;
		}
	};

	return DSA;
}());