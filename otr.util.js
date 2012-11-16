/**
 * Other Functions
 *
 * @author Khandar William
 * @namespace Otr
 *
 * 2012-07-10 initial commit
 * 2012-07-12 generateProb/TruePrime
 * 2012-07-17 remove generateProb/TruePrime
 * 2012-07-18 createIV, correctWordsLength, bytesEqual
 * 2012-07-27 powMod
 */

Otr.Util = (function () {
	var Util = {
		byteArrayToWordArray: function (ba) {
			var offset = 0,
				sigBytes = ba.length,
				words = [];

			while (offset < sigBytes) {
				words.push(
					(ba[offset++] & 0xFF) << 24 |
					(ba[offset++] & 0xFF) << 16 |
					(ba[offset++] & 0xFF) << 8 |
					(ba[offset++] & 0xFF)
				);
			}
			return CryptoJS.lib.WordArray.create(words, sigBytes);
		},

		wordArrayToByteArray: function (wa) {
			var ba = [],
				i, l, word,
				remains = wa.sigBytes;

			for (i=0, l=wa.words.length; i<l; ++i) {
				word = wa.words[i];
				if (remains >= 4) {
					ba.push((word >> 24) & 0xFF);
					ba.push((word >> 16) & 0xFF);
					ba.push((word >> 8) & 0xFF);
					ba.push((word) & 0xFF);
				} else if (remains === 3) {
					ba.push((word >> 24) & 0xFF);
					ba.push((word >> 16) & 0xFF);
					ba.push((word >> 8) & 0xFF);
				} else if (remains === 2) {
					ba.push((word >> 24) & 0xFF);
					ba.push((word >> 16) & 0xFF);
				} else if (remains === 1) {
					ba.push((word >> 24) & 0xFF);
				} else {
					break;
				}
				remains -= 4;
			}
			return ba;
		},

		stringToByteArray: function (str) {
			var i, l, ba = [];

			for (i=0, l=str.length; i<l; ++i) {
				ba[i] = str.charCodeAt(i) & 0xFF;
			}
			return ba;
		},

		/**
		 * OTR use AES encryption with initial counter (IV) 0
		 * @param {Number} bit 
		 * @param {Array} tophalf Optional array of bytes as the first bytes, will be padded with 0x00 until bit length
		 * @return {CryptoJS.lib.WordArray}
		 */
		createIV: function (bit, tophalf) {
			var nbyte = Math.floor(bit/8),
				nword = Math.floor(bit/32),
				i, l, words = [];

			if (tophalf) {
				for (i=0, l=tophalf.length; i<l; i+=4) {
					words.push(
						(tophalf[i] & 0xFF) << 24 |
						(tophalf[i+1] & 0xFF) << 16 |
						(tophalf[i+2] & 0xFF) << 8 |
						(tophalf[i+3] & 0xFF)
					);
				}
				nword -= Math.ceil(tophalf.length/4);
			}
			for (i=0; i<nword; ++i) {
				words.push(0);
			}
			return CryptoJS.lib.WordArray.create(words, nbyte);
		},

		bytesEqual: function (bytes1, bytes2) {
			var len = bytes1.length;
			if (bytes1.length !== bytes2.length) return false;
			while (len--) {
				if ((bytes1[len] & 0xFF) !== (bytes2[len] & 0xFF)) return false;
			}
			return true;
		},

		// !!WARNING!! some CryptoJS methods disregard sigBytes and use words.length instead
		// known affected methods: SHA256
		// And some methods didn't trim the resulted words.length according to sigBytes
		// known affected methods: CryptoJS.AES.decrypt
		correctWordsLength: function (wa) {
			wa.words.length = Math.floor((wa.sigBytes - 1) / 4) + 1;
		},

		// Return random bytes
		// assumes ba is initialized with length
		nextBytes: function (ba) {
  			for(var i = 0; i < ba.length; ++i) ba[i] = Math.floor(Math.random() * 256);
		}
	};

	return Util;
}());
