"use strict";
/** 
 * Unit Testing Otr Util
 * with QUnit
 *
 * @author Khandar William
 *
 * 2012-07-11 initial commit
 * 2012-07-18 equal bytes, correct words length
 * 2012-07-27 powMod
 */

module('Util');

function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

function sameBytes(b1, b2) {
	var i, l;
	if (b1.length !== b2.length) return false;
	for (i=0, l=b1.length; i<l; ++i) {
		if ((b1[i] & 0xFF) !== (b2[i] & 0xFF)) return false;
	}
	return true;
}

function sameWords(w1, w2) {
	var i, l;
	if (w1.length !== w2.length) return false;
	for (i=0, l=w1.length; i<l; ++i) {
		if ((w1[i] & 0xFFFFFFFF) !== (w2[i] & 0xFFFFFFFF)) return false;
	}
	return true;
}

test('byte array To WordArray', function () {
	var bytes = [],
		tries = 200, num,
		w1, b1;

	while (tries--) {
		bytes = [];
		num = 555;
		while (num--) {
			bytes.push(getRandomInt(0, 255));
		}
		w1 = Otr.Util.byteArrayToWordArray(bytes);
		b1 = Otr.Util.wordArrayToByteArray(w1);
		ok(sameBytes(b1, bytes), 'byte array is correct');
	}
});

test('WordArray To byte array', function () {
	var words = [],
		tries = 200, num,
		b1, w1;

	while (tries--) {
		words = [];
		num = 100;
		while (num--) {
			words.push(getRandomInt(0, 4294967296));
		}
		b1 = Otr.Util.wordArrayToByteArray(CryptoJS.lib.WordArray.create(words));
		w1 = Otr.Util.byteArrayToWordArray(b1);
		ok(sameWords(w1.words, words), 'word array is correct');
	}
});

test('Create IV', function () {
	var iv1 = Otr.Util.createIV(128),
		iv2 = Otr.Util.createIV(256),
		i;

	equal(iv1.sigBytes, 16, '16-bit IV');
	for (i=0; i<iv1.words.length; ++i) {
		equal(iv1.words[0], 0, 'word is zero');
	}
	equal(iv2.sigBytes, 32, '32-bit IV');
	for (i=0; i<iv2.words.length; ++i) {
		equal(iv2.words[0], 0, 'word is zero');
	}
});

test('Same Bytes', function () {
	var b1 = [100, 200, 12, 24, 48],
		b2 = [100, 200, 12, 24, -48],
		b3 = [100, -56, 12, 24, 48];

	ok(Otr.Util.bytesEqual(b1, b1), 'equal');
	ok(!Otr.Util.bytesEqual(b1, b2), 'not equal');
	ok(Otr.Util.bytesEqual(b1, b3), 'equal although negative');
});

test('Correcting WordArray Length', function () {
	var w = CryptoJS.lib.WordArray.create([1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000]);

	Otr.Util.correctWordsLength(w);
	equal(w.words.length, 9, 'word length do not change');
	w.sigBytes = 35;
	Otr.Util.correctWordsLength(w);
	equal(w.words.length, 9, '25 bytes = 9 words');
	w.sigBytes = 32;
	Otr.Util.correctWordsLength(w);
	equal(w.words.length, 8, '32 bytes = 8 words');
	w.sigBytes = 30;
	Otr.Util.correctWordsLength(w);
	equal(w.words.length, 8, '30 bytes = 8 words');
	w.sigBytes = 4;
	Otr.Util.correctWordsLength(w);
	equal(w.words.length, 1, '4 bytes = 1 words');
});

test('powMod', function () {
	var b1, b2, b3,
		modpow, powmod, bit, tries = 10;

	while (tries--) {
		bit = getRandomInt(300, 1000);
		b1 = Otr.BigInteger.generate(bit-100);
		b2 = Otr.BigInteger.generate(getRandomInt(300, 400));
		b3 = Otr.BigInteger.generate(bit);
		// console.log('b1 '+b1.bitLength());
		// console.log('b2 '+b2.bitLength());
		// console.log('b3 '+b3.bitLength());
		modpow = b1.modPow(b2, b3);
		powmod = Otr.Util.powMod(b1, b2, b3);
		// console.log('modpow '+modpow.toString(16));
		// console.log('powmod '+powmod.toString(16));
		ok(modpow.compareTo(powmod)===0, 'powMod result the same with modPow');
	}
});

/*
test('which is faster', function () {
	var bytes = [],
		tries, num,
		w1, w2, b1, b2,
		start, end;

	tries = 20000;
	start = new Date().getTime();
	while (tries--) {
		bytes = [];
		num = 500;
		while (num--) {
			bytes.push(getRandomInt(0, 255));
		}
		w1 = Otr.Util.byteArrayToWordArray(bytes);
		b1 = Otr.Util.wordArrayToByteArray(w1);
	}
	end = new Date().getTime();
	ok(true, 'byteArrayToWordArray took '+(end-start)+' milliseconds');

	tries = 20000;
	start = new Date().getTime();
	while (tries--) {
		bytes = [];
		num = 500;
		while (num--) {
			bytes.push(getRandomInt(0, 255));
		}
		w2 = Otr.Util.bytesToWords(bytes);
		b2 = Otr.Util.wordsToBytes(w2);
	}
	end = new Date().getTime();
	ok(true, 'bytesToWords took '+(end-start)+' milliseconds');
		
	ok(true);
});
*/