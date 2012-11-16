"use strict";
/**
 * Unit Testing Otr.BigInteger
 * with QUnit
 *
 * @author Khandar William
 *
 * 2012-07-03 basic arithmetic test
 * 2012-07-06 test generate random bigint
 */

function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

module('BigInteger');

test('Basic Arithmetic', function () {
	var val1 = '11111111111111111111111111111111',
		val2 = '22222222222222222222222222222222',
		a = new Otr.BigInteger(val1),
		b = new Otr.BigInteger(val2),
		c = a.add(b);

	equal(a.toString(), val1, 'a = '+val1);
	equal(b.toString(), val2, 'b = '+val2);
	equal(c.toString(), '33333333333333333333333333333333', 'a+b = 33333333333333333333333333333333');
	// equal(c.negate().toString(), '-33333333333333333333333333333333', '-(a+b) = -33333333333333333333333333333333');

	a = new Otr.BigInteger(val1);
	b = new Otr.BigInteger(val2);
	c = b.subtract(a);
	equal(c.toString(), '11111111111111111111111111111111', 'b-a = 11111111111111111111111111111111');

	a = new Otr.BigInteger(val1);
	b = new Otr.BigInteger(val2);
	c = b.divide(a);
	equal(c.toString(), '2', 'b/a = 2');
	equal(b.remainder(a).toString(), '0', 'b%a = 0');
	equal(a.remainder(b).toString(), val1, 'a%b = '+val1);
});

test('Random Generator', function () {
	var val, bits, tries = 200;
	
	while (tries--) {
		bits = getRandomInt(2, 400);
		val = Otr.BigInteger.generate(bits);
		equal(val.bitLength(), bits, 'generate '+bits+'-bit value:'+val.toString(16));
	}
});

// @TODO test more complex operations
// @TODO test Otr.SecureRandom