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
	var val1 = '123456789123456789123456789123456789',
		val2 = '94827928173849589482792817384958',
		x = new Otr.BigInteger(val1),
		y = new Otr.BigInteger(val2),
		ans,
		// precalculated result
		ansAdd = '123551617051630638712939581940841747',
		ansSub = '123361961195282939533973996306071831',
		ansX2 = '15241578780673678546105778311537878046486820281054720515622620750190521',
		ansX3 = '1881676377434183987554591832242899905854079093020664811051450059946434845350648282631554954480361860897069',
		ansMul = '11707151531573255618087027604697319172852167652986063566472291579862',
		ansDiv = '1301',
		ansMod = '85654569278473206343333705626431';

	equal(x.toString(), val1, 'x = '+val1);
	equal(y.toString(), val2, 'y = '+val2);

	ans = x.add(y);
	equal(ans.toString(), ansAdd, 'x+y='+ansAdd);

	ans = x.subtract(y);
	equal(ans.toString(), ansSub, 'x-y='+ansSub);
	
	ans = x.multiply(x);
	equal(ans.toString(), ansX2, 'x^2='+ansX2);

	ans = x.multiply(x).multiply(x);
	equal(ans.toString(), ansX3, 'x^3='+ansX3);

	ans = x.multiply(y);
	equal(ans.toString(), ansMul, 'x*y='+ansMul);

	ans = x.divide(y);
	equal(ans.toString(), ansDiv, 'x/y='+ansDiv);

	ans = x.mod(y);
	equal(ans.toString(), ansMod, 'x%y='+ansMod);

});

test('Random Generator', function () {
	var val, bits, tries = 200;
	
	while (tries--) {
		bits = getRandomInt(2, 400);
		val = Otr.BigInteger.generate(bits);
		equal(val.bitLength(), bits, 'generate '+bits+'-bit value:'+val.toString(16));
	}
});

