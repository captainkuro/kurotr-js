"use strict";
/**
 * Unit Testing Otr.Communication
 * with QUnit
 *
 * @author Khandar William
 *
 * 2012-09-24 initial commit
 */

module('Communication');

var start;
function log_start() {
	start = new Date().getTime();
}
function log_finish(text) {
	console.log(text+':'+(new Date().getTime() - start));
}

test('AKE', function () {
	var dsa = new Otr.DSA(),
		alice, bob,
		sample = {
			q: '89fb9e2e61d7e7c208277622d65e51a53f44e9d3',
			p: 'b6d99db733a40b28ee50b2af461f6c2ff5b77f59f1bfbd2cc54c188f5430b8b07e4ffa0a025c75f3277212dfa62a89b99e820a2c17acf01e01c294486e07773af8407e8fe370affb8daf042c49f064e30061bf832d4204e6c85c4ae749455a3a4d7f6716a026517135709fc6a11be05f3e5c795918c349573ea32d06f093f235',
			g: '7fea71e5619ad24d2f044c3adcd9fc88875503f6fdeb2e714752ef3ecd85d19b6e0e802000d4c08a9619560585cd39fea08e9147b98d1685dece988d7ba6f0b3b636895b8ea6c980b9f3e8dfd2df265ea59c0ed7951df3a6577b24ba7a4bd71cd85ca6b8119bd6c7d787b17e601defac428b42dfe5f7dbc9a4bed97b1e50d585'
		};

	// use sample dsa keys
	dsa.q = new Otr.BigInteger(sample.q, 16);
	dsa.p = new Otr.BigInteger(sample.p, 16);
	dsa.g = new Otr.BigInteger(sample.g, 16);

	alice = new Otr.Communication(dsa, function (text, other) {
		console.log('Alice get:'+text);
	}, function (text, other) {
		bob.receiveMessage(text);
	});

	bob = new Otr.Communication(dsa, function (text, other) {
		console.log('Bob get:'+text);
	}, function (text, other) {
		alice.receiveMessage(text);
	});

	alice.sendMessage('Alo');
	log_start();
	bob.startAKE(function () {
		log_finish('AKE');
		console.log('AKE finished');
		console.log(alice.auth.encrypted);
		console.log(bob.auth.encrypted);

		log_start();
		alice.sendMessage('This is encrypted');
		log_finish('Alice send OTR');
		log_start();
		bob.sendMessage('I know right?');
		log_finish('bob send OTR');
		log_start();
		alice.sendMessage('How is this even possible?');
		log_finish('Alice send OTR');
		log_start();
		bob.sendMessage('Ask the man');
		log_finish('bob send OTR');
		log_start();
		alice.sendMessage('This is encrypted');
		log_finish('Alice send OTR');
		log_start();
		bob.sendMessage('I know right?');
		log_finish('bob send OTR');
		log_start();
		alice.sendMessage('How is this even possible?');
		log_finish('Alice send OTR');
		log_start();
		bob.sendMessage('Ask the man');
		log_finish('bob send OTR');
	});
	ok(true, 'dummy');
});