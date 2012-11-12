"use strict";
/**
 * Unit Testing Otr.Auth
 * with QUnit
 *
 * @author Khandar William
 *
 * 2012-07-06 initial commit
 * 2012-07-17 sample AKE
 * 2012-07-20 give time counter
 */

module('Auth');

function hash (s) {
	var words = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(s));
	return Otr.Util.wordArrayToByteArray(words);
}

/**/
test('Sample AKE', function () {
	var dsa = new Otr.DSA(),
		alice, bob,
		msg,
		start, end,
		sample = {
			q: '89fb9e2e61d7e7c208277622d65e51a53f44e9d3',
			p: 'b6d99db733a40b28ee50b2af461f6c2ff5b77f59f1bfbd2cc54c188f5430b8b07e4ffa0a025c75f3277212dfa62a89b99e820a2c17acf01e01c294486e07773af8407e8fe370affb8daf042c49f064e30061bf832d4204e6c85c4ae749455a3a4d7f6716a026517135709fc6a11be05f3e5c795918c349573ea32d06f093f235',
			g: '7fea71e5619ad24d2f044c3adcd9fc88875503f6fdeb2e714752ef3ecd85d19b6e0e802000d4c08a9619560585cd39fea08e9147b98d1685dece988d7ba6f0b3b636895b8ea6c980b9f3e8dfd2df265ea59c0ed7951df3a6577b24ba7a4bd71cd85ca6b8119bd6c7d787b17e601defac428b42dfe5f7dbc9a4bed97b1e50d585'
		}, sent, retrieved;

	// use sample dsa keys
	dsa.q = new Otr.BigInteger(sample.q, 16);
	dsa.p = new Otr.BigInteger(sample.p, 16);
	dsa.g = new Otr.BigInteger(sample.g, 16);
	
	alice = new Otr.Auth(dsa);
	bob = new Otr.Auth(dsa);
	// query message
	start = new Date().getTime();
	msg = alice.produceQueryMessage();
	equal(msg.type, Otr.Message.MSG_QUERY, 'query message');
	bob.consumeMessage(new Otr.Message(msg.toString()));
	ok(true, 'produce DH Commit Message took '+(new Date().getTime()-start)+'ms');
	// DH commit message
	start = new Date().getTime();
	msg = bob.reply;
	equal(msg.type, Otr.Message.MSG_DH_COMMIT, 'DH Commit message');
	alice.consumeMessage(new Otr.Message(msg.toString()));
	ok(true, 'produce DH Key Message took '+(new Date().getTime()-start)+'ms');
	// DH Key message
	start = new Date().getTime();
	msg = alice.reply;
	equal(msg.type, Otr.Message.MSG_DH_KEY, 'DH Key message');
	bob.consumeMessage(new Otr.Message(msg.toString()));
	ok(true, 'produce Reveal Signature Message took '+(new Date().getTime()-start)+'ms');
	// Reveal Signature message
	start = new Date().getTime();
	msg = bob.reply;
	equal(msg.type, Otr.Message.MSG_REVEAL_SIGNATURE, 'Reveal Signature message');
	alice.consumeMessage(new Otr.Message(msg.toString()));
	ok(true, 'produce Signature Message took '+(new Date().getTime()-start)+'ms');
	// Signature message
	start = new Date().getTime();
	msg = alice.reply;
	equal(msg.type, Otr.Message.MSG_SIGNATURE, 'Signature message');
	bob.consumeMessage(new Otr.Message(msg.toString()));
	ok(!bob.reply, 'No more reply');
	ok(true, 'verify Signature took '+(new Date().getTime()-start)+'ms');

	ok(alice.encrypted, 'Alice side is encrypted');
	ok(bob.encrypted, 'Bob side is encrypted');

	start = new Date().getTime();
	sent = 'Alabama!';
	msg = alice.produceDataMessage(sent);
	retrieved = bob.consumeDataMessage(new Otr.Message(msg.toString()));
	equal(retrieved, sent, 'Alice sent secure message to Bob: '+(new Date().getTime()-start)+'ms');

	start = new Date().getTime();
	sent = 'Africa!';
	msg = bob.produceDataMessage(sent);
	retrieved = alice.consumeDataMessage(new Otr.Message(msg.toString()));
	equal(retrieved, sent,  'Bob sent secure message to Alice: '+(new Date().getTime()-start)+'ms');
	// ok(true, 'dummy: '+((end-start)/1000)+' s');

	/*
	sent = 'Alabama2!';
	msg = alice.produceDataMessage(sent);
	console.log(msg); // 1
	retrieved = bob.consumeDataMessage(new Otr.Message(msg.toString()));
	sent = 'Africa2!';
	msg = bob.produceDataMessage(sent);
	console.log(msg); // 2
	alice.consumeDataMessage(msg);
	msg = bob.produceDataMessage(sent);
	console.log(msg); // 3
	msg = alice.produceDataMessage(sent);
	console.log(msg);// 4
	bob.consumeDataMessage(msg);
	msg = bob.produceDataMessage(sent);
	console.log(msg);//5
	alice.consumeDataMessage(msg);
	msg = bob.produceDataMessage(sent);
	console.log(msg);//6
	alice.consumeDataMessage(msg);
	msg = alice.produceDataMessage(sent);
	console.log(msg);//7
	msg = alice.produceDataMessage(sent);
	console.log(msg);//8
	*/

	start = new Date().getTime();
	msg = alice.produceDisconnectMessage();
	bob.consumeDataMessage(new Otr.Message(msg.toString()));
	ok(bob.finished, 'Alice sent disconnect message to Bob: '+(new Date().getTime()-start)+'ms');
});
/**/