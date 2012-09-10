"use strict";
/**
 * Unit Testing Otr.DSA
 * with QUnit
 *
 * @author Khandar William
 *
 * 2012-07-13 initial commit
 * 2012-07-16 validity test
 * 2012-07-17 sign & verify test
 */

module('DSA');

function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
test('Generate Param', function () {
	var dsa = new Otr.DSA(),
		start, end;

	start = new Date().getTime();
	dsa.generateParameters();
	end = new Date().getTime();
	ok(true, 'generate param took: '+((end-start)/1000)+' s');

	var p,q,g,pmin1,certain = 20;
	// validity q
	q = dsa.q;
	equal(q.bitLength(), 160, '160-bit q');
	ok(q.isProbablePrime(certain), 'q is probably prime');
	// validity p
	p = dsa.p;
	equal(p.bitLength(), 1024, '1024-bit p');
	ok(p.isProbablePrime(certain), 'p is probably prime');
	pmin1 = p.subtract(Otr.BigInteger.ONE);
	equal(pmin1.remainder(q).compareTo(Otr.BigInteger.ZERO), 0, 'q is prime factor of p-1');
	// validity g
});
/**/

/**
test('Validity', function () {
	var test = [
		{
			q:'d6861e99fd4ede7f00d82035718a4f8d95d3ba89',
			p:'c6216f0d0af5ad8d6fb0765142202181d6a4e01f678272723ab1a59f72cad172607707b0897a49e89549bc9104663180e41ceea10469b20ec414389f12e34213dea487dd23644db8568bb9e55ae73cd5609a1f035ebb14ad3be3262e67515d1a20a4406e1af143fad863c62e85d97c361840112e4d15a772f6c27cf85aece129',
			g:'248d62494807ffb5c92d5813e0cb976dcf82f3fd5fa43b2fa90c4a953a50e9a096de96e2e253b02054dda8ca91c4703b2d61ddf7490e8757e771ca1bef2942b0df01d15438cef38475ff496477c8a8b6e385c19523ca07a71ba9a6c0389eac79161db92bae4b9f17b6d6c6252624b7f8840311db8fc1af358f9825e50cd05b21'
		},
		{
			q:'c380631de76b2207195cab89421fa4fdd8d9945d',
			p:'83a1e64d1de292037f9818a196d85995d7c9da16f2a50d25e22508d42809c198acdc1a1b20bc554e9c942cc34c117c2eb84a1523764afcc5dc82b84d34d50dbcd8a23de610d077942ef335817161fcc4d605d41bde2615918ab6b3912685966e944925e05e5c50311f20866b1469eec3b49f1851431056fb1a9090fcf55402a7',
			g:'140a34e5a22d7d51eddeb42c4fea914796162c195d7964bad680bedfdca85cebd83151123d1ec4901929e9f71f64f21b7f1da5860e71bae1448b8a176f83f1f35ef255c74318c7248492f4f3ca12d39e4f8c9ec1c826125ae5661233f6017df0b913e2afcc621d85366aa6164374443ef7a12a401efad9a49958e2d7fa8ccd8'
		},
		// from http://www.i2p2.de/how_cryptography
		{
			q:'A5DFC28FEF4CA1E286744CD8EED9D29D684046B7',
			p:'9C05B2AA960D9B97B8931963C9CC9E8C3026E9B8ED92FAD0A69CC886D5BF8015FCADAE31A0AD18FAB3F01B00A358DE237655C4964AFAA2B337E96AD316B9FB1CC564B5AEC5B69A9FF6C3E4548707FEF8503D91DD8602E867E6D35D2235C1869CE2479C3B9D5401DE04E0727FB33D6511285D4CF29538D9E3B6051F5B22CC1C93'
		}
	], i, p, q, g, pmin1,
	certain = 20;

	for (i=0; i<test.length; i++) {
		p = new Otr.BigInteger(test[i].p, 16);
		q = new Otr.BigInteger(test[i].q, 16);
		// g = new Otr.BigInteger(test[i].g, 16);
		pmin1 = p.subtract(Otr.BigInteger.ONE);

		equal(p.bitLength(), 1024, '1024-bit p');
		equal(q.bitLength(), 160, '160-bit q');
		ok(p.isProbablePrime(certain), 'p is probably prime');
		ok(q.isProbablePrime(certain), 'q is probably prime');
		equal(pmin1.remainder(q).compareTo(Otr.BigInteger.ZERO), 0, 'q is prime factor of p-1');
	}
});
/**/

test('Signature', function () {
	var sample = {
		q: '80fc91e2a7cbf3ec976694b0b39bbb5db96519cd',
		p: 'e014949b21b8ce81097f128656cff3a9db176cb7506ce49edfc9b494fd38a8ec3dc9909c951a4825d7f5b971e41df2adac096bab6b6dbc67dd6697fdc02ae4da59f28756e760e0e0ad82d6e9be5da14e718297f98e610260b4ca5c8a8dc52ca6a5e2a68ee281a84b99933898b7f69e88dc34130ae3f17e2e25f2477d69d6a58f',
		g: '2ea1023e303b51f9989b673c864af0180d114690277a4e6e923951325cf6bc2a9956fda5ac20ae5e8be50fc0fb75690b8c3d4c177b3461cf4c2d47d65d0736f2648cfb643284dc24a6335ae9ff314cff36c9807fe76e301d24c82f2d40257b6cf3b50e0efc0923e5399d278cea24ebf9f03c9066b5615c57129fafc62725867a'
	},
	dsa = new Otr.DSA(), dsa2,
	message = [], tries = 5, len,
	sign;

	dsa.q = new Otr.BigInteger(sample.q, 16);
	dsa.p = new Otr.BigInteger(sample.p, 16);
	dsa.g = new Otr.BigInteger(sample.g, 16);
	dsa2 = dsa.clone();
	// x y
	dsa.generateKey();
	dsa2.y = dsa.y.clone();

	while (tries--) {
		message = [];
		len = 1000;
		// random message
		while (len--) {
			message.push(getRandomInt(1, 255));
		}
		sign = dsa.generateSignature(message);
		ok(dsa.verifySignature(message, sign.r, sign.s), 'message verified');
		ok(dsa2.verifySignature(message, sign.r, sign.s), 'message verified by public key only');
		// console.log(sign.r.toByteArray());
		// console.log(sign.s.toByteArray());
	}
});