/**
 * OTR Auth
 * responsible for consuming and producing keys for authentication
 * Implementing http://www.cypherpunks.ca/otr/Protocol-v2-3.1.0.html
 * 
 * @author Khandar William
 * @namespace Otr
 * @require CryptoJS.AES, CryptoJS.SHA256, CryptoJS.HmacSHA256
 * @require CryptoJS.mode.CTR, CryptoJS.pad.NoPadding
 *
 * 2012-07-** initial commit, sketch the state transition, use Type, variable name prefix,
 *            generateAuthKeys, produceRevealSignature, correct IV, some produceSignature,
 *            produceSignature, verifySignature, BUG: when AKE with Spark got pubB failed at produceSignatureMessage,
 *            now AKE is success, drafting SessionKeys, drafting KeyManager, working data message, 
 *            dhkey rotation data message
 * 2012-08-02 add produceDisconnectMessage, oldMacKeys draft
 * 2012-09-17 AKE special case
 */

Otr.Auth = (function () {
	"use strict";

	// Shortcut
	var Message = Otr.Message,
		BigInteger = Otr.BigInteger,
		Util = Otr.Util,
		Type = Otr.Type,
		ByteBuffer = Otr.ByteBuffer,
		
		// Constants
		DH_G = new BigInteger('2'),
		DH_MOD = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16),
		DH_MOD_MIN_2 = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFD", 16),
		TWO = new BigInteger('2'),
		CTR_ZERO = Util.createIV(128), // AKE uses counter/IV with all bytes 0
		// Authentication state
		AUTHSTATE_NONE = 0,
		AUTHSTATE_AWAITING_DHKEY = 1,
		AUTHSTATE_AWAITING_REVEALSIG= 2,
		AUTHSTATE_AWAITING_SIG = 3,
		AUTHSTATE_V1_SETUP = 4;

	// Global functions
	// Generates DH public/private key pair
	function generateDHKey() {
		var biX = BigInteger.generate(320), // random 320-bit integer
			biGx = Util.powMod(DH_G, biX, DH_MOD),//DH_G.modPow(biX, DH_MOD),
			mpiGx = new Type.MPI(biGx);
		return {
			biPrivate: biX, // DH private key, BigInteger
			mpiPublic: mpiGx // DH public key, MPI
		};
	}
	// For debugging
	var stime = {};
	function log_start(text) {
		stime[text] = new Date().getTime();
	}
	function log_end(text) {
		var ms = new Date().getTime() - stime[text];
		if (console) console.log(text+': '+ms+'ms');
	}


	/**
	 * @param {String} myId my identifier/nickname
	 * @param {String} targetId chat buddy identifier/nickname
	 * @param {DSAKey} dsa contain DSA parameters, to be cloned, must already have parameter
	 */
	function Auth(myId, targetId, dsa) {
		this.myId = myId;
		this.targetId = targetId;
		// clone DSA param
		this.dsa = dsa.clone();
		// generate DSA key pair
		this.dsa.generateKey();
		// create pubkey
		this.pubkey = new Type.Pubkey(
			new Type.MPI(this.dsa.p),
			new Type.MPI(this.dsa.q),
			new Type.MPI(this.dsa.g),
			new Type.MPI(this.dsa.y)
		);
	}

	Auth.prototype = {
		state: AUTHSTATE_NONE,
		encrypted: false,
		reply: false, // set with msg to reply
		secret: {}, // store temporary keys in AKE process
		theirPubkey: null,
		keyManager: null, // instance of KeyManager
		finished: false, // if true, the other side is terminating encrypted session

		/* variable name prefix:
		bi- BigInteger
		mpi- Type.MPI
		data- Type.Data
		wa- CryptoJS.lib.WordArray
		enc- CryptoJS.lib.CipherParams and is encrypted
		*/
		// @param {Message} msg

		// Alice
		produceQueryMessage: function () {
			var msg = new Message('?OTRv2?');

			return msg;
		},

		// Bob
		consumeQueryMessage: function (msg) {
			this.reply = this.produceDHCommitMessage();
			this.state = AUTHSTATE_AWAITING_DHKEY;
		},

		// Bob
		produceDHCommitMessage: function () {
			var msg = new Message(''),
				biR = BigInteger.generate(128), 
				dhkey = generateDHKey(),
				biX = dhkey.biPrivate, 
				mpiGx = dhkey.mpiPublic,
				waGxmpi, waR,
				encGx, waHashgx;

			waGxmpi = Util.byteArrayToWordArray(mpiGx.toBytes());
			waR = CryptoJS.enc.Hex.parse(biR.toString(16));
			encGx = CryptoJS.AES.encrypt(waGxmpi, waR, {mode: CryptoJS.mode.CTR, iv: CTR_ZERO, padding: CryptoJS.pad.NoPadding});
			waHashgx = CryptoJS.SHA256(waGxmpi);
			
			msg.type = Message.MSG_DH_COMMIT;
			msg.dataEncryptedGx = new Type.Data(Util.wordArrayToByteArray(encGx.ciphertext));
			msg.dataHashedGx    = new Type.Data(Util.wordArrayToByteArray(waHashgx));

			// save important keys
			this.secret.biX   = biX;
			this.secret.mpiR  = new Type.MPI(biR);
			this.secret.mpiGx = mpiGx;

			this.secret.lastDHCommitMessage = msg;
			return msg;
		},

		// Alice
		consumeDHCommitMessage: function (msg) {
			switch (this.state) {
				case AUTHSTATE_NONE:
				case AUTHSTATE_AWAITING_SIG:
					// grab encrypted gX & hashed gX
					this.secret.dataEncryptedGx = msg.dataEncryptedGx;
					this.secret.dataHashedGx = msg.dataHashedGx;

					this.reply = this.produceDHKeyMessage();
					this.state = AUTHSTATE_AWAITING_REVEALSIG;
					break;
				case AUTHSTATE_AWAITING_DHKEY:
					// It indicates that you have already sent a D-H Commit message to your correspondent, 
					// but that he either didn't receive it, or just didn't receive it yet, and has sent you one as well
					// The symmetry will be broken by comparing the hashed gx you sent in your D-H Commit Message with the one you received, 
					// considered as 32-byte unsigned big-endian values. 
					var biMyHash = BigInteger.fromMagnitude(1, this.secret.lastDHCommitMessage.dataHashedGx.getValue()),
						biTheirHash = BigInteger.fromMagnitude(1, msg.dataHashedGx.getValue());

					// If yours is the higher hash value:
					if (biMyHash.compareTo(biTheirHash) > 0) {
						// Ignore the incoming D-H Commit message, but resend your D-H Commit message.
						this.reply = this.secret.lastDHCommitMessage;
					} else {
					// Otherwise:
    					// Forget your old gx value that you sent (encrypted) earlier, and pretend you're in AUTHSTATE_NONE; 
    					// i.e. reply with a D-H Key Message, and transition authstate to AUTHSTATE_AWAITING_REVEALSIG. 
    					this.secret.dataEncryptedGx = msg.dataEncryptedGx;
						this.secret.dataHashedGx = msg.dataHashedGx;

						this.reply = this.produceDHKeyMessage();
						this.state = AUTHSTATE_AWAITING_REVEALSIG;
					}
					break;
				case AUTHSTATE_AWAITING_REVEALSIG:
					// Retransmit your D-H Key Message (the same one as you sent when you entered AUTHSTATE_AWAITING_REVEALSIG). 
					this.reply = this.secret.lastDHKeyMessage;
					// Forget the old D-H Commit message, and use this new one instead
					this.secret.dataEncryptedGx = msg.dataEncryptedGx;
					this.secret.dataHashedGx = msg.dataHashedGx;
					break;
			}
		},

		// Alice
		produceDHKeyMessage: function () {
			var msg = new Message(''),
				dhkey = generateDHKey(),
				biY = dhkey.biPrivate;

			msg.type  = Message.MSG_DH_KEY;
			msg.mpiGy = dhkey.mpiPublic;

			this.secret.biY   = biY;
			this.secret.mpiGy = msg.mpiGy;

			this.secret.lastDHKeyMessage = msg;
			return msg;
		},

		// Bob
		consumeDHKeyMessage: function (msg) {
			switch (this.state) {
				case AUTHSTATE_AWAITING_DHKEY:
					// grab gY
					this.secret.mpiGy = msg.mpiGy;
					
					this.reply = this.produceRevealSignatureMessage();
					this.state = AUTHSTATE_AWAITING_SIG;
					break;
				case AUTHSTATE_AWAITING_SIG:
					// If this D-H Key message is the same the one you received earlier (when you entered AUTHSTATE_AWAITING_SIG):
					if (this.secret.mpiGy.equals(msg.mpiGy)) {
						// Retransmit your Reveal Signature Message.
						this.reply = this.lastRevealSignatureMessage;
					} else {
					// Otherwise:
						// Ignore the message. 
					}
					break;
				default:
					// Ignore the message. 
			}
		},

		// Computes two AES keys c, c' and four MAC keys m1, m1', m2, m2' by hashing s in various ways
		// hint: AuthInfo.java :: computeAuthKeys()
		// @param {BigInteger} biS Shared diffie-hellman key
		// @return {Object} With key: ssid, c, cp, m1, m1p, m2, m2p; all in WordArray
		_generateAuthKeys: function (biS) {
			var seed = new Type.MPI(biS).toBytes(),
				waTemp,
				waSsid, waC, waCp, waM1, waM1p, waM2, waM2p;

			seed.unshift(0x00); // add 1 byte at the beginning

			// For a given byte b, define h2(b) to be the 256-bit output of the SHA256 hash of the (5+len) bytes consisting of the byte b followed by secbytes.
			// @return {CryptoJS.lib.WordArray}
			function h2(b) {
				seed[0] = b;
				return CryptoJS.SHA256(Util.byteArrayToWordArray(seed));
			}

			// Let ssid be the first 64 bits of h2(0x00).
			waSsid = h2(0x00);
			waSsid.sigBytes = 8;
			// Let c be the first 128 bits of h2(0x01), and let c' be the second 128 bits of h2(0x01).
			waTemp = h2(0x01);
			waC = CryptoJS.lib.WordArray.create(waTemp.words.slice(0, 4), 16);
			waCp = CryptoJS.lib.WordArray.create(waTemp.words.slice(4, 8), 16);
			// Let m1 be h2(0x02).
			waM1 = h2(0x02);
			// Let m2 be h2(0x03).
			waM2 = h2(0x03);
			// Let m1' be h2(0x04).
			waM1p = h2(0x04);
			// Let m2' be h2(0x05).
			waM2p = h2(0x05);

			return {
				ssid: waSsid,
				c: waC,
				cp: waCp,
				m1: waM1,
				m1p: waM1p,
				m2: waM2,
				m2p: waM2p
			};
		},

		// MACm1(gx, gy, pubB, keyidB)
		// MACm1'(gy, gx, pubA, keyidA)
		// @return {WordArray}
		_computeM: function (mpiG1, mpiG2, pubkey, keyid, waKey) {
			var buf = new ByteBuffer(), waHmac;
			// hint: AuthInfo.java :: calculatePubkeyAuth()
			// gx/gy (MPI)
			buf.writeMPI(mpiG1);
			// gy/gx (MPI)
			buf.writeMPI(mpiG2);
			// pubB/pubA (PUBKEY)
			buf.writeBytes(pubkey.toBytes());
			// keyidB/keyidA (INT) 
			buf.writeUInt(keyid);
			// Compute the 32-byte value MB/MA to be the SHA256-HMAC of the above data, using the key m1/m1'
			waHmac = CryptoJS.HmacSHA256(buf.toWordArray(), waKey);
			return waHmac;
		},

		// pubB, keyidB, sigB(MB)
		// pubA, keyidA, sigA(MA)
		// @return {WordArray}
		_computeX: function (pubkey, keyid, dsa, waM) {
			var buf = new ByteBuffer(), sign, sigX;
			// hint: AuthInfo.java :: calculatePubkeyAuth()
			// Let XB/XA be the following structure:
			// pubB/pubA (PUBKEY)
			buf.writeBytes(pubkey.toBytes());
			// keyidB/keyidA (INT)
			buf.writeUInt(keyid);
			// sigB(MB)/sigA(MA) (SIG)
			sign = dsa.generateSignature(Util.wordArrayToByteArray(waM));
			sigX = new Type.Sig(sign.r, sign.s);
			buf.writeBytes(sigX.toBytes());
			return buf.toWordArray();
		},

		// Bob
		produceRevealSignatureMessage: function () {
			// assuming this.secret has: 
			// from produceDHCommit: biX, mpiR, mpiGx
			// from consumeDHKey: mpiGy

			var biTemp, biS, waKeys, keyidB, 
				waMB, waXB,
				encSign, dataEncSign, waHmac,
				msg = new Message('');

			// Verifies that Alice's gy is a legal value (2 <= gy <= modulus-2)
			biTemp = this.secret.mpiGy.toBigInteger();
			if (biTemp.compareTo(TWO) < 0 || biTemp.compareTo(DH_MOD_MIN_2) > 0) throw new Error('Invalid Gy received');

			// Computes s = (gy)x
			// biS = this.secret.mpiGy.toBigInteger().modPow(this.secret.biX, DH_MOD); // shared diffie hellman key
			biS = Util.powMod(this.secret.mpiGy.toBigInteger(), this.secret.biX, DH_MOD); // shared diffie hellman key
			
			// Computes two AES keys c, c' and four MAC keys m1, m1', m2, m2' by hashing s in various ways
			waKeys = this._generateAuthKeys(biS);

			// Picks keyidB, a serial number for his D-H key gx
			keyidB = 1; // our keyid starts at 1

			// Computes MB = MACm1(gx, gy, pubB, keyidB)
			waMB = this._computeM(this.secret.mpiGx, this.secret.mpiGy, this.pubkey, keyidB, waKeys.m1);
			
			// Computes XB = pubB, keyidB, sigB(MB)
			waXB = this._computeX(this.pubkey, keyidB, this.dsa, waMB);
			
			// Encrypt XB using AES128-CTR with key c and initial counter value 0.
			encSign = CryptoJS.AES.encrypt(waXB, waKeys.c, {mode: CryptoJS.mode.CTR, iv: CTR_ZERO, padding: CryptoJS.pad.NoPadding});
			// Encode this encrypted value as the DATA field.
			dataEncSign = new Type.Data(Util.wordArrayToByteArray(encSign.ciphertext));
			
			// hint: AuthInfo.java :: createRevealsigMessage()
			// This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2.
			waHmac = CryptoJS.HmacSHA256(Util.byteArrayToWordArray(dataEncSign.toBytes()), waKeys.m2);
			waHmac.sigBytes = 20;

			// save important keys
			this.secret.waKeys = waKeys;
			this.secret.biS    = biS;
			this.secret.keyidB = keyidB;

			// Sends Alice r, AESc(XB), MACm2(AESc(XB))
			msg.type = Message.MSG_REVEAL_SIGNATURE;
			msg.dataRevealedKey        = new Type.Data(this.secret.mpiR.getValue());
			msg.dataEncryptedSignature = dataEncSign;
			msg.macSignature           = Util.wordArrayToByteArray(waHmac);

			this.secret.lastRevealSignatureMessage = msg;
			return msg;
		},

		// Alice
		consumeRevealSignatureMessage: function (msg) {
			switch (this.state) {
				case AUTHSTATE_AWAITING_REVEALSIG:
					this.secret.dataRevealedKey = msg.dataRevealedKey;
					this.secret.dataEncryptedSignature = msg.dataEncryptedSignature;
					this.secret.macSignature = msg.macSignature;
					
					this.reply = this.produceSignatureMessage();
					this.state = AUTHSTATE_NONE;
					// Transition msgstate to MSGSTATE_ENCRYPTED.
					this.encrypted = true;
					break;
				default:
					// Ignore the message. 
			}
		},

		// Alice
		produceSignatureMessage: function () {
			// assuming this.secret has:
			// from consumeDHCommit: dataEncryptedGx, dataHashedGx
			// from produceDHKey: biY, mpiGy
			// from consumeRevealSignature: dataRevealedKey, dataEncryptedSignature, macSignature

			var waR, encGx, waGxmpi, waHashgx, biGx,
				biS, waKeys, waHmac,
				encSign, waXB, pubB, keyidB, sigB,
				mpiGx, waMB, dsaVerify,
				keyidA, waMA, waXA,
				encSign, dataEncSign, waHmac,
				buf, msg = new Message('');

			// Uses r to decrypt the value of gx sent earlier
			waR = Util.byteArrayToWordArray(this.secret.dataRevealedKey.getValue());
			encGx = CryptoJS.lib.CipherParams.create({
				ciphertext: Util.byteArrayToWordArray(this.secret.dataEncryptedGx.getValue())
			});
			waGxmpi = CryptoJS.AES.decrypt(encGx, waR, {mode: CryptoJS.mode.CTR, iv: CTR_ZERO, padding: CryptoJS.pad.NoPadding});
			
			// Verifies that HASH(gx) matches the value sent earlier
			Util.correctWordsLength(waGxmpi); // SHA256 disregard sigBytes
			waHashgx = CryptoJS.SHA256(waGxmpi);
			if (!Util.bytesEqual(this.secret.dataHashedGx.getValue(), Util.wordArrayToByteArray(waHashgx))) throw new Error('HASH(gx) not match');
			
			// Verifies that Bob's gx is a legal value (2 <= gx <= modulus-2)
			biGx = new Type.MPI(Util.wordArrayToByteArray(waGxmpi).slice(4)).toBigInteger(); // slice(4) -> skip 4 byte of length
			if (biGx.compareTo(TWO) < 0 || biGx.compareTo(DH_MOD_MIN_2) > 0) throw new Error('Invalid Gx received');

			// Computes s = (gx)y (note that this will be the same as the value of s Bob calculated)
			// biS = biGx.modPow(this.secret.biY, DH_MOD); // shared diffie hellman key
			biS = Util.powMod(biGx, this.secret.biY, DH_MOD); // shared diffie hellman key
			
			// Computes two AES keys c, c' and four MAC keys m1, m1', m2, m2' by hashing s in various ways (the same as Bob)
			waKeys = this._generateAuthKeys(biS);

			// Uses m2 to verify MACm2(AESc(XB))
			waHmac = CryptoJS.HmacSHA256(Util.byteArrayToWordArray(this.secret.dataEncryptedSignature.toBytes()), waKeys.m2);
			waHmac.sigBytes = 20;
			if (!Util.bytesEqual(this.secret.macSignature, Util.wordArrayToByteArray(waHmac))) throw new Error('Invalid MAC-ed signature');

			// Uses c to decrypt AESc(XB) to obtain XB = pubB, keyidB, sigB(MB)
			encSign = CryptoJS.lib.CipherParams.create({
				ciphertext: Util.byteArrayToWordArray(this.secret.dataEncryptedSignature.getValue())
			});
			waXB = CryptoJS.AES.decrypt(encSign, waKeys.c, {mode: CryptoJS.mode.CTR, iv: CTR_ZERO, padding: CryptoJS.pad.NoPadding });
			buf = ByteBuffer.fromByteArray(Util.wordArrayToByteArray(waXB));
			pubB = Type.Pubkey.readPubkey(buf);
			keyidB = buf.readUInt();
			sigB = Type.Sig.readSig(buf);
			
			// Computes MB = MACm1(gx, gy, pubB, keyidB)
			mpiGx = new Type.MPI(biGx);
			waMB = this._computeM(mpiGx, this.secret.mpiGy, pubB, keyidB, waKeys.m1);

			// Uses pubB to verify sigB(MB)
			dsaVerify = new Otr.DSA();
			dsaVerify.p = pubB.p.toBigInteger();
			dsaVerify.q = pubB.q.toBigInteger();
			dsaVerify.g = pubB.g.toBigInteger();
			dsaVerify.y = pubB.y.toBigInteger();
			if (!dsaVerify.verifySignature(Util.wordArrayToByteArray(waMB), sigB.r, sigB.s)) throw new Error('pubB verify signature failed');

			// Picks keyidA, a serial number for her D-H key gy
			keyidA = 1; // our keyid starts at 1

			// Computes MA = MACm1'(gy, gx, pubA, keyidA)
			waMA = this._computeM(this.secret.mpiGy, mpiGx, this.pubkey, keyidA, waKeys.m1p);

			// Computes XA = pubA, keyidA, sigA(MA)
			waXA = this._computeX(this.pubkey, keyidA, this.dsa, waMA);
			
			// Encrypt XA using AES128-CTR with key c' and initial counter value 0.
			encSign = CryptoJS.AES.encrypt(waXA, waKeys.cp, {mode: CryptoJS.mode.CTR, iv: CTR_ZERO, padding: CryptoJS.pad.NoPadding});
			// Encode this encrypted value as the DATA field.
			dataEncSign = new Type.Data(Util.wordArrayToByteArray(encSign.ciphertext));

			// This is the SHA256-HMAC-160 (that is, the first 160 bits of the SHA256-HMAC) of the encrypted signature field (including the four-byte length), using the key m2'.
			waHmac = CryptoJS.HmacSHA256(Util.byteArrayToWordArray(dataEncSign.toBytes()), waKeys.m2p);
			waHmac.sigBytes = 20;
			
			// Alice's part in AKE in finished, 
			this.theirPubkey = pubB;
			this.keyManager = new KeyManager(this.secret.biY, this.secret.mpiGy, mpiGx);

			this.secret = {}; // dispose old keys
			
			// Sends Bob AESc'(XA), MACm2'(AESc'(XA))
			msg.type = Message.MSG_SIGNATURE;
			msg.dataEncryptedSignature = dataEncSign;
			msg.macSignature           = Util.wordArrayToByteArray(waHmac);
			return msg;
		},

		// Bob
		consumeSignatureMessage: function (msg) {
			switch (this.state) {
				case AUTHSTATE_AWAITING_SIG:
					this.secret.dataEncryptedSignature = msg.dataEncryptedSignature;
					this.secret.macSignature = msg.macSignature;

					this.verifySignatureMessage(msg);
					this.state = AUTHSTATE_NONE;
					// Transition msgstate to MSGSTATE_ENCRYPTED.
					this.encrypted = true;
					break;
				default:
					// Ignore the message. 
			}
		},

		// Bob, last stage of AKE
		verifySignatureMessage: function () {
			// assuming this.secret has: 
			// from produceDHCommit: biX, mpiR, mpiGx
			// from consumeDHKey: mpiGy
			// from produceRevealSignatureMessage: waKeys, biS, keyidB
			// from consumeSignatureMessage: dataEncryptedSignature, macSignature

			var waHmac, encSign, buf,
				waXA, pubA, keyidA, sigA,
				waMA, dsaVerify;

			// Uses m2' to verify MACm2'(AESc'(XA))
			waHmac = CryptoJS.HmacSHA256(Util.byteArrayToWordArray(this.secret.dataEncryptedSignature.toBytes()), this.secret.waKeys.m2p);
			waHmac.sigBytes = 20;
			if (!Util.bytesEqual(this.secret.macSignature, Util.wordArrayToByteArray(waHmac))) throw new Error('Invalid MAC-ed signature');

			// Uses c' to decrypt AESc'(XA) to obtain XA = pubA, keyidA, sigA(MA)
			encSign = CryptoJS.lib.CipherParams.create({
				ciphertext: Util.byteArrayToWordArray(this.secret.dataEncryptedSignature.getValue())
			});
			waXA = CryptoJS.AES.decrypt(encSign, this.secret.waKeys.cp, {mode: CryptoJS.mode.CTR, iv: CTR_ZERO, padding: CryptoJS.pad.NoPadding });
			buf = ByteBuffer.fromByteArray(Util.wordArrayToByteArray(waXA));
			pubA = Type.Pubkey.readPubkey(buf);
			keyidA = buf.readUInt();
			sigA = Type.Sig.readSig(buf);
			
			// Computes MA = MACm1'(gy, gx, pubA, keyidA)
			waMA = this._computeM(this.secret.mpiGy, this.secret.mpiGx, pubA, keyidA, this.secret.waKeys.m1p);
			
			// Uses pubA to verify sigA(MA)
			dsaVerify = new Otr.DSA();
			dsaVerify.p = pubA.p.toBigInteger();
			dsaVerify.q = pubA.q.toBigInteger();
			dsaVerify.g = pubA.g.toBigInteger();
			dsaVerify.y = pubA.y.toBigInteger();
			if (!dsaVerify.verifySignature(Util.wordArrayToByteArray(waMA), sigA.r, sigA.s)) throw new Error('pubA verify signature failed');
			
			// Bob's part in AKE in finished, 
			this.theirPubkey = pubA;
			this.keyManager = new KeyManager(this.secret.biX, this.secret.mpiGx, this.secret.mpiGy);

			this.secret = {}; // dispose old keys
		},

		// String msg, UInt ourkeyid, UInt theirkeyid, MPI nextdh, byte[8] ctr, Data encaes
		_computeT: function (ourkeyid, theirkeyid, nextdh, ctr, encaes) {
			var buf = new ByteBuffer();
			// simply concatenate all
			buf.writeShort(0x02); // protocol version
			buf.writeByte(Message.MSG_DATA);
			buf.writeByte(0x00); // flags
			buf.writeUInt(ourkeyid);
			buf.writeUInt(theirkeyid);
			buf.writeMPI(nextdh);
			buf.writeBytes(ctr);
			buf.writeData(encaes);
			return buf.toWordArray();
		},

		// Alice|Bob
		// @param {String} plaintext
		produceDataMessage: function (plaintext) {
			if (!this.encrypted) throw new Error("It's not encrypted");
			// Suppose Alice has a message (msg) to send to Bob.
			var sess, oldmackeys, waT,
				baMsg, encMsg, dataEncMsg,
				waHmac,
				msg = new Message('');

			// Picks the most recent of her own D-H encryption keys that Bob has acknowledged receiving (by using it in a Data Message, or failing that, in the AKE). Let keyA by that key, and let keyidA be its serial number.
			// If the above key is Alice's most recent key, she generates a new D-H key (next_dh), to get the serial number keyidA+1.
			// Picks the most recent of Bob's D-H encryption keys that she has received from him (either in a Data Message or in the AKE). Let keyB by that key, and let keyidB be its serial number.
			// Uses Diffie-Hellman to compute a shared secret from the two keys keyA and keyB, and generates the sending AES key, ek, and the sending MAC key, mk, as detailed below.
			sess = this.keyManager.sessKeys[1][0];

			// Collects any old MAC keys that were used in previous messages, but will never again be used (because their associated D-H keys are no longer the most recent ones) into a list, oldmackeys.
			oldmackeys = new Type.Data(this.keyManager.oldMacKeys());

			// Picks a value of the counter, ctr, so that the triple (keyA, keyB, ctr) is never the same for more than one Data Message Alice sends to Bob.
			sess.incCtrSend();

			// Compute AES-CTRek,ctr(msg)
			baMsg = Util.stringToByteArray(plaintext);
			encMsg = CryptoJS.AES.encrypt(Util.byteArrayToWordArray(baMsg), sess.waSendAesKey, {mode: CryptoJS.mode.CTR, iv: Util.createIV(128, sess.ctrSend), padding: CryptoJS.pad.NoPadding});
			dataEncMsg = new Type.Data(Util.wordArrayToByteArray(encMsg.ciphertext));

			// Computes TA = (keyidA, keyidB, next_dh, ctr, AES-CTRek,ctr(msg))
			waT = this._computeT(
				this.keyManager.ourKeyid-1, this.keyManager.theirKeyid, 
				this.keyManager.mpiOurY, sess.ctrSend, dataEncMsg
			);

			// Compute SHA1-HMACmk(TA)
			waHmac = CryptoJS.HmacSHA1(waT, sess.waSendMacKey);

			// Sends Bob TA, MACmk(TA), oldmackeys
			msg.type = Message.MSG_DATA;
			msg.byteFlags = 0x00;
			msg.intSenderKeyid       = this.keyManager.ourKeyid-1;
			msg.intRecipientKeyid    = this.keyManager.theirKeyid;
			msg.mpiDHy               = this.keyManager.mpiOurY;
			msg.ctr                  = sess.ctrSend;
			msg.dataEncryptedMessage = dataEncMsg;
			msg.macAuthenticator     = Util.wordArrayToByteArray(waHmac);
			msg.dataOldMacKeys       = oldmackeys;

			return msg;
		},

		// Bob|Alice
		// @param {Message} msg Type is Message.MSG_DATA
		// @return {String}
		consumeDataMessage: function (msg) {
			if (!this.encrypted) return this.reply = new Message('?OTR Error:an unreadable encrypted message was received');

			/* Verify the information (MAC, keyids, ctr value, etc.) in the message.
				If the verification succeeds:
					Decrypt the message and display the human-readable part (if non-empty) to the user.
					Update the D-H encryption keys, if necessary.
					If you have not sent a message to this correspondent in some (configurable) time, send a "heartbeat" message, consisting of a Data Message encoding an empty plaintext. The heartbeat message should have the IGNORE_UNREADABLE flag set.
					If the received message contains a TLV type 1, forget all encryption keys for this correspondent, and transition msgstate to MSGSTATE_FINISHED.
			*/
			var difOur, difTheir, sess,
				waT, waHmac,
				encMsg, waMsg, baMsg,
				str, i, buf, tlv;
			// Uses Diffie-Hellman to compute a shared secret from the two keys labelled by keyidA and keyidB, and generates the receiving AES key, ek, and the receiving MAC key, mk, as detailed below. (These will be the same as the keys Alice generated, above.)
			difOur = this.keyManager.ourKeyid - msg.intRecipientKeyid;
			difTheir = this.keyManager.theirKeyid - msg.intSenderKeyid;
			sess = this.keyManager.sessKeys[difOur][difTheir];
			if (!sess) throw new Error('Keyid is not recognized\nOur keyid:'+this.keyManager.ourKeyid+'; Recipient keyid:'+msg.intRecipientKeyid+'\nTheir keyid:'+this.keyManager.theirKeyid+'; Sender keyid:'+msg.intSenderKeyid);

    		// Uses mk to verify MACmk(TA).
    		waT = this._computeT(
				msg.intSenderKeyid, msg.intRecipientKeyid,
				msg.mpiDHy, msg.ctr, msg.dataEncryptedMessage
			);
    		waHmac = CryptoJS.HmacSHA1(waT, sess.waRecvMacKey);
    		if (!Util.bytesEqual(Util.wordArrayToByteArray(waHmac), msg.macAuthenticator)) throw new Error('MAC verification failed');

    		// Uses ek and ctr to decrypt AES-CTRek,ctr(msg).
    		encMsg = CryptoJS.lib.CipherParams.create({
				ciphertext: Util.byteArrayToWordArray(msg.dataEncryptedMessage.getValue())
			});
			waMsg = CryptoJS.AES.decrypt(encMsg, sess.waRecvAesKey, {mode: CryptoJS.mode.CTR, iv: Util.createIV(128, msg.ctr), padding: CryptoJS.pad.NoPadding});
			baMsg = Util.wordArrayToByteArray(waMsg);
			
			// Construct plaintext
			str = '';
			i = 0;
			while (i<baMsg.length && (baMsg[i] !== 0)) {
				str += String.fromCharCode(baMsg[i++]);
			}
			// The rest of baMsg bytes after i is TLV bytes
			// process TLV
			buf = new ByteBuffer();
			buf.writeBytes(baMsg.slice(i+1));
			buf.reset();
			tlv = Type.TLV.readTLV(buf);
			if (tlv.type === Type.TLV.DISCONNECTED) {
				this.finished = true;
			}
			
    		// Check for key rotation
    		this.keyManager.processReceivedKey(msg.intRecipientKeyid, msg.intSenderKeyid, msg.mpiDHy);

			return str;
		},

		consumeMessage: function (msg) {
			this.reply = false;
			switch (msg.type) {
				case Message.MSG_QUERY:
					this.consumeQueryMessage(msg);
					break;

				case Message.MSG_DH_COMMIT:
					this.consumeDHCommitMessage(msg);
					break;

				case Message.MSG_DH_KEY:
					this.consumeDHKeyMessage(msg);
					break;

				case Message.MSG_REVEAL_SIGNATURE:
					this.consumeRevealSignatureMessage(msg);
					break;

				case Message.MSG_SIGNATURE:
					this.consumeSignatureMessage(msg);
					break;

				case Message.MSG_DATA:
					this.consumeDataMessage(msg);
					break;

				default: // PLAIN or UNKNOWN
					// Ignored
			}
		},

		// Return a Data Message with disconnect TLV
		produceDisconnectMessage: function () {
			return this.produceDataMessage(String.fromCharCode(0, 0, 1, 0, 0));
		},

		reset: function () {
			this.state = AUTHSTATE_NONE;
			this.encrypted = false;
			this.reply = false;
			this.secret = {};
			this.finished = false;
		}
	};

	// Holds session keys + ctr for specified our DH key pair and their DH public key
	function SessionKeys(biOurDh, mpiOurY, mpiTheirY) {
		// Hint: ca.uwaterloo.crysp.otr.crypt.DHSesskeys::computeSession
		var biS = Util.powMod(mpiTheirY.toBigInteger(), biOurDh, DH_MOD),//mpiTheirY.toBigInteger().modPow(biOurDh, DH_MOD),
			secbytes = new Type.MPI(biS).toBytes(),
			sendbyte, recvbyte;
		
		secbytes.unshift(0x00); // prepend 1 byte

		// For a given byte b, define h1(b) to be the 160-bit output of the SHA-1 hash of the (5+len) bytes consisting of the byte b, followed by secbytes.
		// @return {WordArray}
		function h1(b) {
			secbytes[0] = b;
			return CryptoJS.SHA1(Util.byteArrayToWordArray(secbytes));
		}
		/* Are we the "high" or "low" end of the connection? */
		if (mpiOurY.compareTo(mpiTheirY) > 0) { // high
			sendbyte = 0x01;
			recvbyte = 0x02;
		} else { // low
			sendbyte = 0x02;
			recvbyte = 0x01;
		}

		// The "sending AES key" is the first 16 bytes of h1(sendbyte).
		this.waSendAesKey = h1(sendbyte);
		this.waSendAesKey.sigBytes = 16;
		Util.correctWordsLength(this.waSendAesKey);
		// The "sending MAC key" is the 20-byte SHA-1 hash of the 16-byte sending AES key.
		this.waSendMacKey = CryptoJS.SHA1(this.waSendAesKey);
		
		// The "receiving AES key" is the first 16 bytes of h1(recvbyte).
		this.waRecvAesKey = h1(recvbyte);
		this.waRecvAesKey.sigBytes = 16;
		Util.correctWordsLength(this.waRecvAesKey);
		// The "receiving MAC key" is the 20-byte SHA-1 hash of the 16-byte receiving AES key.
		this.waRecvMacKey = CryptoJS.SHA1(this.waRecvAesKey);

		// ctrSend: CTR - 8 bytes
		this.ctrSend = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
	}

	SessionKeys.prototype = {
		incCtrSend: function () {
			for (var i = 7; i >= 0; i--) {
				this.ctrSend[i]++;
				if (this.ctrSend[i] != 0)
					break;
			}
		}
	};

	function KeyManager(biOurDh, mpiOurY, mpiTheirY) {
		var dhkey;
		// this.sessKeys is Array[2][2] of {SessionKeys}
		// sesskeys[i][j] are the session keys
	    // derived from DH key[our_keyid-i]
	    // and mpi Y[their_keyid-j] */
		this.sessKeys = new Array(2);
		this.sessKeys[0] = new Array(2);
		this.sessKeys[1] = new Array(2);
		// initial sesskeys, just after finishing AKE
		this.sessKeys[1][0] = new SessionKeys(biOurDh, mpiOurY, mpiTheirY);
		// generate new dhkey
		dhkey = generateDHKey();
		this.sessKeys[0][0] = new SessionKeys(dhkey.biPrivate, dhkey.mpiPublic, mpiTheirY);
		this.sessKeys[0][1] = null;
		this.sessKeys[1][1] = null;

		// UInt
		this.ourKeyid = 2; // karena sudah ada 2 dhkey (1 dari AKE, 1 di atas)
		this.theirKeyid = 1; // karena baru ada 1 dhkey (1 dari AKE)
		// BigInteger
		this.biOurDhKey = dhkey.biPrivate;
		this.biOurOldDhKey = biOurDh;
		// MPI
		this.mpiOurY = dhkey.mpiPublic;
		this.mpiOurOldY = mpiOurY;
		this.mpiTheirY = mpiTheirY;
		this.mpiTheirOldY = null;
	}

	KeyManager.prototype = {
		processReceivedKey: function (intRecipKeyid, intSenderKeyid, mpiSenderNewY) {
			var dhkey;
			// If the "recipient keyid" in the Data message equals our_keyid, then he's seen the public part of our most recent DH key pair, so you must securely forget our_dh[our_keyid-1], increment our_keyid, and set our_dh[our_keyid] to a new DH key pair which you generate.
			if (intRecipKeyid == this.ourKeyid) {
				// @TODO save forgotten mac keys
				this.sessKeys[1][0] = this.sessKeys[0][0];
				this.sessKeys[1][1] = this.sessKeys[0][1];
				this.ourKeyid++;
				this.biOurOldDhKey = this.biOurDhKey;
				this.mpiOurOldY = this.mpiOurY;
				// generate new dhkey
				dhkey = generateDHKey();
				this.biOurDhKey = dhkey.biPrivate;
				this.mpiOurY = dhkey.mpiPublic;
				// set new sesskeys
				if (this.mpiTheirY) {
					this.sessKeys[0][0] = new SessionKeys(dhkey.biPrivate, dhkey.mpiPublic, this.mpiTheirY);
				}
				if (this.mpiTheirOldY) {
					this.sessKeys[0][1] = new SessionKeys(dhkey.biPrivate, dhkey.mpiPublic, this.mpiTheirOldY);
				}
			}
    		// If the "sender keyid" in the Data message equals their_keyid, increment their_keyid, and set their_y[their_keyid] to the new DH pubkey specified in the Data message.
    		if (intSenderKeyid == this.theirKeyid) {
    			// @TODO save forgotten mac keys
    			this.sessKeys[0][1] = this.sessKeys[0][0];
    			this.sessKeys[1][1] = this.sessKeys[1][0];
    			this.theirKeyid++;
    			this.mpiTheirOldY = this.mpiTheirY;
    			this.mpiTheirY = mpiSenderNewY;
    			// set new sesskeys
    			this.sessKeys[0][0] = new SessionKeys(this.biOurDhKey, this.mpiOurY, mpiSenderNewY);
    			this.sessKeys[1][0] = new SessionKeys(this.biOurOldDhKey, this.mpiOurOldY, mpiSenderNewY);
    		}
		},

		// Return concatenated 20-byte values of forgotten mac keys
		// @return {Array} Array of bytes
		oldMacKeys: function () {
			return []; // @TODO
		}
	};

	return Auth;
}());