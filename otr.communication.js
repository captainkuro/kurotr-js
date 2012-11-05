/**
 * OTR Communication
 * Wraps the whole OTR authentication and encryption methods 
 * To simplify usage
 *
 * @author Khandar William
 * @namespace Otr
 *
 * 2012-09-21 initial commit
 * 2012-11-05 fragmentation
 */

Otr.Communication = (function () {
	"use strict";

	var Message = Otr.Message;

	/**
	 * @param {DSA|Auth} the DSA key parameters or Auth object
	 * @param {Function} display function to be called when receiving a message
	 * @param {Function} send function to be called when sending a message
	 */
	function Communication(dsa, display, send) {
		if (dsa instanceof Otr.Auth) {
			this.auth = dsa;
		} else { // dsa instanceof Otr.DSA
			this.auth = new Otr.Auth(dsa);
		}
		this.display = display;
		this.send = send;
	}

	Communication.prototype = {
		whenSecured: null, // one-time use function, called immediately after OTR is established
		fragments: [],

		/**
		 * @param {String} text either plaintext or OTR ciphertext
		 * @param {Any} other optional parameter to be sent to display function
		 */
		receiveMessage: function (text, other) {
			var msg = new Message(text),
				auth = this.auth,
				plaintext;
			if (msg.type === Message.MSG_PLAIN) {
				this.display(text, other);
			} else if (msg.type === Message.MSG_FRAGMENT) {
				var matches = msg.message.match(/^\?OTR,(\d+),(\d+),(.+)\.?,$/),
					fragI = matches[1],
					fragN = matches[2],
					fragContent = matches[3];
				this.fragments[parseInt(fragI)-1] = fragContent;
				if (fragI == fragN) {
					this.receiveMessage(this.fragments.join(''), other);
					this.fragments = []; // reset
				}
			} else {
				if (auth.encrypted && msg.type === Message.MSG_DATA) {
					// decrypt then display
					plaintext = auth.consumeDataMessage(msg);
					this.display(plaintext, other);
					if (auth.finished) {
						auth.reset();
					}
				} else { // this is AKE
					try {
						auth.consumeMessage(msg);
					} catch (e) {
						auth.reset();
					}
					if (auth.reply) {
						this.send(auth.reply.toString());
					}
					if (auth.encrypted) {
						if (this.whenSecured) this.whenSecured();
						this.whenSecured = null;
					}
				}
			}
		},

		/**
		 * @param {String} text plaintext to be sent
		 * @param {Any} other optional parameter to be sent to send function
		 */
		sendMessage: function (text, other) {
			var auth = this.auth;
			if (auth.encrypted) {
				this.send(auth.produceDataMessage(text).toString(), other);
			} else {
				this.send(text, other);
			}
		},

		/**
		 * @param {Function} whenSecured optional function to be called once OTR is established
		 */
		startAKE: function (whenSecured) {
			this.whenSecured = whenSecured;
			this.send(this.auth.produceQueryMessage().toString());
		}
	};

	return Communication;
}());