/**
 * JavaScript Implementation of Off-the-Record Messaging
 * http://www.cypherpunks.ca/otr/
 * See "README" for details
 * 
 * @author Khandar William
 * @namespace Otr
 * @version 0.5.0
 *
 * 2012-07-02 initial commit, some constants
 * 2012-07-19 use MIT license
 */

var Otr = Otr || (function () {
	"use strict";

	// Constants
	var _ = {
		// Message state
		MSGSTATE_PLAINTEXT: 0,
		MSGSTATE_ENCRYPTED: 1,
		MSGSTATE_FINISHED: 2,
		// Authentication state
		AUTHSTATE_NONE: 0,
		AUTHSTATE_AWAITING_DHKEY: 1,
		AUTHSTATE_AWAITING_REVEALSIG: 2,
		AUTHSTATE_AWAITING_SIG: 3,
		AUTHSTATE_V1_SETUP: 4,
		// Policies
		ALLOW_V1: 0x01,
		ALLOW_V2: 0x02,
		REQUIRE_ENCRYPTION: 0x04,
		SEND_WHITESPACE_TAG: 0x08,
		WHITESPACE_START_AKE: 0x10,
		ERROR_START_AKE: 0x20
	};
	// The four old version 1 policies
	_.NEVER = 0x00;
	_.MANUAL = (_.ALLOW_V1 | _.ALLOW_V2);
	_.OPPORTUNISTIC = (_.ALLOW_V1 | _.ALLOW_V2 | _.SEND_WHITESPACE_TAG | _.WHITESPACE_START_AKE | _.ERROR_START_AKE);
	_.ALWAYS = (_.ALLOW_V1 | _.ALLOW_V2 | _.REQUIRE_ENCRYPTION | _.WHITESPACE_START_AKE | _.ERROR_START_AKE);
	
	return _;
}());

/* components must be included in the following order:
- cryptojs components
- biginteger
- util
- type
- bytebuffer
- message
- dsa
- auth
*/