"use strict";
/**
 * Unit Testing for Otr.Message
 * with QUnit
 *
 * @author Khandar William
 * 
 * 2012-07-04 initial commit, dummy test
 * 2012-07-05 message type checking
 */

var sample = {
	DH_COMMIT: '?OTR:AAICAAAAxKGoMrS+HAnFDRrPN284mksqE7dZZInUGfox0tJ/dHMSku8gkwLGGZX9Cjsbhkm/K29lhDGkklY+H8xhUO8IWLeOSPZ5fL/Thmx2uOnzMl4WaHWvuddvckkaKM9a2GmO++BwdUKckQUtn1efnuLci8VFf09lLeVz8tdbPsqdYOqfyxaMvI9z74sOYd4FsU+RxNUUJtZx/z+x1nEv12rKBJBFap5U3lbQdIJc/8imrTS4nfwx2p2VoXwr0XreDC0kagc1YrgAAAAgZnyDsCSWVRFaBVWkICeXvDVdyUCcIpMRplBwFu7Yk/E=.',
	DH_KEY: '?OTR:AAIKAAAAwNPeKdOYCEWRI8JunbPzMWq4/NKQN57mS0vM+0bh9W4DU2pybqU1Cmeu2UgKrP7RD3lVzj5bm3chc40qEsOQ0QDxAzzfl+WJB2Y2Qft4GY0YF6cllxg1bgmn3jFhEEocw9wFi0NF876btorli56j1ghVZpcKELYVF4S5rlM+Tz8YdjUE2Xf2+IC8m6U99Ez1IimOi/GLjNPCxzWE1Rtl9dEOborP3UXCYfunSxfYBPBvqLc+4ccQG8By5hP/Ni7smw==.',
	REV_SIGN: '?OTR:AAIRAAAAEJj3+3DmMLP5IG6ZaoD8HB0AAAHS/pKQFN4iOkseX5zbnmMywSutPWtDzTX9LPcBKjMmOxIUDrFENlhZvy7MEmLh17YUQkAfCQ5VYknzFr2xNPzJLiXdVyqA5+YFiGhc+fMFZM7qxHcZAinvLwbP9pE21fJy9sIzPAby+LjmaYCs965n17BwHmMQhg8jrlu+IdEweyeqMIvczAkDES2B1X+xelw70ymJPG5PsLfXj7n05lzoZJNI/ANc9M0pzKg03lCk4b9kwvah+yJ/IXza7oR1qoaXsgRjOy2WuApUbByxGl92HXhBCkKY2wLiec31aOY1qaBQCiPxyMX7Cfl6jr6UkSegTN129rflzgxAKyv9EuELZgnclxajjkcPLqdSvkBGDBMI3ptOwAYq/2+iFSEuKiPfQSspmyHopLQUcbM2dQR3R7ABFn3rQ2DnKCqC8xYLQpbYWhx86LVehEIx1wyNpkMnWboNDXeQGlwTtWOjdhOCYUnlCZFA2RenZLALravr7ZH7UsmZ2P5TGNO9G9V9+GPytERS5i7VJz5toRuXHIj0Q3/EBDHP5QlBlBAH9m5eIS3C7i60hWmyszVR7wJL8uS50STfyMyCY0M/GbKlMNKML8bCn3EW55VyAzFmQBIb7lgcpVBxk5b3ozzIwYeVpKiP1oAi+STi.',
	SIGN: '?OTR:AAISAAAB0iyMVsh2pDuD6cfA20hNiQnmpuKvLveyLVrJd4LXGF7i+u28z1kgW+daUGdkO3sI/i+kDb24n4sOlQbWBTzYst3YYsAKulW8Ur9cM5YWQfc2/QV25Ku9UVRSyE4BA0WMz3q6VXOgMyR/2vjA4VFnF4E/n9yo0qZFMT1M5ke0x4fJhNgtDlE+oZAkVaIQCeQodwm9Ddh++v3hNI1jcohpowcbhvrWW0O79J3I4CkEboFdx5GkqStbcZKsMhuJfHHCT9A8hMNTj2WAqi6bdsmSkeO1blqtW5OKA3wVTxBVmiWPaz8OQA83Oa4ECKy8yaO65S6NfqlZHh+1tjjqVv5K4p/EAWM5VyA6cANnfYM5aWYnJRAA6SqZOZAIslHAe24Vi/+mT+L5VQA4XBTtgXOYG9lg68KjK+KnX0sPx4eFM8GtgQBMkAd0ksj9R5J2kZjCUg4hIktQM1NA+VSKhlShjRbetWMBzwz7DCAbXoiKH9RyrAVPXgJQB9xK2ycJjv/LuHiZMLEBW5W5Xbb0a1kuowbPbF5qdIS5UvYSZ57s0wvZtbWpF9/iTnZYL+bDhWniab4Y6rULSZf1hmMdHag/dQ7vq/a9Euy20RQW7GfTZP/HkWGxGo1FDLJcLdm6Msl5mKMLeKTI0A==.',
	DATA: '?OTR:AAIDAAAAAAEAAAABAAAAwN8ksifoKXS54rClQJeW3zazRPMwfEsIAOvbJoQxbnAdokdjsX8AtEfuem12TpNuSlgJuwYtGgjrJDc+OOVsbB2c/swIJbJqOWD2uPe6dIYPHmg/HglZnDQ8WPqKlZkcMydG3gVYkjjWjJxHFEFNceU+Ylrhti/qBqmYc9f/9zkuFuGR+ECqdK0g8CRSZkFCywv3bnCxjLjpdwKXliHHfrAekqI59Bho0OdEnja/f+VQ9BgIeOuoGY9YKm/mEIBLXgAAAAAAAAABAAAAB0cAVMnyc4amCOueiKvb91Re8KlJSmTcQ/lDJwAAAAA=.'
};

module('Message');

test('Message Type Checking', function () {
	var otr = '?OTRv2?',
		msg = new Otr.Message(otr),
		err;
	equal(msg.type, Otr.Message.MSG_QUERY, 'Query Message');
	equal(msg.toString(), otr, 'toString returns the same content');

	err = 'This is a sample error message';
	msg = new Otr.Message('?OTR Error:'+err);
	equal(msg.type, Otr.Message.MSG_ERROR, 'Error Message');	
	equal(msg.message, err, 'Error content is correct');
	equal(msg.toString(), '?OTR Error:'+err, 'toString returns the same content');

	otr = 'asdfasdf';
	msg = new Otr.Message(otr);
	equal(msg.type, Otr.Message.MSG_PLAIN, 'Plaintext Message');
	equal(msg.toString(), otr, 'toString returns the same content');

	otr = '?OTRasdflkasdf';
	msg = new Otr.Message(otr);
	equal(msg.type, Otr.Message.MSG_UNKNOWN, 'Unknown Message');
	equal(msg.toString(), otr, 'toString returns the same content');

	msg = new Otr.Message(sample.DH_COMMIT);
	equal(msg.type, Otr.Message.MSG_DH_COMMIT, 'DH Commit Message');
	equal(msg.toString(), sample.DH_COMMIT, 'toString returns the same content');
	// console.log(msg.dataEncryptedGx.getLength());

	msg = new Otr.Message(sample.DH_KEY);
	equal(msg.type, Otr.Message.MSG_DH_KEY, 'DH Key Message');
	equal(msg.toString(), sample.DH_KEY, 'toString returns the same content');

	msg = new Otr.Message(sample.REV_SIGN);
	equal(msg.type, Otr.Message.MSG_REVEAL_SIGNATURE, 'Reveal Signature Message');
	equal(msg.toString(), sample.REV_SIGN, 'toString returns the same content');

	msg = new Otr.Message(sample.SIGN);
	equal(msg.type, Otr.Message.MSG_SIGNATURE, 'Signature Message');
	equal(msg.toString(), sample.SIGN, 'toString returns the same content');

	msg = new Otr.Message(sample.DATA);
	equal(msg.type, Otr.Message.MSG_DATA, 'Data Message');
	equal(msg.toString(), sample.DATA, 'toString returns the same content');

});

