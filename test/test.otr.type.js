"use strict";
/**
 * Unit Testing Otr.Type
 * with QUnit
 * 
 * @author Khandar William
 *
 * 2012-07-10 initial commit, Data and MPI
 */

module('Type');

function getRandomInt(min, max) {
	return Math.floor(Math.random() * (max - min + 1)) + min;
}

test('Data', function () {
	var test1 = [],
		num = 100,
		i, d, d2, 
		bytes2, len;

	i = num;
	while (i--) {
		test1.push(getRandomInt(0, 255));
	}
	d = new Otr.Type.Data(test1);
	equal(d.getLength(), test1.length, 'the same array length');
	deepEqual(d.getValue(), test1, 'the same array values');
	d2 = new Otr.Type.Data(test1);
	ok(d.equals(d2), 'equals works');
	ok(d2.equals(d), 'equals works');

	bytes2 = d.toBytes();
	len = (bytes2[0] << 24) 
		+ (bytes2[1] << 16) 
		+ (bytes2[2] << 8) 
		+ (bytes2[3]);
	equal(len, d.getLength(), 'toBytes length is correct');
	deepEqual(bytes2.slice(4), d.getValue(), 'toBytes values are correct');
});

test('MPI', function () {
	var bi1 = new Otr.BigInteger('22222222222222222222222222222222'), bi2,
		bytes1 = bi1.toByteArray(),
		mpi, mpi2, 
		bytes2, len;

	mpi = new Otr.Type.MPI(bi1);
	ok(mpi.toBigInteger().equals(bi1), 'from/to BigInteger');
	mpi2 = new Otr.Type.MPI(bytes1);
	deepEqual(mpi2.getValue(), bytes1, 'the same array values');
	ok(mpi.equals(mpi2), 'equals works');
	ok(mpi2.equals(mpi), 'equals works');

	bytes2 = mpi.toBytes();
	len = (bytes2[0] << 24) 
		+ (bytes2[1] << 16) 
		+ (bytes2[2] << 8) 
		+ (bytes2[3]);
	equal(len, mpi.getLength(), 'toBytes length is correct');
	deepEqual(bytes2.slice(4), mpi.getValue(), 'toBytes values are correct');
	// compareTo
	bi2 = bi1.clone();
	mpi2 = new Otr.Type.MPI(bi2);
	ok(mpi2.compareTo(mpi) === 0, 'compareTo equal');
	bi2 = bi2.add(Otr.BigInteger.ONE);
	mpi2 = new Otr.Type.MPI(bi2);
	ok(mpi2.compareTo(mpi) > 0, 'compareTo greater than');
	bi2 = bi2.subtract(new Otr.BigInteger('5'));
	mpi2 = new Otr.Type.MPI(bi2);
	ok(mpi2.compareTo(mpi) < 0, 'compareTo less than');

});