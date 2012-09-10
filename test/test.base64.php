<?php
// some base 64 decode
$a = base64_decode('AAIDAAAAAAEAAAACAAAAwCWgj9D/OcQjsx4YMAJdUWrC6X+koK3ArG2tVtUiwVIj68LENhmf3NZTUz2yha5/S9CzYnGMxEt6La7Vs8Vjpm7CbX3YAJ/gmBUYOUc5sU7petKRX3+LwVgQBEsHWiA56wc8EUKc7IAGefTsCVoWXQ8bw7zzaFiE2m5M6dCxbxsUfdb4aPJjjA7RY25jjxozYtebNPmCQLDfG2jLVBbFhwgrQ+WhHrj+0+kAATcuFSp5OZmqiSL75QvPv8zYBllHOwAAAAAAAAABAAAAAy293djSr6FVYYjgka3g4PPbnq+jjJFTAAAAFNpc5QQZeqvV3NtkHgzOJFxyayYV');
// $a = base64_decode('asdfasdfasdf');
echo '[';
for ($i=0, $l=strlen($a); $i<$l; $i++) {
	$c = $a[$i];
	$d = dechex(ord($c));
	if (strlen($d) < 2) $d = '0'.$d;
	echo "0x$d, ";
}
echo ']';