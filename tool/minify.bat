:: delete old minified files
del "..\kurotr-js.min.js"

:: minify kurOTR.js
copy ..\components\core-min.js          aa.js
copy ..\components\cipher-core-min.js   ab.js
copy ..\components\enc-base64-min.js    ac.js
copy ..\components\aes-min.js           ad.js
copy ..\components\mode-ctr-min.js      ae.js
copy ..\components\pad-nopadding-min.js af.js
copy ..\components\sha256-min.js        ag.js
copy ..\components\sha1-min.js          ah.js
copy ..\components\hmac-min.js          ai.js
jsmin.exe > ba.js < ..\otr.js
jsmin.exe > bb.js < ..\otr.util.js
jsmin.exe > bc.js < ..\otr.biginteger.js
jsmin.exe > bd.js < ..\otr.type.js
jsmin.exe > be.js < ..\otr.bytebuffer.js
jsmin.exe > bf.js < ..\otr.message.js
jsmin.exe > bg.js < ..\otr.dsa.js
jsmin.exe > bh.js < ..\otr.auth.js
jsmin.exe > bi.js < ..\otr.communication.js
copy /b *.js kurotr-js.min
del *.js

:: move minified files to final location
move /Y kurotr-js.min ..\kurotr-js.min.js
