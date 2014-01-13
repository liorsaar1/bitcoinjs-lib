var SignAndVerify = new BenchmarkSuite('SignAndVerify', [69930], [
  new Benchmark("SignMessage", true, false, signMessage),
  new Benchmark("VerifyMessage", true, false, verifyMessage),
]);


var private_key = new Bitcoin.ECKey();
var message = "this is the bitcoin transaction";
var sigHex;

function signMessage() {
  var hash = Crypto.SHA256(Crypto.SHA256(message, {asBytes: true}), {asBytes: true});
  var sig = private_key.sign(hash);
  var obj = Bitcoin.ECDSA.parseSig(sig);
  sigHex = Crypto.util.bytesToHex(integerToBytes(obj.r, 32))+Crypto.util.bytesToHex(integerToBytes(obj.s, 32));
}

function verifyMessage() {
  var adr = private_key.getBitcoinAddress();
  var pub = private_key.getPub();
  var sig = sigHex;

  var hash = Crypto.SHA256(Crypto.SHA256(message, {asBytes: true}), {asBytes: true});

  var sig = [27].concat(Crypto.util.hexToBytes(sig));
  sig = Bitcoin.ECDSA.parseSigCompact(sig);

  var res = false;

  for (var i=0; i<4; i++)
  {
    sig.i = i;

    var pubKey;
    try {
      pubKey = Bitcoin.ECDSA.recoverPubKey(sig.r, sig.s, hash, sig.i);
    } catch(err) {
      throw err;  // benchmark error
    }

    var expectedAddress = pubKey.getBitcoinAddress().toString();
    if (expectedAddress == adr)
    {
      res = adr;
      break;
    }
  }
  if (!res) {
    throw 'verification failure';
  }
}
