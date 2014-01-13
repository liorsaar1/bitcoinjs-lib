var SignTransaction = new BenchmarkSuite('SignTransaction', [100000], [
  new Benchmark("SignTransaction", true, false, signTransaction),
]);


var private_key = new Bitcoin.ECKey();
var message = "this is the bitcoin transaction";
var compressed = false;
var addrtype = undefined;

function signTransaction() {
  var digest = 'Bitcoin Signed Message:\n' +message;
  var hash = Crypto.SHA256(Crypto.SHA256(digest, {asBytes: true}), {asBytes: true});
  var sig = private_key.sign(hash);
  var obj = Bitcoin.ECDSA.parseSig(sig);
  var sigHex = Crypto.util.bytesToHex(integerToBytes(obj.r, 32))+Crypto.util.bytesToHex(integerToBytes(obj.s, 32));
  var pubHex = Crypto.util.bytesToHex(private_key.getPub());
}
