var AddressChain = new BenchmarkSuite('AddressChain', [35587], [
  new Benchmark("AddressChain", true, false, chain),
]);

var privKey = new Bitcoin.ECKey().getPrivateKeyByteArray();
var chainCode = new Array(32);
new SecureRandom().nextBytes(chainCode);

function chain() {
  var newkey = Bitcoin.ECKey.createECKeyFromChain(privKey, chainCode);
  privKey = newkey.getPrivateKeyByteArray();
}
