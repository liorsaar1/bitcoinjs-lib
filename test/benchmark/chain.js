var AddressChain = new BenchmarkSuite('AddressChain', [55865.922], [
  new Benchmark("AddressChain", true, false, chain),
]);

var privKey;
var chainCode;

function chain() {
  if (!privKey) {
    privKey = new Bitcoin.ECKey().getPrivateKeyByteArray();
    chainCode = new Array(32);
    new SecureRandom().nextBytes(chainCode);
  }
  var newkey = Bitcoin.ECKey.createECKeyFromChain(privKey, chainCode);
  privKey = newkey.getPrivateKeyByteArray();
}
