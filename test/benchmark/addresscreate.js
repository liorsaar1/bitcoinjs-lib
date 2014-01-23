var AddressCreate = new BenchmarkSuite('AddressCreate', [25575.445], [
  new Benchmark("AddressCreate", true, false, create),
]);


function create() {
  var key = new Bitcoin.ECKey();
  return key.getBitcoinAddress();
}
