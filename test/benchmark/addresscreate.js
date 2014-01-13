var AddressCreate = new BenchmarkSuite('AddressCreate', [17361], [
  new Benchmark("AddressCreate", true, false, create),
]);


function create() {
  var key = new Bitcoin.ECKey();
  return key.getBitcoinAddress();
}
