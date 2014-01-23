var AES = new BenchmarkSuite('AES', [83.333], [
  new Benchmark("Encrypt", true, false, encrypt),
  new Benchmark("Decrypt", true, false, decrypt),
]);

var password = "th1s iS a pr3tty g0oD pAsSw1rd!? o!K!";
var message = "5JBvuKS3bYj2QJpf69oZ7w5ZZaaZws9ucPcQuosM9ekFFDkyS4k";
var encryptedMessage;

function encrypt() {
  encryptedMessage = sjcl.encrypt(password, message, {iter: 10000, ks: 256});
}

function decrypt() {
  msg = sjcl.decrypt(password, encryptedMessage);
}
