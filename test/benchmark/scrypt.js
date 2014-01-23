var Scrypt = new BenchmarkSuite('Scrypt', [87719.298], [
  new Benchmark("Scrypt", true, false, scrypt),
]);

// The test case I want to use would be taken from 
//     http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-00
// But this is so slow that it makes the benchmark unbearable.
// var result = [
//   0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
//   0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
//   0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
//   0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87,
// ];
// var hash = Bitcoin.scrypt('pleaseletmein', 'SodiumChloride', 16384, 8, 1, 64);

var result = [
  117, 233, 120, 139, 247, 232, 30, 139, 45, 160, 185, 97, 242, 206, 205,
  204, 82, 99, 239, 141, 147, 24, 220, 215, 186, 81, 6, 46, 36, 181, 147,
  147, 118, 223, 6, 28, 239, 153, 147, 219, 23, 75, 33, 23, 129, 98, 140,
  28, 176, 100, 193, 202, 183, 233, 255, 72, 53, 67, 211, 32, 253, 74, 39, 76
];

function scrypt() {
  // NOTE: We really want to use 16384 for N, rather than 512.  But for this
  //       benchmark, this will suffice.
  var hash = Bitcoin.scrypt('pleaseletmein', 'SodiumChloride', 512, 8, 1, 64);
  for (var index = 0; index < result.length; ++index) {
    if (hash[index] != result[index]) {
      throw 'scrypt error';
    }
  }
}
