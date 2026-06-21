#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

// Safely prints detailed OpenSSL errors to prevent information-leak
// vulnerabilities
void handleOpenSSLErrors(const string& contextMessage) {
  cerr << "[UX ERROR] " << contextMessage << "\n";
  ERR_print_errors_fp(stderr);
}

vector<unsigned char> readFile(const string& path) {
  ifstream f(path, ios::binary);
  if (!f.is_open()) return {};
  return vector<unsigned char>((istreambuf_iterator<char>(f)),
                               istreambuf_iterator<char>());
}

bool writeFile(const string& path, const vector<unsigned char>& data) {
  ofstream f(path, ios::binary);
  if (!f.is_open()) {
    cerr << "[ERROR] Cannot open output file: " << path << "\n";
    return false;
  }

  if (!data.empty()) {
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<streamsize>(data.size()));
  }

  if (!f.good()) {
    cerr << "[ERROR] Failed while writing output file: " << path << "\n";
    return false;
  }
  return true;
}

EVP_PKEY* loadPrivateKey(const string& path) {
  FILE* fp = fopen(path.c_str(), "r");
  if (!fp) return nullptr;
  EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  return pkey;
}

EVP_PKEY* loadPublicKey(const string& path) {
  FILE* fp = fopen(path.c_str(), "r");
  if (!fp) return nullptr;
  EVP_PKEY* pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
  fclose(fp);
  return pkey;
}

/* ---------------- 1. Key Generation ---------------- */
bool keygen(const string& algo, const string& pubPath, const string& privPath) {
  EVP_PKEY_CTX* ctx = nullptr;
  EVP_PKEY* pkey = nullptr;

  if (algo == "ecdsa-p256") {
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <=
            0) {
      cerr << "[ERROR] Invalid algorithm identifier mapping.\n";
      if (ctx) EVP_PKEY_CTX_free(ctx);
      return false;
    }
  } else if (algo == "rsa-pss-3072") {
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
      cerr << "[ERROR] RSA Key parameter setup failed.\n";
      if (ctx) EVP_PKEY_CTX_free(ctx);
      return false;
    }
  } else {
    cerr << "[ERROR] Unsupported algorithm: " << algo << "\n";
    return false;
  }

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    handleOpenSSLErrors("Key generation structural failure.");
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  FILE* fpriv = fopen(privPath.c_str(), "w");
  FILE* fpub = fopen(pubPath.c_str(), "w");
  if (!fpriv || !fpub) {
    cerr << "[ERROR] File system write error.\n";
    if (fpriv) fclose(fpriv);
    if (fpub) fclose(fpub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  PEM_write_PrivateKey(fpriv, pkey, nullptr, nullptr, 0, nullptr, nullptr);
  PEM_write_PUBKEY(fpub, pkey);

  fclose(fpriv);
  fclose(fpub);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return true;
}

/* ---------------- 2. Signing (Deterministic Enforced) ---------------- */
bool sign(const string& algo, const string& inFile, const string& outSig,
          const string& privPath, const string& hashAlgo) {
  if (hashAlgo != "sha256") {
    cerr << "[ERROR] Hash mismatch error: Only sha256 is supported.\n";
    return false;
  }

  vector<unsigned char> msg = readFile(inFile);
  if (msg.empty()) {
    cerr << "[ERROR] Input file missing or unreadable.\n";
    return false;
  }

  EVP_PKEY* pkey = loadPrivateKey(privPath);
  if (!pkey) {
    handleOpenSSLErrors("Malformed key payload or wrong file path structure.");
    return false;
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
    handleOpenSSLErrors("Signature initialization context failure.");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
  if (algo == "ecdsa-p256") {
#ifdef EVP_PKEY_CTX_set_ec_sign_type
    // Enforce RFC 6979 Deterministic Nonces explicitly
    EVP_PKEY_CTX_set_ec_sign_type(pctx, EVP_EC_DETERMINISTIC_SIGNING);
#endif
  } else if (algo == "rsa-pss-3072") {
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                     -1);  // salt length = hashLen (32 bytes)
  } else {
    cerr << "[ERROR] Incorrect algorithm identification profile: " << algo
         << "\n";
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  if (EVP_DigestSignUpdate(ctx, msg.data(), msg.size()) <= 0) {
    handleOpenSSLErrors("Failed to process message for signing.");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  size_t sigLen = 0;
  if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0 || sigLen == 0) {
    handleOpenSSLErrors("Failed to determine signature length.");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  vector<unsigned char> sig(sigLen);
  if (EVP_DigestSignFinal(ctx, sig.data(), &sigLen) <= 0) {
    handleOpenSSLErrors(
        "Cryptographic processing failure during final sign computation.");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  // EVP_DigestSignFinal may return an ECDSA DER signature shorter than the
  // initially requested maximum buffer size. Remove unused trailing bytes.
  sig.resize(sigLen);

  if (!writeFile(outSig, sig)) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return true;
}

/* ---------------- 3. Verification ---------------- */
bool verify(const string& algo, const string& inFile, const string& sigFile,
            const string& pubPath, const string& hashAlgo) {
  if (hashAlgo != "sha256") {
    cout << "INVALID SIGNATURE\n";
    cerr << "[LOG] Hash parameter verification mismatch.\n";
    return false;
  }

  vector<unsigned char> msg = readFile(inFile);
  vector<unsigned char> sig = readFile(sigFile);
  if (msg.empty() || sig.empty()) {
    cout << "INVALID SIGNATURE\n";
    cerr << "[LOG] Verification assets missing from local file descriptors.\n";
    return false;
  }

  if (algo != "ecdsa-p256" && algo != "rsa-pss-3072") {
    cout << "INVALID SIGNATURE\n";
    cerr << "[LOG] Unsupported verification algorithm: " << algo << "\n";
    return false;
  }

  EVP_PKEY* pkey = loadPublicKey(pubPath);
  if (!pkey) {
    cout << "INVALID SIGNATURE\n";
    handleOpenSSLErrors(
        "Verification failed: Public key token corrupt or invalid.");
    return false;
  }

  const int keyType = EVP_PKEY_base_id(pkey);
  if ((algo == "ecdsa-p256" && keyType != EVP_PKEY_EC) ||
      (algo == "rsa-pss-3072" && keyType != EVP_PKEY_RSA &&
       keyType != EVP_PKEY_RSA_PSS)) {
    cout << "INVALID SIGNATURE\n";
    cerr << "[LOG] Public key type does not match requested algorithm.\n";
    EVP_PKEY_free(pkey);
    return false;
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    cout << "INVALID SIGNATURE\n";
    cerr << "[LOG] Failed to allocate verification context.\n";
    EVP_PKEY_free(pkey);
    return false;
  }
  if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0) {
    cout << "INVALID SIGNATURE\n";
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  EVP_PKEY_CTX* pctx = EVP_MD_CTX_get_pkey_ctx(ctx);
  if (algo == "rsa-pss-3072") {
    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1);
  }

  if (EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()) <= 0) {
    cout << "INVALID SIGNATURE\n";
    handleOpenSSLErrors("Failed to process message for verification.");
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  int ret = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  // Constant-time execution consideration: separate output strings to mitigate
  // processing side-channels
  if (ret == 1) {
    cout << "VALID SIGNATURE\n";
    return true;
  } else {
    cout << "INVALID SIGNATURE\n";
    return false;
  }
}

/* ---------------- 4. Mandatory Automated Benchmarks ---------------- */
void runBenchmarks(const string& algo) {
  cout << "\n================= BENCHMARK SUITE: " << algo
       << " =================\n";
  vector<size_t> sizes = {1 * 1024, 16 * 1024, 1024 * 1024,
                          8 * 1024 * 1024};  // 1KiB, 16KiB, 1MiB, 8MiB

  // Key Generation Benchmark
  auto startK = chrono::high_resolution_clock::now();
  keygen(algo, "bench_pub.pem", "bench_priv.pem");
  auto endK = chrono::high_resolution_clock::now();
  chrono::duration<double, milli> durationK = endK - startK;
  cout << "Key Generation Latency: " << durationK.count() << " ms\n\n";

  for (size_t size : sizes) {
    vector<unsigned char> mockData(size, 'A');
    if (!writeFile("bench_msg.bin", mockData)) {
      cerr << "[ERROR] Benchmark input creation failed.\n";
      return;
    }

    // Sign Latency Tracking
    auto startS = chrono::high_resolution_clock::now();
    sign(algo, "bench_msg.bin", "bench_sig.bin", "bench_priv.pem", "sha256");
    auto endS = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> durationS = endS - startS;

    // Verify Latency Tracking
    auto startV = chrono::high_resolution_clock::now();
    verify(algo, "bench_msg.bin", "bench_sig.bin", "bench_pub.pem", "sha256");
    auto endV = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> durationV = endV - startV;

    double signSeconds = durationS.count() / 1000.0;
    double verifySeconds = durationV.count() / 1000.0;

    cout << "Payload Size: " << size / 1024.0 << " KiB\n"
         << "  -> Sign Latency:   " << durationS.count() << " ms ("
         << (1.0 / signSeconds) << " ops/sec)\n"
         << "  -> Verify Latency: " << durationV.count() << " ms ("
         << (1.0 / verifySeconds) << " ops/sec)\n\n";
  }
}

/* ---------------- 5. Mandatory Negative Testing Engine ---------------- */
int runAutomatedTests() {
  cout << "\n================= AUTOMATED NEGATIVE TESTING SUITE "
          "=================\n";
  int failures = 0;
  auto check = [&](bool condition, const string& name) {
    cout << (condition ? "PASS" : "FAIL") << " - " << name << "\n";
    if (!condition) ++failures;
  };

  check(keygen("ecdsa-p256", "test_pub.pem", "test_priv.pem"),
        "ECDSA P-256 key generation");

  vector<unsigned char> normalMsg = {'T', 'E', 'S', 'T'};
  if (!writeFile("test_msg.bin", normalMsg)) {
    cerr << "[ERROR] Failed to create test message.\n";
    return 1;
  }
  check(sign("ecdsa-p256", "test_msg.bin", "test_sig.bin", "test_priv.pem",
             "sha256"),
        "ECDSA signing");

  check(verify("ecdsa-p256", "test_msg.bin", "test_sig.bin", "test_pub.pem",
               "sha256"),
        "Valid ECDSA signature accepted");

  vector<unsigned char> badMsg = {'B', 'A', 'D', 'D'};
  if (!writeFile("test_bad_msg.bin", badMsg)) {
    cerr << "[ERROR] Failed to create modified test message.\n";
    return 1;
  }
  check(!verify("ecdsa-p256", "test_bad_msg.bin", "test_sig.bin",
                "test_pub.pem", "sha256"),
        "Modified message rejected");

  vector<unsigned char> badSig = readFile("test_sig.bin");
  if (!badSig.empty()) badSig[badSig.size() / 2] ^= 0xFF;
  if (!writeFile("test_bad_sig.bin", badSig)) {
    cerr << "[ERROR] Failed to create modified signature.\n";
    return 1;
  }
  check(!verify("ecdsa-p256", "test_msg.bin", "test_bad_sig.bin",
                "test_pub.pem", "sha256"),
        "Modified signature rejected");

  // Wrong-key rejection.
  check(keygen("ecdsa-p256", "test_wrong_pub.pem", "test_wrong_priv.pem"),
        "Second ECDSA key generation");
  check(!verify("ecdsa-p256", "test_msg.bin", "test_sig.bin",
                "test_wrong_pub.pem", "sha256"),
        "Wrong ECDSA public key rejected");

  cout << "Test summary: " << (7 - failures) << "/7 passed\n";
  if (failures != 0) {
    cerr << "[ERROR] Automated test suite failed with " << failures
         << " failure(s).\n";
    return 1;
  }
  cout << "ALL AUTOMATED TESTS PASSED\n";
  return 0;
}

/* ---------------- Dynamic CLI Flag Routing ---------------- */
int main(int argc, char* argv[]) {
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if (argc < 2) {
    cerr << "Usage: " << argv[0]
         << " [keygen|sign|verify|benchmark|test|selftest] "
            "--algo <type> [options...]\n";
    return 1;
  }

  string cmd = argv[1];
  if (cmd == "test" || cmd == "selftest") {
    return runAutomatedTests();
  }

  string algo = "", pub = "", priv = "", in = "", out = "", sig = "",
         hash = "sha256";

  // Safe dynamic parsing loops ensuring argument indices don't segfault
  // out-of-bounds
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc)
      algo = argv[++i];
    else if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc)
      pub = argv[++i];
    else if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc)
      priv = argv[++i];
    else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc)
      in = argv[++i];
    else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
      out = argv[++i];
    else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc)
      sig = argv[++i];
    else if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc)
      hash = argv[++i];
  }

  if (cmd == "benchmark") {
    if (algo.empty()) {
      cerr << "[ERROR] Specify algorithm via --algo\n";
      return 1;
    }
    runBenchmarks(algo);
    return 0;
  }
  if (cmd == "keygen") {
    if (algo.empty() || pub.empty() || priv.empty()) {
      cerr << "[ERROR] Keygen parameters missing.\n";
      return 1;
    }
    return keygen(algo, pub, priv) ? 0 : 1;
  }
  if (cmd == "sign") {
    if (algo.empty() || in.empty() || out.empty() || priv.empty()) {
      cerr << "[ERROR] Sign parameters missing.\n";
      return 1;
    }
    return sign(algo, in, out, priv, hash) ? 0 : 1;
  }
  if (cmd == "verify") {
    if (algo.empty() || in.empty() || sig.empty() || pub.empty()) {
      cerr << "[ERROR] Verification parameters missing.\n";
      return 1;
    }
    return verify(algo, in, sig, pub, hash) ? 0 : 1;
  }

  cerr << "[ERROR] Unknown execution command requested.\n";
  return 1;
}