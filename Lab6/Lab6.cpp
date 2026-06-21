#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using Bytes = std::vector<unsigned char>;
using Clock = std::chrono::steady_clock;

struct PKeyDeleter {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct PKeyCtxDeleter {
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct MdCtxDeleter {
  void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
struct BioDeleter {
  void operator()(BIO* p) const { BIO_free(p); }
};
using PKeyPtr = std::unique_ptr<EVP_PKEY, PKeyDeleter>;
using PKeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PKeyCtxDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using BioPtr = std::unique_ptr<BIO, BioDeleter>;

[[noreturn]] void fail(const std::string& msg) {
  unsigned long code = ERR_get_error();
  if (code != 0) {
    char buf[256]{};
    ERR_error_string_n(code, buf, sizeof(buf));
    throw std::runtime_error(msg + ": " + buf);
  }
  throw std::runtime_error(msg);
}

void check(int ok, const std::string& msg) {
  if (ok <= 0) fail(msg);
}

std::string normalize_algo(std::string a) {
  std::transform(a.begin(), a.end(), a.begin(), [](unsigned char c) {
    if (c == '_') return '-';
    return static_cast<char>(std::toupper(c));
  });
  if (a == "MLDSA-44" || a == "ML-DSA44") return "ML-DSA-44";
  if (a == "MLDSA-65" || a == "ML-DSA65") return "ML-DSA-65";
  if (a == "MLDSA-87" || a == "ML-DSA87") return "ML-DSA-87";
  if (a == "MLKEM-512" || a == "ML-KEM512") return "ML-KEM-512";
  if (a == "MLKEM-768" || a == "ML-KEM768") return "ML-KEM-768";
  if (a == "MLKEM-1024" || a == "ML-KEM1024") return "ML-KEM-1024";
  return a;
}

bool is_mldsa(const std::string& a) { return a.rfind("ML-DSA-", 0) == 0; }
bool is_mlkem(const std::string& a) { return a.rfind("ML-KEM-", 0) == 0; }

Bytes read_file(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw std::runtime_error("Cannot open file: " + p.string());
  return Bytes(std::istreambuf_iterator<char>(in), {});
}

std::string read_text(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) throw std::runtime_error("Cannot open file: " + p.string());
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

void write_file(const fs::path& p, const Bytes& data) {
  if (p.has_parent_path()) fs::create_directories(p.parent_path());
  std::ofstream out(p, std::ios::binary);
  if (!out) throw std::runtime_error("Cannot write file: " + p.string());
  out.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

void write_text(const fs::path& p, const std::string& s) {
  if (p.has_parent_path()) fs::create_directories(p.parent_path());
  std::ofstream out(p, std::ios::binary);
  if (!out) throw std::runtime_error("Cannot write file: " + p.string());
  out << s;
}

std::string b64_encode(const Bytes& in) {
  if (in.empty()) return {};
  std::string out(4 * ((in.size() + 2) / 3), '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                          in.data(), static_cast<int>(in.size()));
  if (n < 0) fail("Base64 encode failed");
  out.resize(static_cast<size_t>(n));
  return out;
}

Bytes b64_decode(const std::string& s) {
  if (s.empty()) return {};
  Bytes out((s.size() * 3) / 4 + 3);
  int n = EVP_DecodeBlock(out.data(),
                          reinterpret_cast<const unsigned char*>(s.data()),
                          static_cast<int>(s.size()));
  if (n < 0) throw std::runtime_error("Invalid base64");
  size_t pad = 0;
  if (!s.empty() && s.back() == '=') ++pad;
  if (s.size() > 1 && s[s.size() - 2] == '=') ++pad;
  out.resize(static_cast<size_t>(n) - pad);
  return out;
}

std::string json_escape(const std::string& s) {
  std::ostringstream o;
  for (unsigned char c : s) {
    switch (c) {
      case '"':
        o << "\\\"";
        break;
      case '\\':
        o << "\\\\";
        break;
      case '\n':
        o << "\\n";
        break;
      case '\r':
        o << "\\r";
        break;
      case '\t':
        o << "\\t";
        break;
      default:
        if (c < 0x20)
          o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c);
        else
          o << char(c);
    }
  }
  return o.str();
}

std::string json_get_string(const std::string& json, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t p = json.find(needle);
  if (p == std::string::npos)
    throw std::runtime_error("Missing JSON field: " + key);
  p = json.find(':', p + needle.size());
  if (p == std::string::npos)
    throw std::runtime_error("Malformed JSON field: " + key);
  p = json.find('"', p + 1);
  if (p == std::string::npos)
    throw std::runtime_error("Malformed JSON string: " + key);
  ++p;
  std::string out;
  bool esc = false;
  for (; p < json.size(); ++p) {
    char c = json[p];
    if (esc) {
      switch (c) {
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case '"':
          out.push_back('"');
          break;
        case '\\':
          out.push_back('\\');
          break;
        default:
          out.push_back(c);
          break;
      }
      esc = false;
    } else if (c == '\\')
      esc = true;
    else if (c == '"')
      return out;
    else
      out.push_back(c);
  }
  throw std::runtime_error("Unterminated JSON string: " + key);
}

PKeyPtr generate_key(const std::string& algo) {
  EVP_PKEY* raw = EVP_PKEY_Q_keygen(nullptr, nullptr, algo.c_str());
  if (!raw)
    fail("Key generation failed for " + algo + " (requires OpenSSL 3.5+)");
  return PKeyPtr(raw);
}

void save_private_pem(EVP_PKEY* key, const fs::path& p) {
  BioPtr bio(BIO_new_file(p.string().c_str(), "wb"));
  if (!bio) fail("Cannot open private key output");
  check(PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr,
                                 nullptr),
        "Private PEM write failed");
}

void save_public_pem(EVP_PKEY* key, const fs::path& p) {
  BioPtr bio(BIO_new_file(p.string().c_str(), "wb"));
  if (!bio) fail("Cannot open public key output");
  check(PEM_write_bio_PUBKEY(bio.get(), key), "Public PEM write failed");
}

PKeyPtr load_private_pem(const fs::path& p) {
  BioPtr bio(BIO_new_file(p.string().c_str(), "rb"));
  if (!bio) fail("Cannot open private key");
  EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
  if (!raw) fail("Private key read failed");
  return PKeyPtr(raw);
}

PKeyPtr load_public_pem(const fs::path& p) {
  BioPtr bio(BIO_new_file(p.string().c_str(), "rb"));
  if (!bio) fail("Cannot open public key");
  EVP_PKEY* raw = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
  if (!raw) fail("Public key read failed");
  return PKeyPtr(raw);
}

Bytes public_der(EVP_PKEY* key) {
  int len = i2d_PUBKEY(key, nullptr);
  if (len <= 0) fail("Public DER size failed");
  Bytes der(static_cast<size_t>(len));
  unsigned char* p = der.data();
  if (i2d_PUBKEY(key, &p) != len) fail("Public DER encoding failed");
  return der;
}

PKeyPtr public_from_der(const Bytes& der) {
  const unsigned char* p = der.data();
  EVP_PKEY* raw = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
  if (!raw) fail("Public DER decoding failed");
  return PKeyPtr(raw);
}

Bytes sign_message(EVP_PKEY* private_key, const Bytes& msg) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) fail("EVP_MD_CTX allocation failed");
  check(EVP_DigestSignInit_ex(ctx.get(), nullptr, nullptr, nullptr, nullptr,
                              private_key, nullptr),
        "ML-DSA sign init failed");
  size_t n = 0;
  check(EVP_DigestSign(ctx.get(), nullptr, &n, msg.data(), msg.size()),
        "ML-DSA signature sizing failed");
  Bytes sig(n);
  check(EVP_DigestSign(ctx.get(), sig.data(), &n, msg.data(), msg.size()),
        "ML-DSA signing failed");
  sig.resize(n);
  return sig;
}

bool verify_message(EVP_PKEY* public_key, const Bytes& msg, const Bytes& sig) {
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) fail("EVP_MD_CTX allocation failed");
  check(EVP_DigestVerifyInit_ex(ctx.get(), nullptr, nullptr, nullptr, nullptr,
                                public_key, nullptr),
        "ML-DSA verify init failed");
  int rc = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(),
                            msg.size());
  if (rc < 0) fail("ML-DSA verification internal error");
  return rc == 1;
}

std::pair<Bytes, Bytes> encapsulate(EVP_PKEY* public_key) {
  PKeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, public_key, nullptr));
  if (!ctx) fail("KEM context creation failed");
  check(EVP_PKEY_encapsulate_init(ctx.get(), nullptr),
        "KEM encapsulation init failed");
  size_t ct_len = 0, ss_len = 0;
  check(EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &ss_len),
        "KEM output sizing failed");
  Bytes ct(ct_len), ss(ss_len);
  check(EVP_PKEY_encapsulate(ctx.get(), ct.data(), &ct_len, ss.data(), &ss_len),
        "KEM encapsulation failed");
  ct.resize(ct_len);
  ss.resize(ss_len);
  return {ct, ss};
}

Bytes decapsulate(EVP_PKEY* private_key, const Bytes& ct) {
  PKeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr));
  if (!ctx) fail("KEM context creation failed");
  check(EVP_PKEY_decapsulate_init(ctx.get(), nullptr),
        "KEM decapsulation init failed");
  size_t ss_len = 0;
  check(EVP_PKEY_decapsulate(ctx.get(), nullptr, &ss_len, ct.data(), ct.size()),
        "KEM secret sizing failed");
  Bytes ss(ss_len);
  check(
      EVP_PKEY_decapsulate(ctx.get(), ss.data(), &ss_len, ct.data(), ct.size()),
      "KEM decapsulation failed");
  ss.resize(ss_len);
  return ss;
}

std::map<std::string, std::string> parse_opts(int argc, char** argv,
                                              int start) {
  std::map<std::string, std::string> o;
  for (int i = start; i < argc; ++i) {
    std::string k = argv[i];
    if (k.rfind("--", 0) != 0)
      throw std::runtime_error("Expected option, got: " + k);
    if (i + 1 >= argc) throw std::runtime_error("Missing value for " + k);
    o[k] = argv[++i];
  }
  return o;
}

std::string need(const std::map<std::string, std::string>& o,
                 const std::string& k) {
  auto it = o.find(k);
  if (it == o.end()) throw std::runtime_error("Missing required option " + k);
  return it->second;
}

std::string cert_payload(const std::string& subject, const std::string& issuer,
                         const std::string& algo,
                         const std::string& public_key_b64) {
  return "subject=" + subject + "\nissuer=" + issuer + "\nalgorithm=" + algo +
         "\npublic_key=" + public_key_b64 + "\n";
}

void cmd_keygen(const std::map<std::string, std::string>& o) {
  std::string algo = normalize_algo(need(o, "--algo"));
  if (!is_mldsa(algo) && !is_mlkem(algo))
    throw std::runtime_error("Unsupported algorithm: " + algo);
  auto key = generate_key(algo);
  save_public_pem(key.get(), need(o, "--pub"));
  save_private_pem(key.get(), need(o, "--priv"));
  std::cout << "Generated " << algo << " key pair\n";
}

void cmd_sign(const std::map<std::string, std::string>& o) {
  auto key = load_private_pem(need(o, "--priv"));
  Bytes sig = sign_message(key.get(), read_file(need(o, "--in")));
  auto fmt = o.count("--format") ? o.at("--format") : "raw";
  if (fmt == "base64")
    write_text(need(o, "--out"), b64_encode(sig) + "\n");
  else if (fmt == "raw")
    write_file(need(o, "--out"), sig);
  else
    throw std::runtime_error("Signature format must be raw or base64");
  std::cout << "Signature created: " << sig.size() << " bytes\n";
}

void cmd_verify(const std::map<std::string, std::string>& o) {
  auto key = load_public_pem(need(o, "--pub"));
  auto fmt = o.count("--format") ? o.at("--format") : "raw";
  Bytes sig = fmt == "base64" ? b64_decode(read_text(need(o, "--sig")))
                              : read_file(need(o, "--sig"));
  bool ok = verify_message(key.get(), read_file(need(o, "--in")), sig);
  std::cout << (ok ? "VALID\n" : "INVALID\n");
  if (!ok) std::exit(2);
}

void cmd_encaps(const std::map<std::string, std::string>& o) {
  auto key = load_public_pem(need(o, "--pub"));
  auto [ct, ss] = encapsulate(key.get());
  write_file(need(o, "--ct"), ct);
  write_file(need(o, "--ss"), ss);
  std::cout << "Encapsulated: ciphertext=" << ct.size()
            << " bytes, shared_secret=" << ss.size() << " bytes\n";
}

void cmd_decaps(const std::map<std::string, std::string>& o) {
  auto key = load_private_pem(need(o, "--priv"));
  Bytes ss = decapsulate(key.get(), read_file(need(o, "--ct")));
  write_file(need(o, "--ss"), ss);
  std::cout << "Decapsulated shared secret: " << ss.size() << " bytes\n";
}


struct MiniCertificate {
  std::string subject;
  std::string issuer;
  std::string algorithm;
  std::string public_key_b64;
  Bytes signature;
};

MiniCertificate make_certificate(EVP_PKEY* subject_pub, EVP_PKEY* ca_priv,
                                 const std::string& subject,
                                 const std::string& issuer) {
  MiniCertificate cert;
  cert.subject = subject;
  cert.issuer = issuer;
  cert.algorithm = EVP_PKEY_get0_type_name(ca_priv);
  cert.public_key_b64 = b64_encode(public_der(subject_pub));

  const std::string payload =
      cert_payload(cert.subject, cert.issuer, cert.algorithm,
                   cert.public_key_b64);
  const Bytes payload_bytes(payload.begin(), payload.end());
  cert.signature = sign_message(ca_priv, payload_bytes);
  return cert;
}

bool verify_certificate_object(const MiniCertificate& cert,
                               EVP_PKEY* ca_pub) {
  try {
    // Parse the embedded public key as part of certificate validation.
    const Bytes subject_der = b64_decode(cert.public_key_b64);
    auto subject_key = public_from_der(subject_der);
    if (!subject_key) return false;

    const std::string payload =
        cert_payload(cert.subject, cert.issuer, cert.algorithm,
                     cert.public_key_b64);
    const Bytes payload_bytes(payload.begin(), payload.end());
    return verify_message(ca_pub, payload_bytes, cert.signature);
  } catch (...) {
    return false;
  }
}

void cmd_cert_create(const std::map<std::string, std::string>& o) {
  std::string subject = need(o, "--subject");
  std::string issuer = o.count("--issuer") ? o.at("--issuer") : "PQ-CA";
  auto subject_pub = load_public_pem(need(o, "--subject-pub"));
  auto ca_priv = load_private_pem(need(o, "--ca-priv"));
  std::string algo = EVP_PKEY_get0_type_name(ca_priv.get());
  std::string pub_b64 = b64_encode(public_der(subject_pub.get()));
  std::string payload = cert_payload(subject, issuer, algo, pub_b64);
  Bytes payload_bytes(payload.begin(), payload.end());
  Bytes sig = sign_message(ca_priv.get(), payload_bytes);
  std::ostringstream json;
  json << "{\n"
       << "  \"subject\": \"" << json_escape(subject) << "\",\n"
       << "  \"issuer\": \"" << json_escape(issuer) << "\",\n"
       << "  \"algorithm\": \"" << json_escape(algo) << "\",\n"
       << "  \"public_key\": \"" << pub_b64 << "\",\n"
       << "  \"signature\": \"" << b64_encode(sig) << "\"\n"
       << "}\n";
  write_text(need(o, "--out"), json.str());
  std::cout << "Certificate created and signed by " << issuer << "\n";
}

void cmd_cert_verify(const std::map<std::string, std::string>& o) {
  std::string json = read_text(need(o, "--cert"));
  std::string subject = json_get_string(json, "subject");
  std::string issuer = json_get_string(json, "issuer");
  std::string algo = json_get_string(json, "algorithm");
  std::string pub_b64 = json_get_string(json, "public_key");
  Bytes sig = b64_decode(json_get_string(json, "signature"));
  auto ca_pub = load_public_pem(need(o, "--ca-pub"));
  std::string payload = cert_payload(subject, issuer, algo, pub_b64);
  Bytes payload_bytes(payload.begin(), payload.end());
  bool ok = verify_message(ca_pub.get(), payload_bytes, sig);
  if (ok) {
    auto subject_key = public_from_der(b64_decode(pub_b64));
    std::cout << "CERTIFICATE VALID\nSubject: " << subject
              << "\nIssuer: " << issuer << "\nSubject key type: "
              << EVP_PKEY_get0_type_name(subject_key.get()) << "\n";
  } else {
    std::cout << "CERTIFICATE INVALID\n";
    std::exit(2);
  }
}

template <class F>
double avg_ms(F&& f, int iterations) {
  auto t0 = Clock::now();
  for (int i = 0; i < iterations; ++i) f();
  auto t1 = Clock::now();
  return std::chrono::duration<double, std::milli>(t1 - t0).count() /
         iterations;
}

void cmd_bench(const std::map<std::string, std::string>& o) {
  std::string algo =
      normalize_algo(o.count("--algo") ? o.at("--algo") : "ML-DSA-44");
  int n = o.count("--iterations") ? std::stoi(o.at("--iterations")) : 100;
  size_t size = o.count("--size")
                    ? static_cast<size_t>(std::stoull(o.at("--size")))
                    : 1024;
  Bytes msg(size, 0xA5);
  std::cout
      << "algorithm,operation,message_bytes,iterations,avg_ms,ops_per_sec\n";
  if (is_mldsa(algo)) {
    PKeyPtr key;
    double kg = avg_ms([&] { key = generate_key(algo); }, std::max(1, n / 10));
    key = generate_key(algo);
    Bytes sig;
    double s = avg_ms([&] { sig = sign_message(key.get(), msg); }, n);
    sig = sign_message(key.get(), msg);
    double v = avg_ms(
        [&] {
          if (!verify_message(key.get(), msg, sig))
            fail("Benchmark verification failed");
        },
        n);
    auto row = [&](const char* op, double ms) {
      std::cout << algo << ',' << op << ',' << size << ',' << n << ',' << ms
                << ',' << 1000.0 / ms << '\n';
    };
    row("keygen", kg);
    row("sign", s);
    row("verify", v);
    std::cout << "# signature_bytes=" << sig.size() << "\n";
  } else if (is_mlkem(algo)) {
    PKeyPtr key;
    double kg = avg_ms([&] { key = generate_key(algo); }, std::max(1, n / 10));
    key = generate_key(algo);
    std::pair<Bytes, Bytes> enc;
    double e = avg_ms([&] { enc = encapsulate(key.get()); }, n);
    enc = encapsulate(key.get());
    Bytes ss;
    double d = avg_ms([&] { ss = decapsulate(key.get(), enc.first); }, n);
    auto row = [&](const char* op, double ms) {
      std::cout << algo << ',' << op << ",0," << n << ',' << ms << ','
                << 1000.0 / ms << '\n';
    };
    row("keygen", kg);
    row("encaps", e);
    row("decaps", d);
    std::cout << "# ciphertext_bytes=" << enc.first.size()
              << ", shared_secret_bytes=" << enc.second.size() << "\n";
  } else
    throw std::runtime_error("Unsupported benchmark algorithm");
}

void cmd_selftest() {
  std::cout << "=== Lab 6 automated correctness and negative-test suite ===\n";

  int passed = 0;
  int total = 0;
  auto check_result = [&](bool condition, const std::string& name) {
    ++total;
    std::cout << (condition ? "PASS" : "FAIL") << "  " << name << '\n';
    if (condition) ++passed;
  };

  // -----------------------------------------------------------------------
  // ML-DSA correctness and negative tests
  // -----------------------------------------------------------------------
  auto sig_key = generate_key("ML-DSA-44");
  auto wrong_sig_key = generate_key("ML-DSA-44");

  const Bytes msg{'L', 'a', 'b', '6'};
  const Bytes sig = sign_message(sig_key.get(), msg);

  check_result(verify_message(sig_key.get(), msg, sig),
               "ML-DSA valid signature accepted");

  Bytes modified_msg = msg;
  modified_msg[0] ^= 0x01;
  check_result(!verify_message(sig_key.get(), modified_msg, sig),
               "ML-DSA modified message rejected");

  Bytes modified_sig = sig;
  modified_sig[0] ^= 0x01;
  check_result(!verify_message(sig_key.get(), msg, modified_sig),
               "ML-DSA modified signature rejected");

  check_result(!verify_message(wrong_sig_key.get(), msg, sig),
               "ML-DSA wrong public key rejected");

  // Basic batch verification: verify N independent signatures.
  constexpr int kBatchVerifyCount = 16;
  bool batch_verify_ok = true;
  for (int i = 0; i < kBatchVerifyCount; ++i) {
    Bytes batch_msg = {'b', 'a', 't', 'c', 'h',
                       static_cast<unsigned char>(i)};
    Bytes batch_sig = sign_message(sig_key.get(), batch_msg);
    if (!verify_message(sig_key.get(), batch_msg, batch_sig)) {
      batch_verify_ok = false;
      break;
    }
  }
  check_result(batch_verify_ok,
               "ML-DSA batch verification succeeds for 16 signatures");

  // -----------------------------------------------------------------------
  // ML-KEM correctness and negative tests
  // -----------------------------------------------------------------------
  auto kem_key = generate_key("ML-KEM-512");
  auto wrong_kem_key = generate_key("ML-KEM-512");

  auto [ct, ss1] = encapsulate(kem_key.get());
  const Bytes ss2 = decapsulate(kem_key.get(), ct);
  check_result(ss1 == ss2, "ML-KEM encapsulation/decapsulation secrets match");

  const Bytes wrong_ss = decapsulate(wrong_kem_key.get(), ct);
  check_result(wrong_ss != ss1,
               "ML-KEM wrong private key yields a different secret");

  Bytes modified_ct = ct;
  modified_ct[0] ^= 0x01;
  const Bytes modified_ss = decapsulate(kem_key.get(), modified_ct);
  check_result(modified_ss != ss1,
               "ML-KEM modified ciphertext yields a different secret");

  // Basic batch decapsulation: each encapsulated secret must match.
  constexpr int kBatchDecapsCount = 16;
  bool batch_decaps_ok = true;
  for (int i = 0; i < kBatchDecapsCount; ++i) {
    auto batch_pair = encapsulate(kem_key.get());
    Bytes recovered = decapsulate(kem_key.get(), batch_pair.first);
    if (recovered != batch_pair.second) {
      batch_decaps_ok = false;
      break;
    }
  }
  check_result(batch_decaps_ok,
               "ML-KEM batch decapsulation succeeds for 16 ciphertexts");

  // -----------------------------------------------------------------------
  // Mini post-quantum certificate tests
  // -----------------------------------------------------------------------
  auto ca_key = generate_key("ML-DSA-44");
  auto subject_key = generate_key("ML-DSA-44");
  auto other_subject_key = generate_key("ML-DSA-44");

  const MiniCertificate cert =
      make_certificate(subject_key.get(), ca_key.get(), "Alice", "PQ-CA");

  check_result(verify_certificate_object(cert, ca_key.get()),
               "valid post-quantum certificate accepted");

  MiniCertificate tampered_subject = cert;
  tampered_subject.subject = "Mallory";
  check_result(!verify_certificate_object(tampered_subject, ca_key.get()),
               "certificate with modified subject rejected");

  MiniCertificate tampered_issuer = cert;
  tampered_issuer.issuer = "Fake-PQ-CA";
  check_result(!verify_certificate_object(tampered_issuer, ca_key.get()),
               "certificate with modified issuer rejected");

  MiniCertificate tampered_algorithm = cert;
  tampered_algorithm.algorithm = "ML-DSA-65";
  check_result(!verify_certificate_object(tampered_algorithm, ca_key.get()),
               "certificate with modified algorithm rejected");

  MiniCertificate tampered_public_key = cert;
  tampered_public_key.public_key_b64 =
      b64_encode(public_der(other_subject_key.get()));
  check_result(!verify_certificate_object(tampered_public_key, ca_key.get()),
               "certificate with replaced subject public key rejected");

  MiniCertificate malformed_public_key = cert;
  malformed_public_key.public_key_b64 = "not-valid-base64!!!";
  check_result(!verify_certificate_object(malformed_public_key, ca_key.get()),
               "certificate with malformed public key rejected");

  MiniCertificate tampered_cert_signature = cert;
  tampered_cert_signature.signature[0] ^= 0x01;
  check_result(
      !verify_certificate_object(tampered_cert_signature, ca_key.get()),
      "certificate with modified signature rejected");

  auto wrong_ca_key = generate_key("ML-DSA-44");
  check_result(!verify_certificate_object(cert, wrong_ca_key.get()),
               "certificate signed by another CA is rejected");

  std::cout << "Self-test summary: " << passed << "/" << total << " passed\n";
  if (passed != total) {
    throw std::runtime_error(
        "Lab 6 self-test failed with " + std::to_string(total - passed) +
        " failure(s)");
  }

  std::cout << "ALL LAB 6 AUTOMATED TESTS PASSED\n";
}

void usage() {
  std::cout
      << R"(pqtool - Lab 6 Post-Quantum Signatures & Certificates (OpenSSL 3.5+)

Commands:
  pqtool keygen --algo mldsa-44|mldsa-65|mlkem-512|mlkem-768 --pub pub.pem --priv priv.pem
  pqtool sign --in msg.bin --priv priv.pem --out sig.bin [--format raw|base64]
  pqtool verify --in msg.bin --sig sig.bin --pub pub.pem [--format raw|base64]
  pqtool encaps --pub pub.pem --ct ct.bin --ss ss.bin
  pqtool decaps --priv priv.pem --ct ct.bin --ss ss.bin
  pqtool cert-create --subject "Alice" --subject-pub subject_pub.pem --ca-priv ca_priv.pem --out cert.json [--issuer PQ-CA]
  pqtool cert-verify --cert cert.json --ca-pub ca_pub.pem
  pqtool bench [--algo mldsa-44|mldsa-65|mlkem-512] [--size 1024] [--iterations 100]
  pqtool selftest
)";
}

int main(int argc, char** argv) {
  try {
    if (OPENSSL_VERSION_NUMBER < 0x30500000L)
      throw std::runtime_error("OpenSSL 3.5+ is required");
    if (argc < 2) {
      usage();
      return 1;
    }
    std::string cmd = argv[1];
    if (cmd == "selftest") {
      cmd_selftest();
      return 0;
    }
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
      usage();
      return 0;
    }
    auto o = parse_opts(argc, argv, 2);
    if (cmd == "keygen")
      cmd_keygen(o);
    else if (cmd == "sign")
      cmd_sign(o);
    else if (cmd == "verify")
      cmd_verify(o);
    else if (cmd == "encaps")
      cmd_encaps(o);
    else if (cmd == "decaps")
      cmd_decaps(o);
    else if (cmd == "cert-create")
      cmd_cert_create(o);
    else if (cmd == "cert-verify")
      cmd_cert_verify(o);
    else if (cmd == "bench")
      cmd_bench(o);
    else {
      usage();
      throw std::runtime_error("Unknown command: " + cmd);
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << '\n';
    return 1;
  }
}
