/**
 * lab4tool.cpp - Lab 4: Hashing, PKI, and Practical Attacks
 *
 * Build:
 *   g++ -std=c++17 -O2 -Wall -Wextra -o lab4tool lab4tool.cpp \
 *       -lssl -lcrypto -lcryptopp
 *
 * Libraries:
 *   - OpenSSL: hashing, SHAKE, X.509 parsing/verification, MD5 file digest
 *   - Crypto++: HMAC-SHA256 mitigation demo
 *
 * Ethics:
 *   This tool is for offline defensive education only.
 *   Do not use against real systems or live services.
 */

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

static std::string lower_copy(std::string s) {
  for (auto& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

static void print_openssl_errors() {
  unsigned long err = 0;
  while ((err = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    std::cerr << "OpenSSL: " << buf << "\n";
  }
}

static bool read_file_bytes(const std::string& path, Bytes& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return false;
  f.seekg(0, std::ios::end);
  std::streampos pos = f.tellg();
  if (pos < 0) return false;
  out.resize(static_cast<size_t>(pos));
  f.seekg(0, std::ios::beg);
  if (!out.empty()) {
    f.read(reinterpret_cast<char*>(out.data()),
           static_cast<std::streamsize>(out.size()));
    if (!f) return false;
  }
  return true;
}

static bool write_file_bytes(const std::string& path, const Bytes& data) {
  std::ofstream f(path, std::ios::binary);
  if (!f.is_open()) return false;
  if (!data.empty())
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(f);
}

static std::string bytes_to_hex(const Bytes& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char b : data) oss << std::setw(2) << static_cast<int>(b);
  return oss.str();
}

static bool hex_to_bytes(const std::string& hex, Bytes& out) {
  if (hex.size() % 2 != 0) return false;
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned int v = 0;
    std::istringstream iss(hex.substr(i, 2));
    iss >> std::hex >> v;
    if (iss.fail()) return false;
    out.push_back(static_cast<unsigned char>(v));
  }
  return true;
}

static std::string escaped_view(const Bytes& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char b : data) {
    if (b >= 0x20 && b <= 0x7e && b != '\\' && b != '"')
      oss << static_cast<char>(b);
    else
      oss << "\\x" << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

static std::map<std::string, std::string> parse_opts(int argc, char* argv[],
                                                     int start) {
  std::map<std::string, std::string> opts;
  for (int i = start; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg.rfind("--", 0) != 0)
      throw std::runtime_error("Unexpected argument: " + arg);
    std::string key = arg.substr(2);
    if (key.empty()) throw std::runtime_error("Empty option name");
    if (key == "stream" || key == "help") {
      opts[key] = "true";
      continue;
    }
    if (i + 1 >= argc) throw std::runtime_error("Missing value for --" + key);
    opts[key] = argv[++i];
  }
  return opts;
}

static std::string require_opt(const std::map<std::string, std::string>& opts,
                               const std::string& key) {
  auto it = opts.find(key);
  if (it == opts.end() || it->second.empty())
    throw std::runtime_error("Missing required option --" + key);
  return it->second;
}

static int parse_int_opt(const std::map<std::string, std::string>& opts,
                         const std::string& key, int def = 0) {
  auto it = opts.find(key);
  if (it == opts.end()) return def;
  size_t idx = 0;
  int value = 0;
  try {
    value = std::stoi(it->second, &idx);
  } catch (...) {
    throw std::runtime_error("Invalid integer for --" + key);
  }
  if (idx != it->second.size())
    throw std::runtime_error("Invalid integer for --" + key);
  return value;
}

class HashEngine {
 private:
  EVP_MD_CTX* ctx = nullptr;
  const EVP_MD* md = nullptr;
  bool shake_mode = false;
  int shake_bits = 0;

 public:
  ~HashEngine() {
    if (ctx) EVP_MD_CTX_free(ctx);
  }

  bool init(const std::string& algo, int outlen_bits = 0) {
    std::string a = lower_copy(algo);
    md = nullptr;
    shake_mode = false;
    shake_bits = 0;
    if (a == "sha224")
      md = EVP_sha224();
    else if (a == "sha256")
      md = EVP_sha256();
    else if (a == "sha384")
      md = EVP_sha384();
    else if (a == "sha512")
      md = EVP_sha512();
    else if (a == "sha3-224")
      md = EVP_sha3_224();
    else if (a == "sha3-256")
      md = EVP_sha3_256();
    else if (a == "sha3-384")
      md = EVP_sha3_384();
    else if (a == "sha3-512")
      md = EVP_sha3_512();
    else if (a == "md5")
      md = EVP_md5();
    else if (a == "shake128") {
      md = EVP_shake128();
      shake_mode = true;
      shake_bits = outlen_bits;
    } else if (a == "shake256") {
      md = EVP_shake256();
      shake_mode = true;
      shake_bits = outlen_bits;
    } else
      return false;
    if (!md) return false;
    if (ctx) {
      EVP_MD_CTX_free(ctx);
      ctx = nullptr;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    return EVP_DigestInit_ex(ctx, md, nullptr) == 1;
  }

  bool update(const unsigned char* data, size_t len) {
    if (!ctx) return false;
    if (len == 0) return true;
    if (!data) return false;
    return EVP_DigestUpdate(ctx, data, len) == 1;
  }

  bool stream_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    constexpr size_t BUFFER_SIZE = 1024 * 1024;
    std::vector<char> buffer(BUFFER_SIZE);
    while (file) {
      file.read(buffer.data(), static_cast<std::streamsize>(BUFFER_SIZE));
      std::streamsize got = file.gcount();
      if (got > 0) {
        if (!update(reinterpret_cast<const unsigned char*>(buffer.data()),
                    static_cast<size_t>(got)))
          return false;
      }
    }
    return !file.bad();
  }

  Bytes finalize() {
    Bytes digest;
    if (!ctx || !md) return digest;
    if (shake_mode) {
      if (shake_bits <= 0 || shake_bits % 8 != 0) return digest;
      size_t outlen = static_cast<size_t>(shake_bits / 8);
      digest.resize(outlen);
      if (EVP_DigestFinalXOF(ctx, digest.data(), outlen) != 1) digest.clear();
    } else {
      int sz = EVP_MD_get_size(md);
      if (sz <= 0) return digest;
      digest.resize(static_cast<size_t>(sz));
      unsigned int outlen = 0;
      if (EVP_DigestFinal_ex(ctx, digest.data(), &outlen) != 1) {
        digest.clear();
        return digest;
      }
      digest.resize(outlen);
    }
    return digest;
  }
};

static bool hash_memory(const std::string& algo, const Bytes& data,
                        int outlen_bits, Bytes& digest) {
  HashEngine engine;
  if (!engine.init(algo, outlen_bits)) return false;
  if (!data.empty() && !engine.update(data.data(), data.size())) return false;
  digest = engine.finalize();
  return !digest.empty();
}

static bool hash_file(const std::string& algo, const std::string& file,
                      int outlen_bits, Bytes& digest, long long* ms = nullptr) {
  std::string a = lower_copy(algo);
  bool is_shake = (a == "shake128" || a == "shake256");
  if (is_shake) {
    if (outlen_bits <= 0 || outlen_bits % 8 != 0)
      throw std::runtime_error(
          "SHAKE requires --outlen as a positive multiple of 8 bits");
  } else if (outlen_bits != 0)
    throw std::runtime_error("--outlen is only valid for SHAKE128/SHAKE256");
  HashEngine engine;
  if (!engine.init(algo, outlen_bits))
    throw std::runtime_error("Unsupported algorithm: " + algo);
  auto start = std::chrono::high_resolution_clock::now();
  if (!engine.stream_file(file))
    throw std::runtime_error("Failed to read/hash input file: " + file);
  auto end = std::chrono::high_resolution_clock::now();
  digest = engine.finalize();
  if (digest.empty()) throw std::runtime_error("Hashing failed");
  if (ms)
    *ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
              .count();
  return true;
}

static int cmd_kat() {
  struct TestCase {
    std::string algo;
    Bytes input;
    std::string expected_hex;
    int outlen_bits = 0;
  };
  const Bytes abc = {'a', 'b', 'c'};
  std::vector<TestCase> tests = {
      {"sha224", abc,
       "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
      {"sha256", abc,
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"sha384", abc,
       "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072"
       "ba1e7cc2358baeca134c825a7"},
      {"sha512", abc,
       "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992"
       "a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
      {"sha3-224", abc,
       "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
      {"sha3-256", abc,
       "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
      {"sha3-384", abc,
       "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88ce"
       "a927ac7f539f1edf228376d25"},
      {"sha3-512", abc,
       "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e"
       "9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
      {"shake128", abc, "5881092dd818bf5cf8a3ddb793fbcba7", 128},
      {"shake256", abc,
       "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
       256}};
  for (const auto& t : tests) {
    Bytes digest;
    if (!hash_memory(t.algo, t.input, t.outlen_bits, digest)) {
      std::cerr << "[FAIL] " << t.algo << "\n";
      return 1;
    }
    std::string got = bytes_to_hex(digest);
    if (got != t.expected_hex) {
      std::cerr << "[FAIL] " << t.algo << "\n  got:      " << got
                << "\n  expected: " << t.expected_hex << "\n";
      return 1;
    }
    std::cout << "[PASS] " << t.algo << "\n";
  }
  std::cout << "KAT summary: " << tests.size() << "/" << tests.size()
            << " passed\n";
  return 0;
}

static X509* load_cert_pem_or_der(const std::string& path) {
  FILE* fp = std::fopen(path.c_str(), "rb");
  if (!fp) return nullptr;
  X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
  if (!cert) {
    std::rewind(fp);
    cert = d2i_X509_fp(fp, nullptr);
  }
  std::fclose(fp);
  return cert;
}

static std::string bio_to_string(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (!mem || !mem->data) return "";
  return std::string(mem->data, mem->length);
}

static std::string x509_name_to_string(const X509_NAME* name) {
  if (!name) return "(none)";
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) return "(error)";
  X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
  std::string s = bio_to_string(bio);
  BIO_free(bio);
  return s;
}

static std::string asn1_time_to_string(const ASN1_TIME* t) {
  if (!t) return "(none)";
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) return "(error)";
  ASN1_TIME_print(bio, t);
  std::string s = bio_to_string(bio);
  BIO_free(bio);
  return s;
}

static std::string pkey_info(EVP_PKEY* pkey) {
  if (!pkey) return "(none)";
  std::ostringstream oss;
  int base = EVP_PKEY_base_id(pkey);
  const char* name = OBJ_nid2ln(base);
  oss << (name ? name : "unknown");
  int bits = EVP_PKEY_bits(pkey);
  if (bits > 0) oss << ", " << bits << " bits";
#if OPENSSL_VERSION_MAJOR >= 3
  char group[128];
  size_t group_len = 0;
  if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group,
                                     sizeof(group), &group_len) == 1)
    oss << ", group=" << group;
#endif
  return oss.str();
}

static void print_key_usage(X509* cert) {
  ASN1_BIT_STRING* usage = static_cast<ASN1_BIT_STRING*>(
      X509_get_ext_d2i(cert, NID_key_usage, nullptr, nullptr));
  std::cout << "Key Usage: ";
  if (!usage) {
    std::cout << "(not present)\n";
    return;
  }
  struct UsageMap {
    int bit;
    const char* name;
  };
  UsageMap maps[] = {{KU_DIGITAL_SIGNATURE, "Digital Signature"},
                     {KU_NON_REPUDIATION, "Non Repudiation"},
                     {KU_KEY_ENCIPHERMENT, "Key Encipherment"},
                     {KU_DATA_ENCIPHERMENT, "Data Encipherment"},
                     {KU_KEY_AGREEMENT, "Key Agreement"},
                     {KU_KEY_CERT_SIGN, "Certificate Sign"},
                     {KU_CRL_SIGN, "CRL Sign"},
                     {KU_ENCIPHER_ONLY, "Encipher Only"},
                     {KU_DECIPHER_ONLY, "Decipher Only"}};
  bool any = false;
  for (const auto& m : maps) {
    if (ASN1_BIT_STRING_get_bit(usage, m.bit)) {
      if (any) std::cout << ", ";
      std::cout << m.name;
      any = true;
    }
  }
  if (!any) std::cout << "(present but no recognized bits)";
  std::cout << "\n";
  ASN1_BIT_STRING_free(usage);
}

static void print_sans(X509* cert) {
  GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  std::cout << "Subject Alternative Names: ";
  if (!names) {
    std::cout << "(not present)\n";
    return;
  }
  int count = sk_GENERAL_NAME_num(names);
  if (count <= 0) {
    std::cout << "(empty)\n";
    GENERAL_NAMES_free(names);
    return;
  }
  std::cout << "\n";
  for (int i = 0; i < count; ++i) {
    const GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, i);
    if (!gn) continue;
    if (gn->type == GEN_DNS) {
      const unsigned char* data = ASN1_STRING_get0_data(gn->d.dNSName);
      int len = ASN1_STRING_length(gn->d.dNSName);
      std::cout << "  DNS: "
                << std::string(reinterpret_cast<const char*>(data), len)
                << "\n";
    } else if (gn->type == GEN_IPADD) {
      const unsigned char* data = ASN1_STRING_get0_data(gn->d.iPAddress);
      int len = ASN1_STRING_length(gn->d.iPAddress);
      std::cout << "  IP: ";
      if (len == 4)
        std::cout << static_cast<int>(data[0]) << "."
                  << static_cast<int>(data[1]) << "."
                  << static_cast<int>(data[2]) << "."
                  << static_cast<int>(data[3]);
      else
        std::cout << bytes_to_hex(Bytes(data, data + len));
      std::cout << "\n";
    } else
      std::cout << "  Type " << gn->type << ": (not decoded)\n";
  }
  GENERAL_NAMES_free(names);
}

static int cmd_cert(const std::map<std::string, std::string>& opts) {
  std::string cert_path = require_opt(opts, "cert");
  X509* cert = load_cert_pem_or_der(cert_path);
  if (!cert) {
    std::cerr << "Error: cannot load certificate: " << cert_path << "\n";
    print_openssl_errors();
    return 1;
  }
  std::cout << "Certificate: " << cert_path << "\n";
  std::cout << "Subject: " << x509_name_to_string(X509_get_subject_name(cert))
            << "\n";
  std::cout << "Issuer:  " << x509_name_to_string(X509_get_issuer_name(cert))
            << "\n";
  std::cout << "Validity Not Before: "
            << asn1_time_to_string(X509_get0_notBefore(cert)) << "\n";
  std::cout << "Validity Not After:  "
            << asn1_time_to_string(X509_get0_notAfter(cert)) << "\n";
  int sig_nid = X509_get_signature_nid(cert);
  std::cout << "Signature Algorithm: "
            << (OBJ_nid2ln(sig_nid) ? OBJ_nid2ln(sig_nid) : "unknown") << " ["
            << (OBJ_nid2sn(sig_nid) ? OBJ_nid2sn(sig_nid) : "?") << "]\n";
  const X509_ALGOR* tbs_sig_alg = X509_get0_tbs_sigalg(cert);
  if (tbs_sig_alg && tbs_sig_alg->algorithm) {
    int tbs_nid = OBJ_obj2nid(tbs_sig_alg->algorithm);
    std::cout << "TBS Signature Algorithm: "
              << (OBJ_nid2ln(tbs_nid) ? OBJ_nid2ln(tbs_nid) : "unknown") << " ["
              << (OBJ_nid2sn(tbs_nid) ? OBJ_nid2sn(tbs_nid) : "?") << "]\n";
    std::cout << "Algorithm Consistency: "
              << (tbs_nid == sig_nid ? "OK" : "MISMATCH") << "\n";
  }
  EVP_PKEY* pkey = X509_get_pubkey(cert);
  std::cout << "Subject Public Key Info: " << pkey_info(pkey) << "\n";
  print_key_usage(cert);
  print_sans(cert);
  int tbs_len = i2d_re_X509_tbs(cert, nullptr);
  std::cout << "TBS DER Integrity: " << (tbs_len > 0 ? "OK" : "FAILED") << "\n";
  auto issuer_it = opts.find("issuer");
  if (issuer_it != opts.end()) {
    X509* issuer = load_cert_pem_or_der(issuer_it->second);
    if (!issuer) {
      std::cerr << "Error: cannot load issuer certificate: "
                << issuer_it->second << "\n";
      if (pkey) EVP_PKEY_free(pkey);
      X509_free(cert);
      return 1;
    }
    EVP_PKEY* issuer_pub = X509_get_pubkey(issuer);
    if (!issuer_pub) {
      std::cerr << "Error: issuer certificate has no public key\n";
      X509_free(issuer);
      if (pkey) EVP_PKEY_free(pkey);
      X509_free(cert);
      return 1;
    }
    int ok = X509_verify(cert, issuer_pub);
    std::cout << "Signature Verification With Issuer: "
              << (ok == 1 ? "VALID" : "INVALID") << "\n";
    EVP_PKEY_free(issuer_pub);
    X509_free(issuer);
  } else
    std::cout << "Signature Verification With Issuer: SKIPPED; no --issuer "
                 "provided\n";
  if (pkey) EVP_PKEY_free(pkey);
  X509_free(cert);
  return 0;
}

static std::string cryptopp_hmac_sha256_hex(const std::string& key,
                                            const std::string& msg) {
  std::string mac;
  CryptoPP::HMAC<CryptoPP::SHA256> hmac(
      reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
  CryptoPP::StringSource ss(
      msg, true,
      new CryptoPP::HashFilter(
          hmac,
          new CryptoPP::HexEncoder(new CryptoPP::StringSink(mac), false)));
  return lower_copy(mac);
}

static int cmd_hmac(const std::map<std::string, std::string>& opts) {
  std::cout << cryptopp_hmac_sha256_hex(require_opt(opts, "key"),
                                        require_opt(opts, "message"))
            << "\n";
  return 0;
}

static std::string naive_mac_sha256_hex(const std::string& key,
                                        const std::string& msg) {
  Bytes data;
  data.insert(data.end(), key.begin(), key.end());
  data.insert(data.end(), msg.begin(), msg.end());
  Bytes digest;
  if (!hash_memory("sha256", data, 0, digest))
    throw std::runtime_error("Failed to compute naive SHA256 MAC");
  return bytes_to_hex(digest);
}

static int cmd_mac_naive(const std::map<std::string, std::string>& opts) {
  std::cout << naive_mac_sha256_hex(require_opt(opts, "key"),
                                    require_opt(opts, "message"))
            << "\n";
  return 0;
}

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}
static uint32_t load_be32(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
static void store_be32(unsigned char* p, uint32_t x) {
  p[0] = (x >> 24) & 0xff;
  p[1] = (x >> 16) & 0xff;
  p[2] = (x >> 8) & 0xff;
  p[3] = x & 0xff;
}
static void store_be64(Bytes& out, uint64_t x) {
  for (int i = 7; i >= 0; --i)
    out.push_back(static_cast<unsigned char>((x >> (8 * i)) & 0xff));
}
static const uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
    0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
    0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
    0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
    0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
    0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
    0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
    0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
    0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};

static void sha256_compress(std::array<uint32_t, 8>& H,
                            const unsigned char block[64]) {
  uint32_t W[64];
  for (int i = 0; i < 16; ++i) W[i] = load_be32(block + 4 * i);
  for (int i = 16; i < 64; ++i) {
    uint32_t s0 =
        rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
    uint32_t s1 =
        rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
    W[i] = W[i - 16] + s0 + W[i - 7] + s1;
  }
  uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6],
           h = H[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + K256[i] + W[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  H[0] += a;
  H[1] += b;
  H[2] += c;
  H[3] += d;
  H[4] += e;
  H[5] += f;
  H[6] += g;
  H[7] += h;
}

static Bytes sha256_padding_for_length(uint64_t message_len_bytes) {
  Bytes pad;
  pad.push_back(0x80);
  while ((message_len_bytes + pad.size()) % 64 != 56) pad.push_back(0x00);
  store_be64(pad, message_len_bytes * 8);
  return pad;
}

static bool sha256_state_from_hex(const std::string& hex,
                                  std::array<uint32_t, 8>& H) {
  Bytes d;
  if (!hex_to_bytes(hex, d) || d.size() != 32) return false;
  for (int i = 0; i < 8; ++i) H[i] = load_be32(d.data() + 4 * i);
  return true;
}

static std::string sha256_state_to_hex(const std::array<uint32_t, 8>& H) {
  Bytes d(32);
  for (int i = 0; i < 8; ++i) store_be32(d.data() + 4 * i, H[i]);
  return bytes_to_hex(d);
}

static std::string sha256_length_extend(const std::string& orig_mac_hex,
                                        uint64_t processed_bytes_after_glue_pad,
                                        const Bytes& append) {
  std::array<uint32_t, 8> H{};
  if (!sha256_state_from_hex(orig_mac_hex, H))
    throw std::runtime_error("--orig-mac must be a 32-byte SHA256 hex digest");
  Bytes continuation = append;
  Bytes final_pad =
      sha256_padding_for_length(processed_bytes_after_glue_pad + append.size());
  continuation.insert(continuation.end(), final_pad.begin(), final_pad.end());
  if (continuation.size() % 64 != 0)
    throw std::runtime_error("Internal error: continuation not block-aligned");
  for (size_t off = 0; off < continuation.size(); off += 64)
    sha256_compress(H, continuation.data() + off);
  return sha256_state_to_hex(H);
}

static int cmd_le_sha256(const std::map<std::string, std::string>& opts) {
  std::string orig_mac = lower_copy(require_opt(opts, "orig-mac"));
  std::string orig_msg = require_opt(opts, "orig-msg");
  std::string append_msg = require_opt(opts, "append");
  int key_len = parse_int_opt(opts, "key-len");
  if (key_len < 0) throw std::runtime_error("--key-len must be non-negative");
  Bytes orig(orig_msg.begin(), orig_msg.end()),
      append(append_msg.begin(), append_msg.end());
  uint64_t unknown_prefix_total = static_cast<uint64_t>(key_len) + orig.size();
  Bytes glue_pad = sha256_padding_for_length(unknown_prefix_total);
  uint64_t processed_after_glue =
      unknown_prefix_total + static_cast<uint64_t>(glue_pad.size());
  std::string forged_mac =
      sha256_length_extend(orig_mac, processed_after_glue, append);
  Bytes forged_msg = orig;
  forged_msg.insert(forged_msg.end(), glue_pad.begin(), glue_pad.end());
  forged_msg.insert(forged_msg.end(), append.begin(), append.end());
  std::cout << "Forged MAC:\n" << forged_mac << "\n\n";
  std::cout << "Forged message, hex:\n" << bytes_to_hex(forged_msg) << "\n\n";
  std::cout << "Forged message, escaped view:\n"
            << escaped_view(forged_msg) << "\n\n";
  std::cout << "Glue padding, hex:\n" << bytes_to_hex(glue_pad) << "\n";
  return 0;
}

static int cmd_selftest() {
  std::cout << "=== Lab 4 automated correctness and negative-test suite ===\n";

  int passed = 0;
  int total = 0;
  auto check = [&](bool condition, const std::string& name) {
    ++total;
    std::cout << (condition ? "PASS" : "FAIL") << "  " << name << '\n';
    if (condition) ++passed;
  };

  auto rejects = [&](const auto& fn) {
    try {
      fn();
      return false;
    } catch (const std::exception&) {
      return true;
    }
  };

  // -----------------------------------------------------------------------
  // Hash correctness and input validation
  // -----------------------------------------------------------------------
  const Bytes abc = {'a', 'b', 'c'};
  Bytes digest;
  check(hash_memory("sha256", abc, 0, digest) &&
            bytes_to_hex(digest) ==
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb"
                "410ff61f20015ad",
        "SHA-256 known-answer test");

  check(hash_memory("sha3-256", abc, 0, digest) &&
            bytes_to_hex(digest) ==
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46"
                "bfe24511431532",
        "SHA3-256 known-answer test");

  check(hash_memory("shake128", abc, 128, digest) &&
            bytes_to_hex(digest) == "5881092dd818bf5cf8a3ddb793fbcba7",
        "SHAKE128 128-bit output known-answer test");

  check(!hash_memory("not-a-real-hash", abc, 0, digest),
        "unsupported hash algorithm is rejected");

  const std::string temp_hash_file = "lab4_selftest_hash_input.bin";
  const Bytes file_data = {'s', 't', 'r', 'e', 'a', 'm', 'i',
                           'n', 'g', '-', 't', 'e', 's', 't'};
  check(write_file_bytes(temp_hash_file, file_data),
        "temporary streaming input file created");

  Bytes memory_digest;
  Bytes file_digest;
  bool stream_ok = hash_memory("sha512", file_data, 0, memory_digest) &&
                   hash_file("sha512", temp_hash_file, 0, file_digest, nullptr);
  check(stream_ok && memory_digest == file_digest,
        "streamed SHA-512 equals in-memory SHA-512");

  check(rejects([&] {
          Bytes ignored;
          (void)hash_file("sha256", temp_hash_file, 128, ignored, nullptr);
        }),
        "--outlen is rejected for fixed-output hashes");

  check(rejects([&] {
          Bytes ignored;
          (void)hash_file("shake256", temp_hash_file, 7, ignored, nullptr);
        }),
        "invalid SHAKE output length is rejected");

  std::remove(temp_hash_file.c_str());

  // -----------------------------------------------------------------------
  // Naive MAC and HMAC tests
  // -----------------------------------------------------------------------
  const std::string key = "Kryptic666";
  const std::string message = "user=fatman&role=user";
  const std::string modified_message = "user=fatman&role=admin";

  const std::string naive_original = naive_mac_sha256_hex(key, message);
  const std::string naive_modified =
      naive_mac_sha256_hex(key, modified_message);
  check(naive_original.size() == 64 && naive_original != naive_modified,
        "naive SHA256(key || message) changes when message changes");

  const std::string rfc4231_key(20, static_cast<char>(0x0b));
  check(cryptopp_hmac_sha256_hex(rfc4231_key, "Hi There") ==
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7",
        "HMAC-SHA256 RFC 4231 test vector");

  check(cryptopp_hmac_sha256_hex(key, message) !=
            cryptopp_hmac_sha256_hex(key, modified_message),
        "HMAC changes when authenticated message changes");

  // -----------------------------------------------------------------------
  // SHA-256 length-extension attack demonstration
  // -----------------------------------------------------------------------
  const std::string append = "&role=admin";
  const uint64_t prefix_len =
      static_cast<uint64_t>(key.size() + message.size());
  const Bytes glue = sha256_padding_for_length(prefix_len);
  const uint64_t processed_after_glue = prefix_len + glue.size();
  const Bytes append_bytes(append.begin(), append.end());

  const std::string forged_mac =
      sha256_length_extend(naive_original, processed_after_glue, append_bytes);

  Bytes forged_message(message.begin(), message.end());
  forged_message.insert(forged_message.end(), glue.begin(), glue.end());
  forged_message.insert(forged_message.end(), append_bytes.begin(),
                        append_bytes.end());

  const std::string forged_message_string(
      reinterpret_cast<const char*>(forged_message.data()),
      forged_message.size());
  const std::string server_mac =
      naive_mac_sha256_hex(key, forged_message_string);

  check(forged_mac == server_mac,
        "length-extension forged MAC is accepted by naive server");

  const uint64_t wrong_prefix_len =
      static_cast<uint64_t>(key.size() + 1 + message.size());

  const Bytes wrong_glue = sha256_padding_for_length(wrong_prefix_len);

  const std::string wrong_guess_mac = sha256_length_extend(
      naive_original, wrong_prefix_len + wrong_glue.size(), append_bytes);

  // Construct the message produced using the wrong secret-length guess.
  Bytes wrong_forged_message(message.begin(), message.end());
  wrong_forged_message.insert(wrong_forged_message.end(), wrong_glue.begin(),
                              wrong_glue.end());

  wrong_forged_message.insert(wrong_forged_message.end(), append_bytes.begin(),
                              append_bytes.end());

  const std::string wrong_forged_message_string(
      reinterpret_cast<const char*>(wrong_forged_message.data()),
      wrong_forged_message.size());

  // The real server uses the actual key, so this is the MAC it computes for
  // the incorrectly padded forged message.
  const std::string wrong_server_mac =
      naive_mac_sha256_hex(key, wrong_forged_message_string);

  check(wrong_guess_mac != wrong_server_mac,
        "wrong secret-length guess is rejected by the server");

  check(rejects([&] {
          (void)sha256_length_extend("deadbeef", processed_after_glue,
                                     append_bytes);
        }),
        "malformed original SHA-256 MAC is rejected");

  // -----------------------------------------------------------------------
  // X.509 fail-closed behavior
  // -----------------------------------------------------------------------
  const std::string bad_cert_path = "lab4_corrupted_cert_test.pem";
  const Bytes bad_cert({'-', '-', '-', '-', '-', 'B', 'E', 'G',  'I', 'N',
                        ' ', 'C', 'E', 'R', 'T', 'I', 'F', 'I',  'C', 'A',
                        'T', 'E', '-', '-', '-', '-', '-', '\n', 'n', 'o',
                        't', '-', 'a', '-', 'c', 'e', 'r', 't',  '\n'});
  check(write_file_bytes(bad_cert_path, bad_cert),
        "corrupted certificate fixture created");

  X509* bad_cert_obj = load_cert_pem_or_der(bad_cert_path);
  check(bad_cert_obj == nullptr, "corrupted X.509 certificate is rejected");
  if (bad_cert_obj) X509_free(bad_cert_obj);
  std::remove(bad_cert_path.c_str());

  std::cout << "Self-test summary: " << passed << "/" << total << " passed\n";
  if (passed != total) {
    std::cerr << "[ERROR] Lab 4 self-test failed with " << (total - passed)
              << " failure(s).\n";
    return 1;
  }

  std::cout << "ALL LAB 4 AUTOMATED TESTS PASSED\n";
  return 0;
}

static int cmd_md5_collision(const std::map<std::string, std::string>& opts) {
  std::string f1 = require_opt(opts, "file1"), f2 = require_opt(opts, "file2");
  Bytes d1, d2, b1, b2;
  hash_file("md5", f1, 0, d1, nullptr);
  hash_file("md5", f2, 0, d2, nullptr);
  if (!read_file_bytes(f1, b1) || !read_file_bytes(f2, b2))
    throw std::runtime_error("Failed to read input files");
  std::cout << "MD5(" << f1 << ") = " << bytes_to_hex(d1) << "\n";
  std::cout << "MD5(" << f2 << ") = " << bytes_to_hex(d2) << "\n";
  bool same_digest = (d1 == d2), different_files = (b1 != b2);
  std::cout << "Same MD5 digest: " << (same_digest ? "YES" : "NO") << "\n";
  std::cout << "Different file contents: " << (different_files ? "YES" : "NO")
            << "\n";
  std::cout << "Collision demonstration: "
            << (same_digest && different_files ? "SUCCESS" : "NOT A COLLISION")
            << "\n";
  return (same_digest && different_files) ? 0 : 2;
}

static bool file_size_bytes(const std::string& path, uint64_t& size) {
  std::ifstream f(path, std::ios::binary | std::ios::ate);
  if (!f.is_open()) return false;
  std::streampos pos = f.tellg();
  if (pos < 0) return false;
  size = static_cast<uint64_t>(pos);
  return true;
}

static int cmd_bench(const std::map<std::string, std::string>& opts) {
  std::string algo = require_opt(opts, "algo"), in = require_opt(opts, "in");
  int rounds = parse_int_opt(opts, "rounds", 3),
      outlen = parse_int_opt(opts, "outlen", 0);
  if (rounds <= 0) throw std::runtime_error("--rounds must be positive");
  uint64_t sz = 0;
  if (!file_size_bytes(in, sz))
    throw std::runtime_error("Cannot determine input file size");
  double mb = static_cast<double>(sz) / (1024.0 * 1024.0);
  std::cout << "algorithm,file,bytes,round,ms,mbps,digest_hex\n";
  for (int r = 1; r <= rounds; ++r) {
    Bytes digest;
    long long ms = 0;
    hash_file(algo, in, outlen, digest, &ms);
    double seconds = static_cast<double>(ms) / 1000.0;
    double mbps = seconds > 0.0 ? mb / seconds : 0.0;
    std::cout << algo << "," << in << "," << sz << "," << r << "," << ms << ","
              << std::fixed << std::setprecision(2) << mbps << ","
              << bytes_to_hex(digest) << "\n";
  }
  return 0;
}

static int cmd_hash(const std::map<std::string, std::string>& opts) {
  std::string algo = require_opt(opts, "algo"), in = require_opt(opts, "in");
  int outlen = parse_int_opt(opts, "outlen", 0);
  Bytes digest;
  long long ms = 0;
  hash_file(algo, in, outlen, digest, &ms);
  auto raw_it = opts.find("raw");
  if (raw_it != opts.end()) {
    if (!write_file_bytes(raw_it->second, digest))
      throw std::runtime_error("Failed to write raw digest file");
    std::cout << "Raw digest written to " << raw_it->second << "\n";
  } else
    std::cout << bytes_to_hex(digest) << "\n";
  uint64_t sz = 0;
  if (file_size_bytes(in, sz) && ms > 0) {
    double mb = static_cast<double>(sz) / (1024.0 * 1024.0);
    double seconds = static_cast<double>(ms) / 1000.0;
    std::cerr << "Throughput: " << std::fixed << std::setprecision(2)
              << (mb / seconds) << " MB/s\n";
  }
  return 0;
}

static void usage(const char* prog) {
  std::cerr
      << "Usage:\n"
      << "  " << prog << " kat\n"
      << "  " << prog << " selftest\n"
      << "  " << prog
      << " hash --algo <alg> --in <file> [--outlen <bits>] [--raw <file>] "
         "[--stream]\n"
      << "  " << prog
      << " cert --cert <cert.pem|der> [--issuer <issuer.pem|der>]\n"
      << "  " << prog << " md5-collision --file1 <a> --file2 <b>\n"
      << "  " << prog << " mac-naive --key <k> --message <m>\n"
      << "  " << prog << " hmac --key <k> --message <m>\n"
      << "  " << prog
      << " le-sha256 --orig-mac <hex> --orig-msg <m> --append <m2> --key-len "
         "<n>\n"
      << "  " << prog
      << " bench --algo <alg> --in <file> [--rounds <n>] [--outlen <bits>]\n\n"
      << "Hash algorithms:\n"
      << "  sha224, sha256, sha384, sha512\n"
      << "  sha3-224, sha3-256, sha3-384, sha3-512\n"
      << "  shake128, shake256 with --outlen <bits>\n";
}

int main(int argc, char* argv[]) {
  ERR_load_crypto_strings();
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }
  std::string cmd = argv[1];
  try {
    if (cmd == "kat") return cmd_kat();
    if (cmd == "selftest" || cmd == "test") return cmd_selftest();
    auto opts = parse_opts(argc, argv, 2);
    if (opts.count("help")) {
      usage(argv[0]);
      return 0;
    }
    if (cmd == "hash")
      return cmd_hash(opts);
    else if (cmd == "cert")
      return cmd_cert(opts);
    else if (cmd == "md5-collision")
      return cmd_md5_collision(opts);
    else if (cmd == "mac-naive")
      return cmd_mac_naive(opts);
    else if (cmd == "hmac")
      return cmd_hmac(opts);
    else if (cmd == "le-sha256")
      return cmd_le_sha256(opts);
    else if (cmd == "bench")
      return cmd_bench(opts);
    else {
      std::cerr << "Unknown command: " << cmd << "\n";
      usage(argv[0]);
      return 1;
    }
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    print_openssl_errors();
    return 1;
  }
}
