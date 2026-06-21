#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <stdexcept>
#include <string>
#include <vector>

// ── Type alias
// ────────────────────────────────────────────────────────────────

using Bytes = std::vector<unsigned char>;

// ── OpenSSL error helper
// ──────────────────────────────────────────────────────

static std::string ossl_error(const std::string& context) {
  char buf[256];
  unsigned long e = ERR_get_error();
  ERR_error_string_n(e, buf, sizeof(buf));
  return context + ": " + buf;
}

// ── Base64 encode / decode
// ────────────────────────────────────────────────────

static std::string base64_encode(const Bytes& data) {
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* mem = BIO_new(BIO_s_mem());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, mem);
  BIO_write(b64, data.data(), (int)data.size());
  BIO_flush(b64);
  const char* ptr;
  long len = BIO_get_mem_data(mem, &ptr);
  std::string result(ptr, len);
  BIO_free_all(b64);
  return result;
}

static Bytes base64_decode(const std::string& s) {
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* mem = BIO_new_mem_buf(s.data(), (int)s.size());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_push(b64, mem);
  Bytes out(s.size());
  int len = BIO_read(b64, out.data(), (int)out.size());
  BIO_free_all(b64);
  if (len < 0) throw std::runtime_error("base64_decode failed");
  out.resize(len);
  return out;
}

// ── Hex encode / decode
// ───────────────────────────────────────────────────────

static std::string bytes_to_hex(const Bytes& data) {
  static const char* hex = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (unsigned char b : data) {
    out += hex[b >> 4];
    out += hex[b & 0xF];
  }
  return out;
}

static Bytes hex_to_bytes(const std::string& s) {
  if (s.size() % 2 != 0) throw std::runtime_error("hex string has odd length");
  Bytes out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    auto nibble = [](char c) -> unsigned char {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return 10 + c - 'a';
      if (c >= 'A' && c <= 'F') return 10 + c - 'A';
      throw std::runtime_error(std::string("invalid hex char: ") + c);
    };
    out.push_back((nibble(s[i]) << 4) | nibble(s[i + 1]));
  }
  return out;
}

// ── File I/O
// ──────────────────────────────────────────────────────────────────

static Bytes read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open file for reading: " + path);
  return Bytes(std::istreambuf_iterator<char>(f), {});
}

static void write_file(const std::string& path, const Bytes& data) {
  std::ofstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open file for writing: " + path);
  f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

static void write_file(const std::string& path, const std::string& data) {
  std::ofstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("cannot open file for writing: " + path);
  f.write(data.data(), data.size());
}

// ── RSA key generation & helpers
// ──────────────────────────────────────────────

struct KeyPair {
  EVP_PKEY* pkey = nullptr;
  ~KeyPair() {
    if (pkey) EVP_PKEY_free(pkey);
  }
};

static std::unique_ptr<KeyPair> rsa_keygen(int bits) {
  if (bits != 3072 && bits != 4096) {
    throw std::invalid_argument(
        "RSA key size must be exactly 3072 or 4096 bits");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx) throw std::runtime_error(ossl_error("EVP_PKEY_CTX_new_id"));
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error(ossl_error("keygen_init"));
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error(ossl_error("set_rsa_bits"));
  }
  auto kp = std::make_unique<KeyPair>();
  if (EVP_PKEY_keygen(ctx, &kp->pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error(ossl_error("EVP_PKEY_keygen"));
  }
  EVP_PKEY_CTX_free(ctx);
  return kp;
}

static int pkey_bits(EVP_PKEY* k) { return EVP_PKEY_get_bits(k); }

// PEM serialisation helpers

static Bytes pkey_to_pem_pub(EVP_PKEY* k) {
  BIO* bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PUBKEY(bio, k)) {
    BIO_free(bio);
    throw std::runtime_error(ossl_error("PEM_write_bio_PUBKEY"));
  }
  const char* ptr;
  long len = BIO_get_mem_data(bio, &ptr);
  Bytes out(ptr, ptr + len);
  BIO_free(bio);
  return out;
}

static Bytes pkey_to_pem_priv(EVP_PKEY* k) {
  BIO* bio = BIO_new(BIO_s_mem());
  if (!PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr,
                                nullptr)) {
    BIO_free(bio);
    throw std::runtime_error(ossl_error("PEM_write_bio_PrivateKey"));
  }
  const char* ptr;
  long len = BIO_get_mem_data(bio, &ptr);
  Bytes out(ptr, ptr + len);
  BIO_free(bio);
  return out;
}

static Bytes pkey_to_der_pub(EVP_PKEY* k) {
  unsigned char* buf = nullptr;
  int len = i2d_PUBKEY(k, &buf);
  if (len < 0) throw std::runtime_error(ossl_error("i2d_PUBKEY"));
  Bytes out(buf, buf + len);
  OPENSSL_free(buf);
  return out;
}

static Bytes pkey_to_der_priv(EVP_PKEY* k) {
  unsigned char* buf = nullptr;
  int len = i2d_PrivateKey(k, &buf);
  if (len < 0) throw std::runtime_error(ossl_error("i2d_PrivateKey"));
  Bytes out(buf, buf + len);
  OPENSSL_free(buf);
  return out;
}

static EVP_PKEY* load_pubkey_file(const std::string& path) {
  Bytes data = read_file(path);
  BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
  EVP_PKEY* k = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!k) throw std::runtime_error("failed to load public key: " + path);
  return k;
}

static EVP_PKEY* load_privkey_file(const std::string& path) {
  Bytes data = read_file(path);
  BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
  EVP_PKEY* k = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (!k) throw std::runtime_error("failed to load private key: " + path);
  return k;
}

// ── Constants ────────────────────────────────────────────────────────────────

static constexpr int AES_KEY_BYTES = 32;  // AES-256
static constexpr int GCM_IV_BYTES = 12;   // 96-bit IV
static constexpr int GCM_TAG_BYTES = 16;  // 128-bit tag
static constexpr int SHA256_BYTES = 32;   // hLen for OAEP

// Max plaintext for RSA-OAEP(SHA-256): k - 2*hLen - 2
inline size_t rsa_oaep_max_plaintext(int modulus_bits) {
  return (modulus_bits / 8) - 2 * SHA256_BYTES - 2;
}

// ── MGF1(SHA-256)
// ───────────────────────────────────────────────────────────── Mask Generation
// Function 1 per PKCS#1 v2.2 §B.2.1

inline Bytes mgf1_sha256(const Bytes& seed, size_t mask_len) {
  const size_t hLen = SHA256_DIGEST_LENGTH;  // 32
  if (mask_len > ((uint64_t)1 << 32) * hLen)
    throw std::invalid_argument("MGF1: mask too long");

  Bytes mask;
  mask.reserve(mask_len);

  for (uint32_t counter = 0; mask.size() < mask_len; ++counter) {
    // C = I2OSP(counter, 4)  — big-endian 4-byte counter
    unsigned char c[4] = {
        (unsigned char)(counter >> 24), (unsigned char)(counter >> 16),
        (unsigned char)(counter >> 8), (unsigned char)(counter)};
    // Hash( seed || C )
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int dlen = SHA256_DIGEST_LENGTH;
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, seed.data(), seed.size());
    EVP_DigestUpdate(ctx, c, 4);
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);

    size_t take =
        std::min((size_t)SHA256_DIGEST_LENGTH, mask_len - mask.size());
    mask.insert(mask.end(), digest, digest + take);
  }
  return mask;
}

// ── OAEP encode
// ─────────────────────────────────────────────────────────────── EM = 0x00 ||
// maskedSeed || maskedDB DB = lHash || PS || 0x01 || M Per RFC 8017 §7.1.1

inline Bytes oaep_encode_manual(const Bytes& message, size_t emLen,
                                const std::string& label = "") {
  const size_t hLen = SHA256_DIGEST_LENGTH;
  if (emLen < 2 * hLen + 2) throw std::invalid_argument("emLen too short");
  size_t mLen = message.size();
  size_t psLen = emLen - mLen - 2 * hLen - 2;
  if (mLen > emLen - 2 * hLen - 2)
    throw std::invalid_argument("message too long for OAEP");

  // lHash = SHA-256(label)
  Bytes lHash(hLen);
  {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned int dlen = hLen;
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    if (!label.empty()) EVP_DigestUpdate(ctx, label.data(), label.size());
    EVP_DigestFinal_ex(ctx, lHash.data(), &dlen);
    EVP_MD_CTX_free(ctx);
  }

  // DB = lHash || PS (zero bytes) || 0x01 || M
  Bytes DB;
  DB.reserve(emLen - hLen - 1);
  DB.insert(DB.end(), lHash.begin(), lHash.end());
  DB.insert(DB.end(), psLen, 0x00);
  DB.push_back(0x01);
  DB.insert(DB.end(), message.begin(), message.end());

  // seed = random hLen bytes
  Bytes seed(hLen);
  if (RAND_bytes(seed.data(), hLen) != 1)
    throw std::runtime_error("RAND_bytes failed for OAEP seed");

  // dbMask = MGF1(seed, emLen - hLen - 1)
  Bytes dbMask = mgf1_sha256(seed, emLen - hLen - 1);
  // maskedDB = DB XOR dbMask
  Bytes maskedDB(DB.size());
  for (size_t i = 0; i < DB.size(); ++i) maskedDB[i] = DB[i] ^ dbMask[i];

  // seedMask = MGF1(maskedDB, hLen)
  Bytes seedMask = mgf1_sha256(maskedDB, hLen);
  // maskedSeed = seed XOR seedMask
  Bytes maskedSeed(hLen);
  for (size_t i = 0; i < hLen; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

  // EM = 0x00 || maskedSeed || maskedDB
  Bytes EM;
  EM.reserve(emLen);
  EM.push_back(0x00);
  EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
  EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
  return EM;
}

// ── OAEP decode
// ─────────────────────────────────────────────────────────────── CRITICAL: All
// comparisons must be constant-time to prevent timing attacks. We use
// CRYPTO_memcmp (OpenSSL) for lHash comparison. The entire decode runs to
// completion before branching on error flags — this prevents an attacker from
// learning WHICH check failed via timing.

inline Bytes oaep_decode_manual(const Bytes& EM, size_t emLen,
                                const std::string& label = "") {
  const size_t hLen = SHA256_DIGEST_LENGTH;

  // Step 1: length checks
  if (EM.size() != emLen || emLen < 2 * hLen + 2)
    throw std::runtime_error("OAEP decode: invalid encoded message length");

  // Step 2: Compute lHash
  Bytes lHash(hLen);
  {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned int dlen = hLen;
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    if (!label.empty()) EVP_DigestUpdate(ctx, label.data(), label.size());
    EVP_DigestFinal_ex(ctx, lHash.data(), &dlen);
    EVP_MD_CTX_free(ctx);
  }

  // Step 3: Parse EM
  unsigned char Y = EM[0];
  Bytes maskedSeed(EM.begin() + 1, EM.begin() + 1 + hLen);
  Bytes maskedDB(EM.begin() + 1 + hLen, EM.end());

  // Step 4: Recover seed
  Bytes seedMask = mgf1_sha256(maskedDB, hLen);
  Bytes seed(hLen);
  for (size_t i = 0; i < hLen; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

  // Step 5: Recover DB
  Bytes dbMask = mgf1_sha256(seed, emLen - hLen - 1);
  Bytes DB(maskedDB.size());
  for (size_t i = 0; i < maskedDB.size(); ++i) DB[i] = maskedDB[i] ^ dbMask[i];

  // Step 6: Validate — collect all error flags before branching (constant-time
  // style) lHash' == lHash?
  int hash_bad = CRYPTO_memcmp(DB.data(), lHash.data(), hLen);
  // Y == 0x00?
  int Y_bad = (Y != 0x00) ? 1 : 0;
  // Find 0x01 separator after PS (variable-length zero run)
  size_t sep = std::string::npos;
  for (size_t i = hLen; i < DB.size(); ++i) {
    if (DB[i] == 0x01) {
      sep = i;
      break;
    }
    if (DB[i] != 0x00) break;  // non-zero before 0x01 — invalid
  }
  int sep_bad = (sep == std::string::npos) ? 1 : 0;

  // Branch ONCE after all checks (minimises timing leak)
  if (Y_bad | hash_bad | sep_bad)
    throw std::runtime_error(
        "OAEP decode: padding validation failed (wrong label or corrupted "
        "data)");

  return Bytes(DB.begin() + sep + 1, DB.end());
}

// ── RSA-OAEP encrypt / decrypt ───────────────────────────────────────────────

// Returns ciphertext bytes. label may be empty.
inline Bytes rsa_oaep_encrypt(EVP_PKEY* pub, const Bytes& plaintext,
                              const std::string& label = "") {
  int bits = pkey_bits(pub);
  size_t max_pt = rsa_oaep_max_plaintext(bits);
  if (plaintext.size() > max_pt)
    throw std::invalid_argument("plaintext too large for RSA-OAEP with " +
                                std::to_string(bits) +
                                "-bit key "
                                "(max " +
                                std::to_string(max_pt) + " bytes, got " +
                                std::to_string(plaintext.size()) + ")");

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
  if (!ctx) throw std::runtime_error(ossl_error("EVP_PKEY_CTX_new (enc)"));

  auto cleanup = [&] { EVP_PKEY_CTX_free(ctx); };

  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("encrypt_init"));
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("set_padding"));
  }
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("set_oaep_md"));
  }
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("set_mgf1_md"));
  }

  if (!label.empty()) {
    // OpenSSL takes ownership of the label copy
    unsigned char* lbl =
        (unsigned char*)OPENSSL_memdup(label.data(), label.size());
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lbl, (int)label.size()) <= 0) {
      OPENSSL_free(lbl);
      cleanup();
      throw std::runtime_error(ossl_error("set_label"));
    }
  }

  size_t ct_len = 0;
  if (EVP_PKEY_encrypt(ctx, nullptr, &ct_len, plaintext.data(),
                       plaintext.size()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("encrypt size"));
  }

  Bytes ct(ct_len);
  if (EVP_PKEY_encrypt(ctx, ct.data(), &ct_len, plaintext.data(),
                       plaintext.size()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("EVP_PKEY_encrypt"));
  }

  ct.resize(ct_len);
  cleanup();
  return ct;
}

inline Bytes rsa_oaep_decrypt(EVP_PKEY* priv, const Bytes& ct,
                              const std::string& label = "") {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
  if (!ctx) throw std::runtime_error(ossl_error("EVP_PKEY_CTX_new (dec)"));

  auto cleanup = [&] { EVP_PKEY_CTX_free(ctx); };

  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("decrypt_init"));
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("set_padding"));
  }
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("set_oaep_md"));
  }
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("set_mgf1_md"));
  }

  if (!label.empty()) {
    unsigned char* lbl =
        (unsigned char*)OPENSSL_memdup(label.data(), label.size());
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, lbl, (int)label.size()) <= 0) {
      OPENSSL_free(lbl);
      cleanup();
      throw std::runtime_error(ossl_error("set_label"));
    }
  }

  size_t pt_len = 0;
  if (EVP_PKEY_decrypt(ctx, nullptr, &pt_len, ct.data(), ct.size()) <= 0) {
    cleanup();
    throw std::runtime_error(ossl_error("decrypt size"));
  }

  Bytes pt(pt_len);
  if (EVP_PKEY_decrypt(ctx, pt.data(), &pt_len, ct.data(), ct.size()) <= 0) {
    cleanup();
    throw std::runtime_error(
        "RSA-OAEP decryption failed: wrong key or corrupted/tampered "
        "ciphertext");
  }

  pt.resize(pt_len);
  cleanup();
  return pt;
}

// ── AES-256-GCM encrypt / decrypt ────────────────────────────────────────────

struct GCMResult {
  Bytes ciphertext;
  Bytes iv;   // 12 bytes
  Bytes tag;  // 16 bytes
};

inline GCMResult aes_gcm_encrypt(const Bytes& key, const Bytes& plaintext,
                                 const Bytes& aad = {}) {
  if (key.size() != AES_KEY_BYTES)
    throw std::invalid_argument("AES key must be 32 bytes");

  GCMResult r;
  r.iv.resize(GCM_IV_BYTES);
  if (RAND_bytes(r.iv.data(), GCM_IV_BYTES) != 1)
    throw std::runtime_error("RAND_bytes failed");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new");

  auto cleanup = [&] { EVP_CIPHER_CTX_free(ctx); };

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1) {
    cleanup();
    throw std::runtime_error(ossl_error("EncryptInit_ex"));
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_BYTES, nullptr) !=
      1) {
    cleanup();
    throw std::runtime_error(ossl_error("set_ivlen"));
  }
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), r.iv.data()) != 1) {
    cleanup();
    throw std::runtime_error(ossl_error("EncryptInit key/iv"));
  }

  if (!aad.empty()) {
    int dummy = 0;
    if (EVP_EncryptUpdate(ctx, nullptr, &dummy, aad.data(), (int)aad.size()) !=
        1) {
      cleanup();
      throw std::runtime_error(ossl_error("AAD update"));
    }
  }

  r.ciphertext.resize(plaintext.size());
  int out_len = 0;
  if (!plaintext.empty()) {
    if (EVP_EncryptUpdate(ctx, r.ciphertext.data(), &out_len, plaintext.data(),
                          (int)plaintext.size()) != 1) {
      cleanup();
      throw std::runtime_error(ossl_error("EncryptUpdate"));
    }
  }
  int final_len = 0;
  if (EVP_EncryptFinal_ex(ctx, r.ciphertext.data() + out_len, &final_len) !=
      1) {
    cleanup();
    throw std::runtime_error(ossl_error("EncryptFinal"));
  }
  r.ciphertext.resize(out_len + final_len);

  r.tag.resize(GCM_TAG_BYTES);
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES,
                          r.tag.data()) != 1) {
    cleanup();
    throw std::runtime_error(ossl_error("GET_TAG"));
  }

  cleanup();
  return r;
}

inline Bytes aes_gcm_decrypt(const Bytes& key, const Bytes& ct, const Bytes& iv,
                             const Bytes& tag, const Bytes& aad = {}) {
  if (key.size() != AES_KEY_BYTES)
    throw std::invalid_argument("AES key must be 32 bytes");
  if (iv.size() != GCM_IV_BYTES)
    throw std::invalid_argument("IV must be 12 bytes");
  if (tag.size() != GCM_TAG_BYTES)
    throw std::invalid_argument("tag must be 16 bytes");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new");
  auto cleanup = [&] { EVP_CIPHER_CTX_free(ctx); };

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) !=
      1) {
    cleanup();
    throw std::runtime_error(ossl_error("DecryptInit_ex"));
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_BYTES, nullptr) !=
      1) {
    cleanup();
    throw std::runtime_error(ossl_error("set_ivlen"));
  }
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
    cleanup();
    throw std::runtime_error(ossl_error("DecryptInit key/iv"));
  }

  if (!aad.empty()) {
    int dummy = 0;
    if (EVP_DecryptUpdate(ctx, nullptr, &dummy, aad.data(), (int)aad.size()) !=
        1) {
      cleanup();
      throw std::runtime_error(ossl_error("AAD update dec"));
    }
  }

  Bytes pt(ct.size());
  int out_len = 0;
  if (!ct.empty()) {
    if (EVP_DecryptUpdate(ctx, pt.data(), &out_len, ct.data(),
                          (int)ct.size()) != 1) {
      cleanup();
      throw std::runtime_error(ossl_error("DecryptUpdate"));
    }
  }

  // Set expected tag BEFORE final (constant-time comparison by OpenSSL)
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_BYTES,
                          const_cast<unsigned char*>(tag.data())) != 1) {
    cleanup();
    throw std::runtime_error(ossl_error("SET_TAG"));
  }

  int final_len = 0;
  int ret = EVP_DecryptFinal_ex(ctx, pt.data() + out_len, &final_len);
  cleanup();
  if (ret <= 0)
    throw std::runtime_error(
        "AES-GCM authentication failed: ciphertext has been tampered");

  pt.resize(out_len + final_len);
  return pt;
}

// ── Hybrid envelope ──────────────────────────────────────────────────────────

// JSON envelope structure (header only; payload is raw AES-GCM ciphertext
// appended)
struct Envelope {
  int rsa_modulus = 0;
  Bytes wrapped_key;  // RSA-OAEP encrypted AES key
  Bytes iv;
  Bytes tag;
  Bytes ciphertext;
  std::string label;
};

// Simple JSON builder (no dependency on nlohmann/json intentionally)
inline std::string envelope_to_json(const Envelope& e) {
  return "{\n"
         "  \"mode\": \"RSA-OAEP-AES-GCM\",\n"
         "  \"rsa_modulus\": " +
         std::to_string(e.rsa_modulus) +
         ",\n"
         "  \"hash\": \"SHA-256\",\n"
         "  \"wrapped_key\": \"" +
         base64_encode(e.wrapped_key) +
         "\",\n"
         "  \"iv\": \"" +
         base64_encode(e.iv) +
         "\",\n"
         "  \"tag\": \"" +
         base64_encode(e.tag) +
         "\",\n"
         "  \"label\": \"" +
         e.label +
         "\",\n"
         "  \"ciphertext\": \"" +
         base64_encode(e.ciphertext) +
         "\"\n"
         "}";
}

// Minimal JSON field extractor (handles string and int values)
inline std::string json_get_str(const std::string& json,
                                const std::string& key) {
  std::string search = "\"" + key + "\"";
  auto pos = json.find(search);
  if (pos == std::string::npos)
    throw std::runtime_error("missing JSON field: " + key);
  pos = json.find(':', pos);
  if (pos == std::string::npos) throw std::runtime_error("bad JSON");
  pos = json.find('"', pos);
  if (pos == std::string::npos)
    throw std::runtime_error("bad JSON value for: " + key);
  auto end = json.find('"', pos + 1);
  if (end == std::string::npos)
    throw std::runtime_error("unterminated JSON string: " + key);
  return json.substr(pos + 1, end - pos - 1);
}

inline int json_get_int(const std::string& json, const std::string& key) {
  std::string search = "\"" + key + "\"";
  auto pos = json.find(search);
  if (pos == std::string::npos)
    throw std::runtime_error("missing JSON field: " + key);
  pos = json.find(':', pos);
  if (pos == std::string::npos) throw std::runtime_error("bad JSON");
  while (pos < json.size() && (json[pos + 1] == ' ' || json[pos + 1] == '\n'))
    pos++;
  return std::stoi(json.substr(pos + 1));
}

inline Envelope envelope_from_json(const std::string& json) {
  Envelope e;
  // Validate mode
  std::string mode = json_get_str(json, "mode");
  if (mode != "RSA-OAEP-AES-GCM")
    throw std::runtime_error("unsupported envelope mode: " + mode);
  std::string hash = json_get_str(json, "hash");
  if (hash != "SHA-256")
    throw std::runtime_error("unsupported hash in envelope: " + hash);
  e.rsa_modulus = json_get_int(json, "rsa_modulus");
  e.wrapped_key = base64_decode(json_get_str(json, "wrapped_key"));
  e.iv = base64_decode(json_get_str(json, "iv"));
  e.tag = base64_decode(json_get_str(json, "tag"));
  e.ciphertext = base64_decode(json_get_str(json, "ciphertext"));
  // label may be empty
  try {
    e.label = json_get_str(json, "label");
  } catch (...) {
  }
  // Validate sizes
  if (e.iv.size() != GCM_IV_BYTES)
    throw std::runtime_error("envelope: bad IV length");
  if (e.tag.size() != GCM_TAG_BYTES)
    throw std::runtime_error("envelope: bad tag length");
  return e;
}

// ── High-level encrypt / decrypt ─────────────────────────────────────────────

// Returns JSON envelope string (all data self-contained in JSON)
inline std::string hybrid_encrypt(EVP_PKEY* pub, const Bytes& plaintext,
                                  const std::string& label = "") {
  // 1. Generate random AES-256 key
  Bytes aes_key(AES_KEY_BYTES);
  if (RAND_bytes(aes_key.data(), AES_KEY_BYTES) != 1)
    throw std::runtime_error("RAND_bytes failed for AES key");

  // 2. Encrypt plaintext with AES-256-GCM
  auto gcm = aes_gcm_encrypt(aes_key, plaintext);

  // 3. Wrap AES key with RSA-OAEP
  Bytes wrapped = rsa_oaep_encrypt(pub, aes_key, label);

  Envelope env;
  env.rsa_modulus = pkey_bits(pub);
  env.wrapped_key = wrapped;
  env.iv = gcm.iv;
  env.tag = gcm.tag;
  env.ciphertext = gcm.ciphertext;
  env.label = label;

  return envelope_to_json(env);
}

inline Bytes hybrid_decrypt(EVP_PKEY* priv, const std::string& json_envelope) {
  Envelope env;
  try {
    env = envelope_from_json(json_envelope);
  } catch (const std::exception& ex) {
    throw std::runtime_error(std::string("envelope parse error: ") + ex.what());
  }

  // Validate key size matches envelope claim
  int actual_bits = pkey_bits(priv);
  if (actual_bits != env.rsa_modulus)
    throw std::runtime_error(
        "key mismatch: envelope claims " + std::to_string(env.rsa_modulus) +
        "-bit RSA, but key is " + std::to_string(actual_bits) + "-bit");

  // 1. Unwrap AES key
  Bytes aes_key = rsa_oaep_decrypt(priv, env.wrapped_key, env.label);
  if (aes_key.size() != AES_KEY_BYTES)
    throw std::runtime_error("unwrapped key has unexpected size");

  // 2. Decrypt ciphertext
  return aes_gcm_decrypt(aes_key, env.ciphertext, env.iv, env.tag);
}

// ── Auto-dispatch encrypt (chooses direct RSA or hybrid) ─────────────────────

enum class EncMode { RSA_DIRECT, HYBRID };

struct EncryptResult {
  EncMode mode;
  Bytes rsa_ct;          // used when mode == RSA_DIRECT
  std::string envelope;  // used when mode == HYBRID
};

inline EncryptResult auto_encrypt(EVP_PKEY* pub, const Bytes& plaintext,
                                  const std::string& label = "") {
  int bits = pkey_bits(pub);
  size_t max_pt = rsa_oaep_max_plaintext(bits);
  EncryptResult r;
  if (plaintext.size() <= max_pt) {
    r.mode = EncMode::RSA_DIRECT;
    r.rsa_ct = rsa_oaep_encrypt(pub, plaintext, label);
  } else {
    r.mode = EncMode::HYBRID;
    r.envelope = hybrid_encrypt(pub, plaintext, label);
  }
  return r;
}

// ── Argument parsing ─────────────────────────────────────────────────────────

struct Args {
  std::string command;  // keygen | encrypt | decrypt | info | test-oaep
  // keygen / benchmark
  int bits = 3072;
  int runs = 30;
  std::string pub_path, priv_path;
  // encrypt / decrypt
  std::string in_path, out_path, label;
  // encoding
  std::string encoding = "raw";  // raw | hex | base64
};

static void usage(const char* prog) {
  fprintf(
      stderr,
      "Usage:\n"
      "  %s keygen  --bits <3072|4096> --pub <pub.pem> --priv <priv.pem>\n"
      "  %s encrypt --in <file> --pub <pub.pem> --out <ct.bin> [--label <str>] "
      "[--enc raw|hex|base64]\n"
      "  %s decrypt --in <ct.bin> --priv <priv.pem> --out <file> [--label "
      "<str>] [--enc raw|hex|base64]\n"
      "  %s info    --pub <pub.pem>|--priv <priv.pem>\n"
      "  %s benchmark --bits <3072|4096> [--runs <N>]\n"
      "  %s test-oaep|selftest  (run Lab 3 automated tests)\n",
      prog, prog, prog, prog, prog, prog);
  exit(1);
}

static Args parse_args(int argc, char** argv) {
  if (argc < 2) usage(argv[0]);
  Args a;
  a.command = argv[1];
  for (int i = 2; i < argc; i++) {
    auto eq = [&](const char* s) { return strcmp(argv[i], s) == 0; };
    auto next = [&]() -> const char* {
      if (i + 1 >= argc) {
        fprintf(stderr, "missing value for %s\n", argv[i]);
        exit(1);
      }
      return argv[++i];
    };
    if (eq("--bits"))
      a.bits = atoi(next());
    else if (eq("--runs"))
      a.runs = atoi(next());
    else if (eq("--pub"))
      a.pub_path = next();
    else if (eq("--priv"))
      a.priv_path = next();
    else if (eq("--in"))
      a.in_path = next();
    else if (eq("--out"))
      a.out_path = next();
    else if (eq("--label"))
      a.label = next();
    else if (eq("--enc"))
      a.encoding = next();
    else {
      fprintf(stderr, "unknown option: %s\n", argv[i]);
      exit(1);
    }
  }
  return a;
}

// ── ISO 8601 timestamp
// ────────────────────────────────────────────────────────

static std::string iso_time() {
  time_t t = time(nullptr);
  char buf[32];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
  return buf;
}

// ── Encoding helpers
// ──────────────────────────────────────────────────────────

static Bytes encode_output(const Bytes& data, const std::string& enc) {
  if (enc == "raw") return data;
  if (enc == "hex") {
    auto s = bytes_to_hex(data);
    return Bytes(s.begin(), s.end());
  }
  if (enc == "base64") {
    auto s = base64_encode(data);
    return Bytes(s.begin(), s.end());
  }
  throw std::runtime_error("unknown encoding: " + enc +
                           " (use raw|hex|base64)");
}

static Bytes decode_input(const Bytes& data, const std::string& enc) {
  if (enc == "raw") return data;
  std::string s(data.begin(), data.end());
  if (enc == "hex") return hex_to_bytes(s);
  if (enc == "base64") return base64_decode(s);
  throw std::runtime_error("unknown encoding: " + enc);
}

// ── Commands ─────────────────────────────────────────────────────────────────

static int cmd_keygen(const Args& a) {
  if (a.pub_path.empty() || a.priv_path.empty()) {
    fprintf(stderr, "keygen requires --pub and --priv\n");
    return 1;
  }
  if (a.bits != 3072 && a.bits != 4096) {
    fprintf(stderr, "key size must be exactly 3072 or 4096 bits\n");
    return 1;
  }

  printf("Generating %d-bit RSA key pair...\n", a.bits);
  auto start = std::chrono::high_resolution_clock::now();
  auto kp = rsa_keygen(a.bits);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now() - start)
                .count();
  std::cout << "Key generated in " << ms << " ms\n";

  // PEM
  write_file(a.pub_path, pkey_to_pem_pub(kp->pkey));
  write_file(a.priv_path, pkey_to_pem_priv(kp->pkey));
  printf("PEM public key  -> %s\n", a.pub_path.c_str());
  printf("PEM private key -> %s\n", a.priv_path.c_str());

  // DER
  auto der_pub_path = a.pub_path + ".der";
  auto der_priv_path = a.priv_path + ".der";
  write_file(der_pub_path, pkey_to_der_pub(kp->pkey));
  write_file(der_priv_path, pkey_to_der_priv(kp->pkey));
  printf("DER public key  -> %s\n", der_pub_path.c_str());
  printf("DER private key -> %s\n", der_priv_path.c_str());

  // Metadata JSON
  auto meta_path = a.pub_path + ".meta.json";
  std::string meta =
      "{\n"
      "  \"creation_time\": \"" +
      iso_time() +
      "\",\n"
      "  \"modulus_bits\": " +
      std::to_string(a.bits) +
      ",\n"
      "  \"hash\": \"SHA-256\",\n"
      "  \"oaep_max_plaintext_bytes\": " +
      std::to_string(rsa_oaep_max_plaintext(a.bits)) +
      "\n"
      "}\n";
  write_file(meta_path, meta);
  printf("Metadata JSON   -> %s\n", meta_path.c_str());

  return 0;
}

static int cmd_encrypt(const Args& a) {
  if (a.in_path.empty() || a.pub_path.empty() || a.out_path.empty()) {
    fprintf(stderr, "encrypt requires --in, --pub, --out\n");
    return 1;
  }

  Bytes plaintext = read_file(a.in_path);
  EVP_PKEY* pub = load_pubkey_file(a.pub_path);

  int bits = pkey_bits(pub);
  size_t max = rsa_oaep_max_plaintext(bits);
  printf("Plaintext: %zu bytes | RSA-%d OAEP limit: %zu bytes\n",
         plaintext.size(), bits, max);

  if (plaintext.size() <= max) {
    printf("Mode: RSA-OAEP direct\n");
    Bytes ct = rsa_oaep_encrypt(pub, plaintext, a.label);
    Bytes out = encode_output(ct, a.encoding);
    write_file(a.out_path, out);
    printf("Ciphertext (%s) -> %s\n", a.encoding.c_str(), a.out_path.c_str());
  } else {
    printf(
        "Mode: Hybrid (RSA-OAEP + AES-256-GCM) — plaintext exceeds direct RSA "
        "limit\n");
    std::string envelope = hybrid_encrypt(pub, plaintext, a.label);
    write_file(a.out_path, Bytes(envelope.begin(), envelope.end()));
    printf("Envelope JSON -> %s\n", a.out_path.c_str());
  }

  EVP_PKEY_free(pub);
  return 0;
}

static int cmd_decrypt(const Args& a) {
  if (a.in_path.empty() || a.priv_path.empty() || a.out_path.empty()) {
    fprintf(stderr, "decrypt requires --in, --priv, --out\n");
    return 1;
  }

  Bytes raw = read_file(a.in_path);
  EVP_PKEY* priv = load_privkey_file(a.priv_path);

  // Detect mode: JSON envelope starts with '{'
  std::string s(raw.begin(), raw.end());
  bool is_hybrid = (s.find("{") != std::string::npos &&
                    s.find("RSA-OAEP-AES-GCM") != std::string::npos);

  Bytes plaintext;
  if (is_hybrid) {
    printf("Mode: Hybrid envelope decryption\n");
    plaintext = hybrid_decrypt(priv, s);
  } else {
    printf("Mode: RSA-OAEP direct decryption\n");
    Bytes ct = decode_input(raw, a.encoding);
    plaintext = rsa_oaep_decrypt(priv, ct, a.label);
  }

  write_file(a.out_path, plaintext);
  printf("Plaintext (%zu bytes) -> %s\n", plaintext.size(), a.out_path.c_str());
  EVP_PKEY_free(priv);
  return 0;
}

static int cmd_info(const Args& a) {
  if (!a.pub_path.empty()) {
    EVP_PKEY* k = load_pubkey_file(a.pub_path);
    int bits = pkey_bits(k);
    printf("Public key:   %s\n", a.pub_path.c_str());
    printf("Modulus bits: %d\n", bits);
    printf("OAEP(SHA-256) max plaintext: %zu bytes\n",
           rsa_oaep_max_plaintext(bits));
    EVP_PKEY_free(k);
  } else if (!a.priv_path.empty()) {
    EVP_PKEY* k = load_privkey_file(a.priv_path);
    int bits = pkey_bits(k);
    printf("Private key:  %s\n", a.priv_path.c_str());
    printf("Modulus bits: %d\n", bits);
    printf("OAEP(SHA-256) max plaintext: %zu bytes\n",
           rsa_oaep_max_plaintext(bits));
    EVP_PKEY_free(k);
  } else {
    fprintf(stderr, "info requires --pub or --priv\n");
    return 1;
  }
  return 0;
}


struct BenchStats {
  double mean_ms = 0.0;
  double median_ms = 0.0;
  double stddev_ms = 0.0;
  double ci95_ms = 0.0;
};

static BenchStats calculate_bench_stats(std::vector<double> values) {
  if (values.empty())
    throw std::invalid_argument("benchmark sample set is empty");

  BenchStats stats;
  stats.mean_ms =
      std::accumulate(values.begin(), values.end(), 0.0) /
      static_cast<double>(values.size());

  std::sort(values.begin(), values.end());
  const size_t n = values.size();
  stats.median_ms =
      (n % 2 == 0)
          ? (values[n / 2 - 1] + values[n / 2]) / 2.0
          : values[n / 2];

  if (n > 1) {
    double squared_sum = 0.0;
    for (double value : values) {
      const double difference = value - stats.mean_ms;
      squared_sum += difference * difference;
    }
    stats.stddev_ms =
        std::sqrt(squared_sum / static_cast<double>(n - 1));
    stats.ci95_ms =
        1.96 * stats.stddev_ms / std::sqrt(static_cast<double>(n));
  }

  return stats;
}

template <typename Function>
static std::vector<double> measure_runs_ms(int runs, Function&& function) {
  std::vector<double> values;
  values.reserve(static_cast<size_t>(runs));

  for (int i = 0; i < runs; ++i) {
    const auto start = std::chrono::steady_clock::now();
    function();
    const auto finish = std::chrono::steady_clock::now();

    values.push_back(
        std::chrono::duration<double, std::milli>(finish - start).count());
  }
  return values;
}

static void print_benchmark_row(const std::string& algorithm,
                                const std::string& operation,
                                size_t size_bytes, int runs,
                                const BenchStats& stats) {
  const double seconds = stats.mean_ms / 1000.0;
  const double mib =
      static_cast<double>(size_bytes) / (1024.0 * 1024.0);
  const double ops_per_second =
      stats.mean_ms > 0.0 ? 1000.0 / stats.mean_ms : 0.0;
  const double throughput_mib_s =
      size_bytes > 0 && seconds > 0.0 ? mib / seconds : 0.0;

  std::cout << algorithm << ',' << operation << ',' << size_bytes << ','
            << runs << ',' << std::fixed << std::setprecision(6)
            << stats.mean_ms << ',' << stats.median_ms << ','
            << stats.stddev_ms << ',' << stats.ci95_ms << ','
            << ops_per_second << ',' << throughput_mib_s << '\n';
}

static int cmd_benchmark(const Args& args) {
  if (args.bits != 3072 && args.bits != 4096) {
    std::cerr << "benchmark requires --bits 3072 or 4096\n";
    return 1;
  }
  if (args.runs < 2) {
    std::cerr << "benchmark requires --runs >= 2\n";
    return 1;
  }

  const std::string rsa_name = "RSA-" + std::to_string(args.bits);

  std::cout
      << "algorithm,operation,size_bytes,runs,mean_ms,median_ms,stddev_ms,"
         "ci95_ms,ops_per_sec,throughput_MiB_per_sec\n";

  // Warm-up.
  (void)rsa_keygen(args.bits);

  // RSA key generation.
  const auto keygen_times = measure_runs_ms(args.runs, [&] {
    auto generated = rsa_keygen(args.bits);
    if (!generated || !generated->pkey)
      throw std::runtime_error("RSA key generation benchmark failed");
  });
  print_benchmark_row(rsa_name, "keygen", 0, args.runs,
                      calculate_bench_stats(keygen_times));

  // Stable key for operation benchmarks.
  auto key_pair = rsa_keygen(args.bits);
  EVP_PKEY* key = key_pair->pkey;

  // Direct RSA-OAEP benchmark.
  const size_t direct_size =
      std::min<size_t>(190, rsa_oaep_max_plaintext(args.bits));
  const Bytes direct_message(direct_size, 0x41);
  const std::string direct_label = "lab3-benchmark";
  const Bytes stable_ciphertext =
      rsa_oaep_encrypt(key, direct_message, direct_label);

  // Warm-up and correctness check.
  (void)rsa_oaep_encrypt(key, direct_message, direct_label);
  if (rsa_oaep_decrypt(key, stable_ciphertext, direct_label) != direct_message)
    throw std::runtime_error("RSA-OAEP benchmark warm-up failed");

  const auto rsa_encrypt_times = measure_runs_ms(args.runs, [&] {
    const Bytes ciphertext =
        rsa_oaep_encrypt(key, direct_message, direct_label);
    if (ciphertext.empty())
      throw std::runtime_error("RSA-OAEP benchmark encryption failed");
  });
  print_benchmark_row(rsa_name + "-OAEP-SHA256", "encrypt", direct_size,
                      args.runs, calculate_bench_stats(rsa_encrypt_times));

  const auto rsa_decrypt_times = measure_runs_ms(args.runs, [&] {
    const Bytes plaintext =
        rsa_oaep_decrypt(key, stable_ciphertext, direct_label);
    if (plaintext != direct_message)
      throw std::runtime_error("RSA-OAEP benchmark decryption failed");
  });
  print_benchmark_row(rsa_name + "-OAEP-SHA256", "decrypt", direct_size,
                      args.runs, calculate_bench_stats(rsa_decrypt_times));

  // Hybrid RSA-OAEP + AES-256-GCM sizes required by the lab.
  const std::vector<size_t> sizes = {
      1024,
      1024 * 1024,
      100ull * 1024ull * 1024ull,
  };

  for (size_t size : sizes) {
    const Bytes message(size, 0x5A);
    const std::string label = "lab3-hybrid-benchmark";
    const std::string stable_envelope = hybrid_encrypt(key, message, label);

    if (hybrid_decrypt(key, stable_envelope) != message)
      throw std::runtime_error("hybrid benchmark warm-up failed");

    const auto encrypt_times = measure_runs_ms(args.runs, [&] {
      const std::string envelope = hybrid_encrypt(key, message, label);
      if (envelope.empty())
        throw std::runtime_error("hybrid benchmark encryption failed");
    });
    print_benchmark_row("RSA-OAEP-AES-256-GCM", "hybrid_encrypt", size,
                        args.runs, calculate_bench_stats(encrypt_times));

    const auto decrypt_times = measure_runs_ms(args.runs, [&] {
      const Bytes recovered = hybrid_decrypt(key, stable_envelope);
      if (recovered != message)
        throw std::runtime_error("hybrid benchmark decryption failed");
    });
    print_benchmark_row("RSA-OAEP-AES-256-GCM", "hybrid_decrypt", size,
                        args.runs, calculate_bench_stats(decrypt_times));
  }

  return 0;
}

static int cmd_test_oaep(const Args&) {
  printf("=== Lab 3 automated correctness and negative-test suite ===\n");

  int passed = 0;
  int total = 0;

  auto check = [&](bool condition, const std::string& name) {
    ++total;
    printf("  [%s] %s\n", condition ? "PASS" : "FAIL", name.c_str());
    if (condition) ++passed;
  };

  auto rejects = [&](const std::function<void()>& fn) {
    try {
      fn();
      return false;
    } catch (const std::exception&) {
      return true;
    }
  };

  printf("Generating two independent RSA-3072 key pairs...\n");
  auto kp = rsa_keygen(3072);
  auto wrong_kp = rsa_keygen(3072);
  const size_t emLen = 3072 / 8;

  // -----------------------------------------------------------------------
  // Manual OAEP encode/decode tests
  // -----------------------------------------------------------------------
  for (const auto& test_msg :
       std::vector<std::string>{"hello", "short", std::string(200, 'A')}) {
    const Bytes msg(test_msg.begin(), test_msg.end());
    const Bytes encoded = oaep_encode_manual(msg, emLen, "test-label");
    const Bytes recovered =
        oaep_decode_manual(encoded, emLen, "test-label");
    check(recovered == msg,
          "manual OAEP round trip (" + std::to_string(msg.size()) +
              " bytes)");
  }

  check(rejects([&] {
          const Bytes msg{'x', 'y', 'z'};
          const Bytes encoded =
              oaep_encode_manual(msg, emLen, "label-A");
          (void)oaep_decode_manual(encoded, emLen, "label-B");
        }),
        "manual OAEP rejects wrong label");

  check(rejects([&] {
          const Bytes msg{'d', 'a', 't', 'a'};
          Bytes encoded = oaep_encode_manual(msg, emLen, "");
          encoded[emLen / 2] ^= 0xFF;
          (void)oaep_decode_manual(encoded, emLen, "");
        }),
        "manual OAEP rejects tampered encoded message");

  // -----------------------------------------------------------------------
  // Library-backed RSA-OAEP tests
  // -----------------------------------------------------------------------
  const Bytes direct_msg{'R', 'S', 'A', '-', 'O', 'A', 'E', 'P'};
  const std::string direct_label = "lab3-label";
  const Bytes direct_ct =
      rsa_oaep_encrypt(kp->pkey, direct_msg, direct_label);

  check(rsa_oaep_decrypt(kp->pkey, direct_ct, direct_label) == direct_msg,
        "RSA-OAEP valid ciphertext decrypts correctly");

  check(rejects([&] {
          (void)rsa_oaep_decrypt(kp->pkey, direct_ct, "wrong-label");
        }),
        "RSA-OAEP rejects wrong label");

  check(rejects([&] {
          (void)rsa_oaep_decrypt(wrong_kp->pkey, direct_ct, direct_label);
        }),
        "RSA-OAEP rejects wrong private key");

  check(rejects([&] {
          Bytes tampered = direct_ct;
          tampered[tampered.size() / 2] ^= 0x01;
          (void)rsa_oaep_decrypt(kp->pkey, tampered, direct_label);
        }),
        "RSA-OAEP rejects tampered ciphertext");

  check(rejects([&] {
          const Bytes too_large(rsa_oaep_max_plaintext(3072) + 1, 0x41);
          (void)rsa_oaep_encrypt(kp->pkey, too_large, "");
        }),
        "RSA-OAEP rejects plaintext above the size limit");

  // -----------------------------------------------------------------------
  // AES-256-GCM tests
  // -----------------------------------------------------------------------
  Bytes aes_key(AES_KEY_BYTES);
  if (RAND_bytes(aes_key.data(), static_cast<int>(aes_key.size())) != 1)
    throw std::runtime_error("RAND_bytes failed during self-test");

  const Bytes gcm_msg{'a', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a',
                      't', 'e', 'd'};
  const Bytes gcm_aad{'l', 'a', 'b', '3', '-', 'a', 'a', 'd'};
  const GCMResult gcm = aes_gcm_encrypt(aes_key, gcm_msg, gcm_aad);

  check(aes_gcm_decrypt(aes_key, gcm.ciphertext, gcm.iv, gcm.tag,
                        gcm_aad) == gcm_msg,
        "AES-256-GCM round trip");

  check(rejects([&] {
          Bytes tampered = gcm.ciphertext;
          tampered[0] ^= 0x01;
          (void)aes_gcm_decrypt(aes_key, tampered, gcm.iv, gcm.tag,
                                gcm_aad);
        }),
        "AES-GCM rejects tampered ciphertext");

  check(rejects([&] {
          Bytes bad_tag = gcm.tag;
          bad_tag[0] ^= 0x01;
          (void)aes_gcm_decrypt(aes_key, gcm.ciphertext, gcm.iv, bad_tag,
                                gcm_aad);
        }),
        "AES-GCM rejects invalid authentication tag");

  check(rejects([&] {
          const Bytes wrong_aad{'w', 'r', 'o', 'n', 'g'};
          (void)aes_gcm_decrypt(aes_key, gcm.ciphertext, gcm.iv, gcm.tag,
                                wrong_aad);
        }),
        "AES-GCM rejects wrong AAD");

  // -----------------------------------------------------------------------
  // Hybrid envelope tests
  // -----------------------------------------------------------------------
  const Bytes hybrid_msg(1024, 0x5A);
  const std::string hybrid_label = "hybrid-label";
  const std::string envelope =
      hybrid_encrypt(kp->pkey, hybrid_msg, hybrid_label);

  check(hybrid_decrypt(kp->pkey, envelope) == hybrid_msg,
        "hybrid RSA-OAEP + AES-GCM round trip");

  check(rejects([&] {
          (void)hybrid_decrypt(wrong_kp->pkey, envelope);
        }),
        "hybrid envelope rejects wrong private key");

  check(rejects([&] {
          Envelope e = envelope_from_json(envelope);
          e.ciphertext[0] ^= 0x01;
          (void)hybrid_decrypt(kp->pkey, envelope_to_json(e));
        }),
        "hybrid envelope rejects tampered AES-GCM ciphertext");

  check(rejects([&] {
          Envelope e = envelope_from_json(envelope);
          e.tag[0] ^= 0x01;
          (void)hybrid_decrypt(kp->pkey, envelope_to_json(e));
        }),
        "hybrid envelope rejects tampered GCM tag");

  check(rejects([&] {
          Envelope e = envelope_from_json(envelope);
          e.wrapped_key[e.wrapped_key.size() / 2] ^= 0x01;
          (void)hybrid_decrypt(kp->pkey, envelope_to_json(e));
        }),
        "hybrid envelope rejects tampered wrapped AES key");

  check(rejects([&] {
          std::string bad = envelope;
          const std::string expected = "\"mode\": \"RSA-OAEP-AES-GCM\"";
          const auto pos = bad.find(expected);
          if (pos == std::string::npos)
            throw std::runtime_error("self-test could not locate mode");
          bad.replace(pos, expected.size(),
                      "\"mode\": \"RSA-OAEP-AES-CBC\"");
          (void)hybrid_decrypt(kp->pkey, bad);
        }),
        "hybrid envelope rejects unsupported mode");

  check(rejects([&] {
          std::string bad = envelope;
          const std::string expected = "\"hash\": \"SHA-256\"";
          const auto pos = bad.find(expected);
          if (pos == std::string::npos)
            throw std::runtime_error("self-test could not locate hash");
          bad.replace(pos, expected.size(), "\"hash\": \"SHA-1\"");
          (void)hybrid_decrypt(kp->pkey, bad);
        }),
        "hybrid envelope rejects unsupported hash");

  check(rejects([&] {
          Envelope e = envelope_from_json(envelope);
          e.rsa_modulus = 4096;
          (void)hybrid_decrypt(kp->pkey, envelope_to_json(e));
        }),
        "hybrid envelope rejects false RSA modulus metadata");

  check(rejects([&] {
          const std::string malformed =
              "{\"mode\":\"RSA-OAEP-AES-GCM\",\"hash\":\"SHA-256\"}";
          (void)hybrid_decrypt(kp->pkey, malformed);
        }),
        "malformed envelope JSON fails closed");

  // -----------------------------------------------------------------------
  // Corrupted PEM and key-size policy tests
  // -----------------------------------------------------------------------
  const std::string bad_pem_path = "lab3_corrupted_key_test.pem";
  write_file(bad_pem_path,
             std::string("-----BEGIN PUBLIC KEY-----\n"
                         "this-is-not-valid-base64\n"
                         "-----END PUBLIC KEY-----\n"));

  check(rejects([&] {
          EVP_PKEY* bad = load_pubkey_file(bad_pem_path);
          EVP_PKEY_free(bad);
        }),
        "corrupted PEM public key is rejected");
  std::remove(bad_pem_path.c_str());

  check(rejects([&] { (void)rsa_keygen(2048); }),
        "RSA-2048 is rejected by the assignment policy");

  check(rsa_oaep_max_plaintext(3072) == 318,
        "RSA-3072 OAEP(SHA-256) plaintext limit is 318 bytes");

  printf("Test summary: %d/%d passed\n", passed, total);
  if (passed != total) {
    printf("Lab 3 automated test suite FAILED: %d failure(s).\n",
           total - passed);
    return 1;
  }

  printf("Lab 3 automated test suite complete: ALL TESTS PASSED.\n");
  return 0;
}

// ── Entry point
// ───────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
  // Initialize OpenSSL error strings
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  Args a = parse_args(argc, argv);

  try {
    if (a.command == "keygen")
      return cmd_keygen(a);
    else if (a.command == "encrypt")
      return cmd_encrypt(a);
    else if (a.command == "decrypt")
      return cmd_decrypt(a);
    else if (a.command == "info")
      return cmd_info(a);
    else if (a.command == "benchmark" || a.command == "bench")
      return cmd_benchmark(a);
    else if (a.command == "test-oaep" || a.command == "selftest")
      return cmd_test_oaep(a);
    else {
      fprintf(stderr, "unknown command: %s\n", a.command.c_str());
      usage(argv[0]);
    }
  } catch (const std::exception& e) {
    fprintf(stderr, "Error: %s\n", e.what());
    return 1;
  }
  return 0;
}