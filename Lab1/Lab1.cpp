#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/ccm.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <cryptopp/xts.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using CryptoPP::AES;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;
using CryptoPP::byte;
using CryptoPP::CBC_Mode;
using CryptoPP::CCM;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::Exception;
using CryptoPP::GCM;
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
using CryptoPP::OFB_Mode;
using CryptoPP::SecByteBlock;
using CryptoPP::SHA256;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::XTS_Mode;

namespace {

constexpr std::size_t GCM_NONCE_LEN = 12;
constexpr std::size_t GCM_TAG_LEN = 16;
constexpr std::size_t CCM_NONCE_LEN = 11;
constexpr std::size_t CCM_TAG_LEN = 16;
constexpr std::size_t ECB_LIMIT = 16 * 1024;

struct Args {
  std::string command;
  std::map<std::string, std::string> values;
  std::map<std::string, bool> flags;
};

struct Metadata {
  std::string mode;
  std::string iv_hex;
  std::string aad_b64;
  std::size_t tag_len = 0;
  std::string encoding = "raw";
};

[[noreturn]] void fail(const std::string& message) {
  throw std::runtime_error(message);
}

void enforce_ecb_policy(std::size_t plaintext_size, bool allow_ecb) {
  if (plaintext_size > ECB_LIMIT && !allow_ecb) {
    fail(
        "ECB input exceeds 16 KiB. Use --allow-ecb only for controlled "
        "experiments.");
  }
}

std::string lower(std::string value) {
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

std::string trim(std::string s) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

Args parse_args(int argc, char** argv) {
  if (argc < 2) fail("Missing command. Use --help for usage.");
  Args args;
  args.command = lower(argv[1]);
  for (int i = 2; i < argc; ++i) {
    std::string token = argv[i];
    if (token.rfind("--", 0) != 0)
      fail("Unexpected positional argument: " + token);
    if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) {
      args.values[token] = argv[++i];
    } else {
      args.flags[token] = true;
    }
  }
  return args;
}

bool has_flag(const Args& args, const std::string& name) {
  return args.flags.count(name) != 0;
}

std::string get_value(const Args& args, const std::string& name,
                      const std::string& default_value = "") {
  auto it = args.values.find(name);
  return it == args.values.end() ? default_value : it->second;
}

std::string require_value(const Args& args, const std::string& name) {
  auto value = get_value(args, name);
  if (value.empty()) fail("Missing required option " + name);
  return value;
}

std::vector<byte> read_binary(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("Cannot open input file: " + path);
  in.seekg(0, std::ios::end);
  const auto end = in.tellg();
  if (end < 0) fail("Cannot determine input file size: " + path);
  in.seekg(0, std::ios::beg);
  std::vector<byte> data(static_cast<std::size_t>(end));
  if (!data.empty() && !in.read(reinterpret_cast<char*>(data.data()),
                                static_cast<std::streamsize>(data.size()))) {
    fail("Failed to read input file: " + path);
  }
  return data;
}

std::string read_text_file(const std::string& path) {
  auto bytes = read_binary(path);
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

void write_binary(const std::string& path, const std::vector<byte>& data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) fail("Cannot open output file: " + path);
  if (!data.empty()) {
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
  }
  if (!out) fail("Failed to write output file: " + path);
}

void write_text(const std::string& path, const std::string& text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) fail("Cannot open output file: " + path);
  out << text;
  if (!out) fail("Failed to write output file: " + path);
}

std::vector<byte> to_bytes(const std::string& s) {
  return std::vector<byte>(reinterpret_cast<const byte*>(s.data()),
                           reinterpret_cast<const byte*>(s.data()) + s.size());
}

std::string to_string(const std::vector<byte>& data) {
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::string hex_encode(const byte* data, std::size_t size) {
  std::string out;
  StringSource(data, size, true, new HexEncoder(new StringSink(out), false));
  return out;
}

std::string hex_encode(const std::vector<byte>& data) {
  return hex_encode(data.data(), data.size());
}

std::vector<byte> hex_decode(std::string text) {
  text.erase(std::remove_if(text.begin(), text.end(),
                            [](unsigned char c) { return std::isspace(c); }),
             text.end());
  if (text.size() % 2 != 0) fail("Hex input has odd length.");
  std::string decoded;
  try {
    StringSource(text, true, new HexDecoder(new StringSink(decoded)));
  } catch (const Exception& e) {
    fail(std::string("Invalid hex input: ") + e.what());
  }
  return to_bytes(decoded);
}

std::string base64_encode(const std::vector<byte>& data) {
  std::string out;
  StringSource(data.data(), data.size(), true,
               new Base64Encoder(new StringSink(out), false));
  return out;
}

std::vector<byte> base64_decode(std::string text) {
  text.erase(std::remove_if(text.begin(), text.end(),
                            [](unsigned char c) { return std::isspace(c); }),
             text.end());
  std::string out;
  try {
    StringSource(text, true, new Base64Decoder(new StringSink(out)));
  } catch (const Exception& e) {
    fail(std::string("Invalid Base64 input: ") + e.what());
  }
  return to_bytes(out);
}

std::vector<byte> random_bytes(std::size_t size) {
  AutoSeededRandomPool rng;
  std::vector<byte> data(size);
  rng.GenerateBlock(data.data(), data.size());
  return data;
}

SecByteBlock make_secblock(const std::vector<byte>& data) {
  SecByteBlock block(data.size());
  if (!data.empty()) std::copy(data.begin(), data.end(), block.begin());
  return block;
}

void validate_key(const std::string& mode, std::size_t size) {
  if (mode == "xts") {
    if (size != 32 && size != 64) fail("AES-XTS key must be 32 or 64 bytes.");
  } else if (size != 16 && size != 24 && size != 32) {
    fail("AES key must be 16, 24, or 32 bytes.");
  }
}

std::vector<byte> load_key(const Args& args, const std::string& mode) {
  std::vector<byte> key;
  const auto key_hex = get_value(args, "--key-hex");
  const auto key_path = get_value(args, "--key");
  if (!key_hex.empty() && !key_path.empty())
    fail("Use only one of --key or --key-hex.");
  if (!key_hex.empty())
    key = hex_decode(key_hex);
  else if (!key_path.empty())
    key = read_binary(key_path);
  else
    fail("A key is required: --key KEYFILE or --key-hex HEX.");
  validate_key(mode, key.size());
  return key;
}

std::size_t required_iv_length(const std::string& mode) {
  if (mode == "ecb") return 0;
  if (mode == "gcm") return GCM_NONCE_LEN;
  if (mode == "ccm") return CCM_NONCE_LEN;
  return AES::BLOCKSIZE;
}

std::vector<byte> load_iv_option(const Args& args, std::size_t expected) {
  const auto iv_hex =
      get_value(args, "--iv-hex", get_value(args, "--nonce-hex"));
  const auto iv_path = get_value(args, "--iv", get_value(args, "--nonce"));
  if (!iv_hex.empty() && !iv_path.empty())
    fail("Use only one IV/nonce source.");
  std::vector<byte> iv;
  if (!iv_hex.empty())
    iv = hex_decode(iv_hex);
  else if (!iv_path.empty())
    iv = read_binary(iv_path);
  if (!iv.empty() && iv.size() != expected) {
    fail("Invalid IV/nonce length: expected " + std::to_string(expected) +
         " bytes.");
  }
  return iv;
}

std::string json_escape(const std::string& s) {
  std::ostringstream out;
  for (unsigned char c : s) {
    switch (c) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec;
        } else
          out << static_cast<char>(c);
    }
  }
  return out.str();
}

void save_metadata(const std::string& path, const Metadata& m) {
  std::ostringstream j;
  j << "{\n"
    << "  \"algorithm\": \"AES\",\n"
    << "  \"mode\": \"" << json_escape(m.mode) << "\",\n"
    << "  \"iv\": \"" << m.iv_hex << "\",\n"
    << "  \"aad\": \"" << m.aad_b64 << "\",\n"
    << "  \"aad_encoding\": \"base64\",\n"
    << "  \"tag_length\": " << m.tag_len << ",\n"
    << "  \"ciphertext_encoding\": \"" << json_escape(m.encoding) << "\"\n"
    << "}\n";
  write_text(path, j.str());
}

std::string json_string_field(const std::string& json, const std::string& key) {
  const std::string marker = "\"" + key + "\"";
  auto p = json.find(marker);
  if (p == std::string::npos) return "";
  p = json.find(':', p + marker.size());
  if (p == std::string::npos) fail("Malformed metadata JSON.");
  p = json.find('"', p + 1);
  if (p == std::string::npos) fail("Malformed metadata JSON.");
  std::string out;
  for (++p; p < json.size(); ++p) {
    if (json[p] == '"') return out;
    if (json[p] == '\\') {
      if (++p >= json.size()) fail("Malformed JSON escape.");
      switch (json[p]) {
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case '\\':
          out.push_back('\\');
          break;
        case '"':
          out.push_back('"');
          break;
        default:
          fail("Unsupported JSON escape.");
      }
    } else
      out.push_back(json[p]);
  }
  fail("Malformed metadata JSON.");
}

std::size_t json_number_field(const std::string& json, const std::string& key) {
  const std::string marker = "\"" + key + "\"";
  auto p = json.find(marker);
  if (p == std::string::npos) return 0;
  p = json.find(':', p + marker.size());
  if (p == std::string::npos) fail("Malformed metadata JSON.");
  ++p;
  while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p])))
    ++p;
  std::size_t end = p;
  while (end < json.size() &&
         std::isdigit(static_cast<unsigned char>(json[end])))
    ++end;
  if (end == p) fail("Malformed numeric metadata field.");
  return static_cast<std::size_t>(std::stoull(json.substr(p, end - p)));
}

Metadata load_metadata(const std::string& path) {
  const auto json = read_text_file(path);
  Metadata m;
  m.mode = lower(json_string_field(json, "mode"));
  m.iv_hex = json_string_field(json, "iv");
  m.aad_b64 = json_string_field(json, "aad");
  m.encoding = lower(json_string_field(json, "ciphertext_encoding"));
  m.tag_len = json_number_field(json, "tag_length");
  return m;
}

std::vector<byte> load_input(const Args& args) {
  const auto in_path = get_value(args, "--in");
  const auto text = get_value(args, "--text");
  if (!in_path.empty() && !text.empty())
    fail("Use only one of --in or --text.");
  if (!in_path.empty()) return read_binary(in_path);
  if (!text.empty()) return to_bytes(text);
  fail("Input required: --in FILE or --text STRING.");
}

std::vector<byte> load_aad(const Args& args) {
  const auto path = get_value(args, "--aad");
  const auto text = get_value(args, "--aad-text");
  if (!path.empty() && !text.empty())
    fail("Use only one of --aad or --aad-text.");
  if (!path.empty()) return read_binary(path);
  if (!text.empty()) return to_bytes(text);
  return {};
}

std::string normalize_encoding(const std::string& value) {
  const auto enc = lower(value.empty() ? "raw" : value);
  if (enc != "raw" && enc != "hex" && enc != "base64") {
    fail("Unsupported encoding: " + enc);
  }
  return enc;
}

std::vector<byte> encode_for_file(const std::vector<byte>& data,
                                  const std::string& encoding) {
  if (encoding == "raw") return data;
  if (encoding == "hex") return to_bytes(hex_encode(data));
  return to_bytes(base64_encode(data));
}

std::vector<byte> decode_from_file(const std::vector<byte>& data,
                                   const std::string& encoding) {
  if (encoding == "raw") return data;
  if (encoding == "hex") return hex_decode(to_string(data));
  return base64_decode(to_string(data));
}

std::vector<byte> transform_stream(const std::string& mode, bool encrypt,
                                   const std::vector<byte>& input,
                                   const std::vector<byte>& key,
                                   const std::vector<byte>& iv) {
  std::string out;
  const std::string in = to_string(input);
  const auto key_block = make_secblock(key);
  const auto iv_block = make_secblock(iv);

  try {
    if (mode == "ecb") {
      if (encrypt) {
        ECB_Mode<AES>::Encryption cipher;
        cipher.SetKey(key_block, key_block.size());
        StringSource(
            in, true,
            new StreamTransformationFilter(cipher, new StringSink(out)));
      } else {
        ECB_Mode<AES>::Decryption cipher;
        cipher.SetKey(key_block, key_block.size());
        StringSource(
            in, true,
            new StreamTransformationFilter(cipher, new StringSink(out)));
      }
    } else if (mode == "cbc") {
      if (encrypt) {
        CBC_Mode<AES>::Encryption cipher;
        cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
        StringSource(
            in, true,
            new StreamTransformationFilter(cipher, new StringSink(out)));
      } else {
        CBC_Mode<AES>::Decryption cipher;
        cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
        StringSource(
            in, true,
            new StreamTransformationFilter(cipher, new StringSink(out)));
      }
    } else if (mode == "cfb") {
      if (encrypt) {
        CFB_Mode<AES>::Encryption cipher;
        cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
        StringSource(in, true,
                     new StreamTransformationFilter(
                         cipher, new StringSink(out),
                         StreamTransformationFilter::NO_PADDING));
      } else {
        CFB_Mode<AES>::Decryption cipher;
        cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
        StringSource(in, true,
                     new StreamTransformationFilter(
                         cipher, new StringSink(out),
                         StreamTransformationFilter::NO_PADDING));
      }
    } else if (mode == "ofb") {
      OFB_Mode<AES>::Encryption cipher;
      cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
      StringSource(in, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(out),
                       StreamTransformationFilter::NO_PADDING));
    } else if (mode == "ctr") {
      CTR_Mode<AES>::Encryption cipher;
      cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
      StringSource(in, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(out),
                       StreamTransformationFilter::NO_PADDING));
    } else if (mode == "xts") {
      if (input.size() < AES::BLOCKSIZE)
        fail("AES-XTS input must be at least 16 bytes.");
      if (encrypt) {
        XTS_Mode<AES>::Encryption cipher;
        cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
        StringSource(in, true,
                     new StreamTransformationFilter(
                         cipher, new StringSink(out),
                         StreamTransformationFilter::NO_PADDING));
      } else {
        XTS_Mode<AES>::Decryption cipher;
        cipher.SetKeyWithIV(key_block, key_block.size(), iv_block);
        StringSource(in, true,
                     new StreamTransformationFilter(
                         cipher, new StringSink(out),
                         StreamTransformationFilter::NO_PADDING));
      }
    } else {
      fail("Unsupported non-AEAD mode: " + mode);
    }
  } catch (const CryptoPP::InvalidCiphertext&) {
    fail("Decryption failed: invalid ciphertext or padding.");
  } catch (const Exception& e) {
    fail(std::string("Crypto++ operation failed: ") + e.what());
  }
  return to_bytes(out);
}

std::vector<byte> aead_encrypt(const std::string& mode,
                               const std::vector<byte>& plaintext,
                               const std::vector<byte>& key,
                               const std::vector<byte>& nonce,
                               const std::vector<byte>& aad) {
  const auto key_block = make_secblock(key);
  const auto nonce_block = make_secblock(nonce);
  const auto in = to_string(plaintext);
  const auto aad_s = to_string(aad);
  std::string out;
  try {
    if (mode == "gcm") {
      GCM<AES>::Encryption enc;
      enc.SetKeyWithIV(key_block, key_block.size(), nonce_block,
                       nonce_block.size());
      AuthenticatedEncryptionFilter filter(enc, new StringSink(out), false,
                                           GCM_TAG_LEN);
      if (!aad.empty())
        filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
      filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
      if (!plaintext.empty())
        filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(),
                          plaintext.size());
      filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    } else if (mode == "ccm") {
      CCM<AES, CCM_TAG_LEN>::Encryption enc;
      enc.SetKeyWithIV(key_block, key_block.size(), nonce_block,
                       nonce_block.size());
      enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);
      AuthenticatedEncryptionFilter filter(enc, new StringSink(out), false,
                                           CCM_TAG_LEN);
      if (!aad.empty())
        filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
      filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
      if (!plaintext.empty())
        filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(),
                          plaintext.size());
      filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    } else
      fail("Unsupported AEAD mode: " + mode);
  } catch (const Exception& e) {
    fail(std::string("AEAD encryption failed: ") + e.what());
  }
  return to_bytes(out);
}

std::vector<byte> aead_decrypt(const std::string& mode,
                               const std::vector<byte>& ciphertext_and_tag,
                               const std::vector<byte>& key,
                               const std::vector<byte>& nonce,
                               const std::vector<byte>& aad) {
  const std::size_t tag_len = mode == "gcm" ? GCM_TAG_LEN : CCM_TAG_LEN;
  if (ciphertext_and_tag.size() < tag_len)
    fail("Ciphertext is shorter than the authentication tag.");
  const auto key_block = make_secblock(key);
  const auto nonce_block = make_secblock(nonce);
  std::string out;
  try {
    if (mode == "gcm") {
      GCM<AES>::Decryption dec;
      dec.SetKeyWithIV(key_block, key_block.size(), nonce_block,
                       nonce_block.size());
      AuthenticatedDecryptionFilter filter(
          dec, new StringSink(out),
          AuthenticatedDecryptionFilter::THROW_EXCEPTION |
              AuthenticatedDecryptionFilter::MAC_AT_END,
          GCM_TAG_LEN);
      if (!aad.empty())
        filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
      filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
      filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext_and_tag.data(),
                        ciphertext_and_tag.size());
      filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    } else if (mode == "ccm") {
      CCM<AES, CCM_TAG_LEN>::Decryption dec;
      dec.SetKeyWithIV(key_block, key_block.size(), nonce_block,
                       nonce_block.size());
      dec.SpecifyDataLengths(aad.size(),
                             ciphertext_and_tag.size() - CCM_TAG_LEN, 0);
      AuthenticatedDecryptionFilter filter(
          dec, new StringSink(out),
          AuthenticatedDecryptionFilter::THROW_EXCEPTION |
              AuthenticatedDecryptionFilter::MAC_AT_END,
          CCM_TAG_LEN);
      if (!aad.empty())
        filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
      filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
      filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, ciphertext_and_tag.data(),
                        ciphertext_and_tag.size());
      filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    } else
      fail("Unsupported AEAD mode: " + mode);
  } catch (const CryptoPP::InvalidCiphertext&) {
    fail(
        "Authentication failed: wrong key/nonce/AAD or tampered "
        "ciphertext/tag.");
  } catch (const Exception& e) {
    fail(std::string("AEAD decryption failed: ") + e.what());
  }
  return to_bytes(out);
}

std::string fingerprint_nonce(const std::string& mode,
                              const std::vector<byte>& key,
                              const std::vector<byte>& iv) {
  SHA256 hash;
  std::array<byte, SHA256::DIGESTSIZE> digest{};
  hash.Update(reinterpret_cast<const byte*>(mode.data()), mode.size());
  hash.Update(key.data(), key.size());
  hash.Update(iv.data(), iv.size());
  hash.Final(digest.data());
  return hex_encode(digest.data(), digest.size());
}

void reject_nonce_reuse(const std::string& mode, const std::vector<byte>& key,
                        const std::vector<byte>& iv,
                        const std::string& registry_path) {
  if (mode != "ctr" && mode != "gcm" && mode != "ccm") return;
  const auto fp = fingerprint_nonce(mode, key, iv);
  std::ifstream in(registry_path);
  std::string line;
  while (std::getline(in, line)) {
    if (trim(line) == fp)
      fail("Nonce reuse detected for the same key and mode.");
  }
  std::ofstream out(registry_path, std::ios::app);
  if (!out) fail("Cannot update nonce registry: " + registry_path);
  out << fp << '\n';
}

void emit_output(const Args& args, const std::vector<byte>& output,
                 const std::string& encoding) {
  const auto out_path = get_value(args, "--out");
  if (!out_path.empty()) {
    write_binary(out_path, encode_for_file(output, encoding));
    std::cout << "[OK] Wrote " << output.size() << " decoded bytes to "
              << out_path << " (encoding=" << encoding << ")\n";
  } else {
    if (encoding == "raw") {
      std::cout << hex_encode(output) << '\n';
      std::cerr << "[INFO] Console output defaults to hex; use --out for raw "
                   "binary.\n";
    } else if (encoding == "hex")
      std::cout << hex_encode(output) << '\n';
    else
      std::cout << base64_encode(output) << '\n';
  }
}

void cmd_keygen(const Args& args) {
  const int bits = std::stoi(get_value(args, "--bits", "256"));
  const bool xts = has_flag(args, "--xts");
  std::size_t bytes = 0;
  if (xts) {
    if (bits != 256 && bits != 512)
      fail("XTS combined key size must be 256 or 512 bits.");
    bytes = static_cast<std::size_t>(bits / 8);
  } else {
    if (bits != 128 && bits != 192 && bits != 256)
      fail("AES key size must be 128, 192, or 256 bits.");
    bytes = static_cast<std::size_t>(bits / 8);
  }
  const auto out = require_value(args, "--out");
  write_binary(out, random_bytes(bytes));
  std::cout << "[OK] Generated " << bits << "-bit " << (xts ? "AES-XTS" : "AES")
            << " key: " << out << '\n';
}

void cmd_encrypt(const Args& args) {
  const auto mode = lower(require_value(args, "--mode"));
  static const std::vector<std::string> supported = {
      "ecb", "cbc", "ofb", "cfb", "ctr", "xts", "ccm", "gcm"};
  if (std::find(supported.begin(), supported.end(), mode) == supported.end()) {
    fail("Unsupported mode: " + mode);
  }
  auto plaintext = load_input(args);
  if (mode == "ecb") {
    std::cerr << "[WARNING] ECB leaks plaintext patterns and provides no "
                 "semantic security.\n";
    enforce_ecb_policy(plaintext.size(), has_flag(args, "--allow-ecb"));
  }
  const auto key = load_key(args, mode);
  const auto iv_len = required_iv_length(mode);
  auto iv = load_iv_option(args, iv_len);
  if (iv_len != 0 && iv.empty()) iv = random_bytes(iv_len);
  if (mode == "xts" && plaintext.size() < AES::BLOCKSIZE) {
    fail("AES-XTS requires at least one full block (16 bytes).");
  }
  const auto aad = load_aad(args);
  if (!aad.empty() && mode != "ccm" && mode != "gcm") {
    fail("AAD is only supported for CCM and GCM.");
  }

  const auto registry =
      get_value(args, "--nonce-registry", ".lab1_nonce_registry");
  if (!iv.empty()) reject_nonce_reuse(mode, key, iv, registry);

  std::vector<byte> ciphertext;
  if (mode == "ccm" || mode == "gcm")
    ciphertext = aead_encrypt(mode, plaintext, key, iv, aad);
  else
    ciphertext = transform_stream(mode, true, plaintext, key, iv);

  const auto encoding = normalize_encoding(get_value(args, "--encode", "raw"));
  emit_output(args, ciphertext, encoding);

  const auto out_path = get_value(args, "--out");
  if (!out_path.empty()) {
    Metadata m;
    m.mode = mode;
    m.iv_hex = hex_encode(iv);
    m.aad_b64 = base64_encode(aad);
    m.tag_len = mode == "gcm" ? GCM_TAG_LEN : (mode == "ccm" ? CCM_TAG_LEN : 0);
    m.encoding = encoding;
    const auto meta_path = get_value(args, "--meta", out_path + ".json");
    save_metadata(meta_path, m);
    std::cout << "[OK] Metadata written to " << meta_path << '\n';
  } else if (!iv.empty()) {
    std::cerr << "[IV/nonce hex] " << hex_encode(iv) << '\n';
  }
}

void cmd_decrypt(const Args& args) {
  auto mode = lower(get_value(args, "--mode"));
  Metadata metadata;
  const auto in_path = get_value(args, "--in");
  const auto meta_path =
      get_value(args, "--meta", in_path.empty() ? "" : in_path + ".json");
  bool have_meta = false;
  if (!meta_path.empty()) {
    std::ifstream probe(meta_path);
    if (probe.good()) {
      metadata = load_metadata(meta_path);
      have_meta = true;
    }
  }
  if (mode.empty() && have_meta) mode = metadata.mode;
  if (mode.empty())
    fail("Missing --mode and no usable metadata sidecar was found.");

  auto encoded_input = load_input(args);
  const auto encoding = normalize_encoding(get_value(
      args, "--encode",
      have_meta && !metadata.encoding.empty() ? metadata.encoding : "raw"));
  auto ciphertext = decode_from_file(encoded_input, encoding);
  const auto key = load_key(args, mode);
  const auto iv_len = required_iv_length(mode);
  auto iv = load_iv_option(args, iv_len);
  if (iv_len != 0 && iv.empty() && have_meta && !metadata.iv_hex.empty()) {
    iv = hex_decode(metadata.iv_hex);
  }
  if (iv_len != 0 && iv.size() != iv_len) fail("Missing or invalid IV/nonce.");

  auto aad = load_aad(args);
  if (aad.empty() && have_meta && !metadata.aad_b64.empty())
    aad = base64_decode(metadata.aad_b64);
  if (!aad.empty() && mode != "ccm" && mode != "gcm")
    fail("AAD is only valid for CCM/GCM.");

  std::vector<byte> plaintext;
  if (mode == "ccm" || mode == "gcm")
    plaintext = aead_decrypt(mode, ciphertext, key, iv, aad);
  else
    plaintext = transform_stream(mode, false, ciphertext, key, iv);

  const auto out_path = get_value(args, "--out");
  if (!out_path.empty()) {
    write_binary(out_path, plaintext);
    std::cout << "[OK] Decryption succeeded: " << out_path << '\n';
  } else {
    std::cout.write(reinterpret_cast<const char*>(plaintext.data()),
                    static_cast<std::streamsize>(plaintext.size()));
    std::cout << '\n';
  }
}

struct KatCase {
  std::string name;
  std::string mode;
  std::string key;
  std::string iv;
  std::string plaintext;
  std::string ciphertext;
};

bool run_kat_case(const KatCase& tc) {
  const auto key = make_secblock(hex_decode(tc.key));
  const auto iv_vec = tc.iv.empty() ? std::vector<byte>{} : hex_decode(tc.iv);
  const auto iv = make_secblock(iv_vec);
  const auto pt_vec = hex_decode(tc.plaintext);
  const auto expected = hex_decode(tc.ciphertext);
  const std::string input = to_string(pt_vec);
  std::string output;
  try {
    if (tc.mode == "ecb") {
      ECB_Mode<AES>::Encryption cipher;
      cipher.SetKey(key, key.size());
      StringSource(input, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(output),
                       StreamTransformationFilter::NO_PADDING));
    } else if (tc.mode == "cbc") {
      CBC_Mode<AES>::Encryption cipher;
      cipher.SetKeyWithIV(key, key.size(), iv);
      StringSource(input, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(output),
                       StreamTransformationFilter::NO_PADDING));
    } else if (tc.mode == "cfb") {
      CFB_Mode<AES>::Encryption cipher;
      cipher.SetKeyWithIV(key, key.size(), iv);
      StringSource(input, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(output),
                       StreamTransformationFilter::NO_PADDING));
    } else if (tc.mode == "ofb") {
      OFB_Mode<AES>::Encryption cipher;
      cipher.SetKeyWithIV(key, key.size(), iv);
      StringSource(input, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(output),
                       StreamTransformationFilter::NO_PADDING));
    } else if (tc.mode == "ctr") {
      CTR_Mode<AES>::Encryption cipher;
      cipher.SetKeyWithIV(key, key.size(), iv);
      StringSource(input, true,
                   new StreamTransformationFilter(
                       cipher, new StringSink(output),
                       StreamTransformationFilter::NO_PADDING));
    } else {
      fail("Unsupported KAT mode: " + tc.mode);
    }
  } catch (const Exception& e) {
    std::cout << "FAIL  " << tc.name << " (" << e.what() << ")\n";
    return false;
  }
  const auto actual = to_bytes(output);
  const bool pass = actual == expected;
  std::cout << (pass ? "PASS" : "FAIL") << "  " << tc.name << '\n';
  return pass;
}

struct AeadKatCase {
  std::string name;
  std::string mode;
  std::string key;
  std::string nonce;
  std::string aad;
  std::string plaintext;
  std::string ciphertext_and_tag;
  std::size_t tag_len;
};

bool run_aead_kat_case(const AeadKatCase& tc) {
  const auto key_vec = hex_decode(tc.key);
  const auto nonce_vec = hex_decode(tc.nonce);
  const auto aad_vec =
      tc.aad.empty() ? std::vector<byte>{} : hex_decode(tc.aad);
  const auto pt_vec =
      tc.plaintext.empty() ? std::vector<byte>{} : hex_decode(tc.plaintext);
  const auto expected = hex_decode(tc.ciphertext_and_tag);

  std::vector<byte> actual;
  try {
    if (tc.mode == "gcm" && tc.tag_len == GCM_TAG_LEN) {
      actual = aead_encrypt("gcm", pt_vec, key_vec, nonce_vec, aad_vec);
    } else if (tc.mode == "ccm" && tc.tag_len == 8) {
      const auto key_block = make_secblock(key_vec);
      const auto nonce_block = make_secblock(nonce_vec);
      std::string out;

      CCM<AES, 8>::Encryption enc;
      enc.SetKeyWithIV(key_block, key_block.size(), nonce_block,
                       nonce_block.size());
      enc.SpecifyDataLengths(aad_vec.size(), pt_vec.size(), 0);

      AuthenticatedEncryptionFilter filter(enc, new StringSink(out), false, 8);
      if (!aad_vec.empty())
        filter.ChannelPut(CryptoPP::AAD_CHANNEL, aad_vec.data(),
                          aad_vec.size());
      filter.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
      if (!pt_vec.empty())
        filter.ChannelPut(CryptoPP::DEFAULT_CHANNEL, pt_vec.data(),
                          pt_vec.size());
      filter.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
      actual = to_bytes(out);
    } else {
      fail("Unsupported AEAD KAT configuration.");
    }
  } catch (const Exception& e) {
    std::cout << "FAIL  " << tc.name << " (" << e.what() << ")\n";
    return false;
  }

  const bool pass = actual == expected;
  std::cout << (pass ? "PASS" : "FAIL") << "  " << tc.name << '\n';
  if (!pass) {
    std::cout << "      expected: " << hex_encode(expected) << '\n'
              << "      actual  : " << hex_encode(actual) << '\n';
  }
  return pass;
}

void cmd_kat() {
  const std::vector<KatCase> classic_tests = {
      {"NIST AES-128-ECB block 1", "ecb", "2b7e151628aed2a6abf7158809cf4f3c",
       "", "6bc1bee22e409f96e93d7e117393172a",
       "3ad77bb40d7a3660a89ecaf32466ef97"},
      {"NIST AES-128-CBC block 1", "cbc", "2b7e151628aed2a6abf7158809cf4f3c",
       "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a",
       "7649abac8119b246cee98e9b12e9197d"},
      {"NIST AES-128-CFB128 block 1", "cfb", "2b7e151628aed2a6abf7158809cf4f3c",
       "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a",
       "3b3fd92eb72dad20333449f8e83cfb4a"},
      {"NIST AES-128-OFB block 1", "ofb", "2b7e151628aed2a6abf7158809cf4f3c",
       "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a",
       "3b3fd92eb72dad20333449f8e83cfb4a"},
      {"NIST AES-128-CTR block 1", "ctr", "2b7e151628aed2a6abf7158809cf4f3c",
       "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "6bc1bee22e409f96e93d7e117393172a",
       "874d6191b620e3261bef6864990db6ce"}};

  const std::vector<AeadKatCase> aead_tests = {
      // NIST SP 800-38D, AES-GCM: 128-bit zero key, 96-bit zero IV,
      // empty plaintext and empty AAD. Output consists only of the tag.
      {"NIST AES-128-GCM empty plaintext", "gcm",
       "00000000000000000000000000000000", "000000000000000000000000", "", "",
       "58e2fccefa7e3061367f1d57a4e7455a", 16},

      // RFC 3610 packet vector #1. The first eight input bytes are AAD;
      // expected output below is ciphertext followed by the 8-byte tag.
      {"RFC 3610 AES-128-CCM packet vector #1", "ccm",
       "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "00000003020100a0a1a2a3a4a5",
       "0001020304050607", "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
       "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0", 8}};

  int passed = 0;
  int total = 0;

  for (const auto& test : classic_tests) {
    ++total;
    if (run_kat_case(test)) ++passed;
  }
  for (const auto& test : aead_tests) {
    ++total;
    if (run_aead_kat_case(test)) ++passed;
  }

  std::cout << "KAT summary: " << passed << "/" << total << " passed\n";
  if (passed != total) fail("One or more KATs failed.");
}

void cmd_selftest() {
  int passed = 0;
  int total = 0;
  auto check = [&](bool condition, const std::string& name) {
    ++total;
    std::cout << (condition ? "PASS" : "FAIL") << "  " << name << '\n';
    if (condition) ++passed;
  };

  const auto key = random_bytes(32);
  const auto wrong_key = random_bytes(32);
  const auto gcm_iv = random_bytes(GCM_NONCE_LEN);
  const auto aad = to_bytes("lab1-aad");
  const auto message = to_bytes("Authenticated test message");

  const auto gcm_ct = aead_encrypt("gcm", message, key, gcm_iv, aad);
  check(aead_decrypt("gcm", gcm_ct, key, gcm_iv, aad) == message,
        "GCM round trip");

  auto tampered_ciphertext = gcm_ct;
  tampered_ciphertext[0] ^= 0x01;
  bool rejected = false;
  try {
    (void)aead_decrypt("gcm", tampered_ciphertext, key, gcm_iv, aad);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "GCM rejects tampered ciphertext");

  auto tampered_tag = gcm_ct;
  tampered_tag.back() ^= 0x01;
  rejected = false;
  try {
    (void)aead_decrypt("gcm", tampered_tag, key, gcm_iv, aad);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "GCM rejects invalid authentication tag");

  rejected = false;
  try {
    (void)aead_decrypt("gcm", gcm_ct, wrong_key, gcm_iv, aad);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "GCM rejects wrong key");

  rejected = false;
  try {
    (void)aead_decrypt("gcm", gcm_ct, key, gcm_iv, to_bytes("wrong-aad"));
  } catch (...) {
    rejected = true;
  }
  check(rejected, "GCM rejects wrong AAD");

  auto wrong_gcm_iv = gcm_iv;
  wrong_gcm_iv[0] ^= 0x80;
  rejected = false;
  try {
    (void)aead_decrypt("gcm", gcm_ct, key, wrong_gcm_iv, aad);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "GCM rejects wrong IV");

  Args bad_iv_args;
  bad_iv_args.values["--iv-hex"] = "00010203";
  rejected = false;
  try {
    (void)load_iv_option(bad_iv_args, GCM_NONCE_LEN);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "Invalid GCM IV length is rejected");

  const auto ccm_iv = random_bytes(CCM_NONCE_LEN);
  const auto ccm_ct = aead_encrypt("ccm", message, key, ccm_iv, aad);
  check(aead_decrypt("ccm", ccm_ct, key, ccm_iv, aad) == message,
        "CCM round trip");

  auto ccm_tampered = ccm_ct;
  ccm_tampered.back() ^= 0x01;
  rejected = false;
  try {
    (void)aead_decrypt("ccm", ccm_tampered, key, ccm_iv, aad);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "CCM rejects tampered tag");

  const auto ctr_iv = random_bytes(AES::BLOCKSIZE);
  const auto ctr_ct = transform_stream("ctr", true, message, key, ctr_iv);
  check(transform_stream("ctr", false, ctr_ct, key, ctr_iv) == message,
        "CTR round trip");

  const std::string registry_path = "lab1_selftest_nonce_registry.tmp";
  std::remove(registry_path.c_str());
  bool first_nonce_accepted = true;
  try {
    reject_nonce_reuse("gcm", key, gcm_iv, registry_path);
  } catch (...) {
    first_nonce_accepted = false;
  }
  check(first_nonce_accepted, "First key/nonce pair is accepted");

  rejected = false;
  try {
    reject_nonce_reuse("gcm", key, gcm_iv, registry_path);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "Repeated GCM key/nonce pair is rejected");
  std::remove(registry_path.c_str());

  rejected = false;
  try {
    enforce_ecb_policy(ECB_LIMIT + 1, false);
  } catch (...) {
    rejected = true;
  }
  check(rejected, "ECB input above 16 KiB is blocked by default");

  bool override_accepted = true;
  try {
    enforce_ecb_policy(ECB_LIMIT + 1, true);
  } catch (...) {
    override_accepted = false;
  }
  check(override_accepted, "ECB size override is accepted explicitly");

  std::cout << "Self-test summary: " << passed << "/" << total << " passed\n";
  if (passed != total) fail("Self-test failed.");
}

struct Stats {
  double mean = 0;
  double median = 0;
  double stddev = 0;
  double ci95 = 0;
};

Stats stats(std::vector<double> values) {
  if (values.empty()) fail("No benchmark samples.");
  Stats s;
  s.mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
  std::sort(values.begin(), values.end());
  s.median =
      values.size() % 2
          ? values[values.size() / 2]
          : (values[values.size() / 2 - 1] + values[values.size() / 2]) / 2.0;
  double sum = 0;
  for (double v : values) sum += (v - s.mean) * (v - s.mean);
  s.stddev = values.size() > 1 ? std::sqrt(sum / (values.size() - 1)) : 0;
  s.ci95 = 1.96 * s.stddev / std::sqrt(static_cast<double>(values.size()));
  return s;
}

void cmd_bench(const Args& args) {
  const auto mode = lower(get_value(args, "--mode", "gcm"));
  const std::size_t size = static_cast<std::size_t>(
      std::stoull(get_value(args, "--size", "1048576")));
  const int runs = std::stoi(get_value(args, "--runs", "30"));
  const int iterations = std::stoi(get_value(args, "--iterations", "100"));
  if (runs < 2 || iterations < 1)
    fail("Use --runs >= 2 and --iterations >= 1.");

  const std::size_t key_size = mode == "xts" ? 64 : 32;
  const auto key = random_bytes(key_size);
  const auto iv = required_iv_length(mode)
                      ? random_bytes(required_iv_length(mode))
                      : std::vector<byte>{};
  const auto aad = (mode == "gcm" || mode == "ccm") ? to_bytes("benchmark-aad")
                                                    : std::vector<byte>{};
  const auto input = random_bytes(size);

  auto operation = [&]() {
    if (mode == "gcm" || mode == "ccm")
      return aead_encrypt(mode, input, key, iv, aad);
    return transform_stream(mode, true, input, key, iv);
  };

  const auto warmup_end =
      std::chrono::steady_clock::now() + std::chrono::seconds(1);
  while (std::chrono::steady_clock::now() < warmup_end) (void)operation();

  std::vector<double> mbps;
  for (int r = 0; r < runs; ++r) {
    const auto start = std::chrono::steady_clock::now();
    std::size_t sink = 0;
    for (int i = 0; i < iterations; ++i) sink ^= operation().size();
    const auto end = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(end - start).count();
    const double total_mb =
        static_cast<double>(size) * iterations / (1024.0 * 1024.0);
    mbps.push_back(total_mb / seconds);
    if (sink == static_cast<std::size_t>(-1)) std::cerr << "";
  }
  const auto s = stats(mbps);
  std::cout
      << "mode,size_bytes,runs,iterations,mean_MBps,median_MBps,stddev,ci95\n";
  std::cout << mode << ',' << size << ',' << runs << ',' << iterations << ','
            << std::fixed << std::setprecision(3) << s.mean << ',' << s.median
            << ',' << s.stddev << ',' << s.ci95 << '\n';
}

void print_help() {
  std::cout <<
      R"(Lab 1 AES tool (Crypto++, C++17)

Commands:
  lab1 keygen  --bits 128|192|256 --out key.bin
  lab1 keygen  --xts --bits 256|512 --out xts.key

  lab1 encrypt --mode ecb|cbc|ofb|cfb|ctr|xts|ccm|gcm
               [--in FILE | --text STRING]
               [--out FILE]
               [--key KEYFILE | --key-hex HEX]
               [--iv FILE | --iv-hex HEX]
               [--aad FILE | --aad-text STRING]
               [--encode raw|hex|base64]
               [--meta FILE]
               [--nonce-registry FILE]
               [--allow-ecb]

  lab1 decrypt --mode MODE [--in FILE | --text STRING]
               [--out FILE] [--key KEYFILE | --key-hex HEX]
               [--iv FILE | --iv-hex HEX]
               [--aad FILE | --aad-text STRING]
               [--encode raw|hex|base64] [--meta FILE]

  lab1 kat
  lab1 selftest
  lab1 bench --mode MODE --size BYTES --runs 30 --iterations 100

Notes:
  * File ciphertext output defaults to raw binary.
  * Console ciphertext output defaults to hexadecimal.
  * Encryption writes a sidecar metadata file: OUTPUT.json.
  * CTR/CCM/GCM nonce reuse is tracked in .lab1_nonce_registry.
  * AEAD decryption fails closed when the tag is invalid.
)";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 1 || std::string(argv[1]) == "--help" ||
        std::string(argv[1]) == "help") {
      print_help();
      return 0;
    }
    const auto args = parse_args(argc, argv);
    if (args.command == "keygen")
      cmd_keygen(args);
    else if (args.command == "encrypt")
      cmd_encrypt(args);
    else if (args.command == "decrypt")
      cmd_decrypt(args);
    else if (args.command == "kat" || args.command == "--kat")
      cmd_kat();
    else if (args.command == "selftest")
      cmd_selftest();
    else if (args.command == "bench")
      cmd_bench(args);
    else
      fail("Unknown command: " + args.command);
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "[SECURITY ABORT] " << e.what() << '\n';
    return 1;
  }
}