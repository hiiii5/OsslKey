#ifndef OSSL_EC_KEY_H
#define OSSL_EC_KEY_H
#pragma once

#include <memory>
#include <string>
#include <tuple>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "OsslResult.h"

namespace ossl {
/**
 * @brief Convert a BIGNUM to a hex string
 * @param bn The BIGNUM to convert
 * @return The hex string
 */
static BIGNUM *HexToBigNum(const std::string &hexBigNum) noexcept {
  BIGNUM *bn = nullptr;
  if (!BN_hex2bn(&bn, hexBigNum.data())) {
    return nullptr;
  }
  return bn;
}

/**
 * @brief Convert a BIGNUM to a hex string
 * @param bn The BIGNUM to convert
 * @return The hex string
 */
static std::string BigNumToHex(const BIGNUM *bn) noexcept {
  char *hexBigNum = BN_bn2hex(bn);
  if (hexBigNum == nullptr) {
    return "";
  }
  std::string result(hexBigNum);
  OPENSSL_free(hexBigNum);
  return result;
}

/**
 * @brief Get the value of a hex digit
 * @param hexDigit The hex digit to get the value of
 * @return The value of the hex digit, or -1 if the hex digit is invalid
 */
static int GetHexValue(unsigned char hexDigit) noexcept {
  static constexpr char HEX_VALUES[256] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,
      6,  7,  8,  9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1,
  };
  return HEX_VALUES[hexDigit];
}

/**
 * @brief Convert raw data to a hex string
 * @param data The data to convert
 * @return The hex string
 */
static std::string DataToHex(const std::string &data) noexcept {
  constexpr char hexDigits[] = "0123456789ABCDEF";
  std::string hexData;
  hexData.reserve(data.size() * 2);
  for (unsigned char byte : data) {
    hexData.push_back(hexDigits[byte >> 4]);
    hexData.push_back(hexDigits[byte & 0x0F]);
  }
  return hexData;
}

/**
 * @brief Convert a hex string to raw data
 * @param hex The hex string to convert
 * @param data The data to fill
 * @return True if the conversion was successful, false otherwise
 */
static bool HexToData(const std::string &hex, std::string *data) noexcept {
  if (hex.size() & 1) // Odd number of characters
  {
    return false;
  }

  data->clear();
  data->reserve(hex.size() / 2);

  auto it = hex.begin();
  while (it != hex.end()) {
    const int hi = GetHexValue(*it++);
    const int lo = GetHexValue(*it++);
    if (hi == -1 || lo == -1) {
      return false;
    }
    // Don't yell at me I want to remove the signedness from the char
    data->push_back(static_cast<char>(hi << 4 | lo));
  }
  return true;
}

/**
 * @brief An OpenSSL EC key wrapper.
 */
class OsslEcKey {
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> m_keyPair = {
      nullptr, EVP_PKEY_free};

  /**
   * @brief Gets the last OpenSSL error.
   * @return A tuple containing the error code and error message.
   */
  static std::tuple<unsigned long, std::string> GetLastError() noexcept {
    unsigned long lastError = ERR_get_error();
    if (lastError == 0) {
      return std::make_tuple(0, "");
    }

    char errorBuffer[256];
    ERR_error_string_n(lastError, errorBuffer, sizeof(errorBuffer));
    return std::make_tuple(lastError, errorBuffer);
  }

public:
  /**
   * @brief Checks if the private key is valid.
   * @return OsslResult with status set to Success if the private key is valid,
   * or Failure if the private key is invalid.
   */
  OsslResult IsPrivateKeyValid() const noexcept;

  /**
   * @brief Checks if the public key is valid.
   * @return OsslResult with status set to Success if the public key is valid,
   * or Failure if the public key is invalid.
   */
  OsslResult IsPublicKeyValid() const noexcept;

  /**
   * @brief Signs the data using the private key.
   * @param[in] data The data to sign.
   * @param[out] signature The signature of the data.
   * @return OsslResult with status set to Success if the data was signed
   * successfully, or Failure if the data could not be signed.
   */
  OsslResult SignData(const std::string &data,
                      std::string *signature) const noexcept;

  /**
   * @brief Verifies the signature of the data using the public key.
   * @param[in] signature The signature to verify.
   * @param[in] data The data to verify.
   * @return OsslResult with status set to Success if the signature is valid,
   * or Failure if the signature is invalid.
   */
  OsslResult VerifySignature(const std::string &signature,
                             const std::string &data) const noexcept;

  /**
   * @brief Generates a key pair.
   * @return OsslResult with status set to Success if the key pair was
   * generated successfully, or Failure if the key pair could not be generated.
   */
  OsslResult GenerateKeyPair() noexcept;

  /**
   * @brief Generates a key pair from a seed phrase.
   * @param[in] hexSeedPhrase The seed phrase in hexadecimal format.
   * @return OsslResult with status set to Success if the key pair was
   * generated successfully, or Failure if the key pair could not be generated.
   * @note This is a helper for working with crypto seed phrases.
   */
  OsslResult GenerateFromSeedPhrase(const std::string &hexSeedPhrase) noexcept;

  /**
   * @brief Generates a key pair from a private key.
   * @param[in] privateKey The private key in hexadecimal format.
   * @return OsslResult with status set to Success if the key pair was
   * generated successfully, or Failure if the key pair could not be generated.
   * @note The public key will not be generated.
   */
  OsslResult GenerateKeyFromPrivateHex(const std::string &privateKey) noexcept;

  /**
   * @brief Generates a key pair from a public key.
   * @param[in] publicKey The public key in hexadecimal format.
   * @return OsslResult with status set to Success if the key pair was
   * generated successfully, or Failure if the key pair could not be generated.
   * @note The private key will not be generated.
   */
  OsslResult GenerateKeyFromPublicHex(const std::string &publicKey) noexcept;

  /**
   * @brief Generates a key pair from a private and public key.
   * @param[in] privateKey The private key in hexadecimal format.
   * @param[in] publicKey The public key in hexadecimal format.
   * @return OsslResult with status set to Success if the key pair was
   * generated successfully, or Failure if the key pair could not be generated.
   */
  OsslResult
  GenerateKeyFromPrivateAndPublicHex(const std::string &privateKey,
                                     const std::string &publicKey) noexcept;

  /**
   * @brief Gets the private key in hexadecimal format.
   * @return The private key in hexadecimal format.
   */
  ossl::OsslResult GetPrivateKeyHex(std::string *privateKeyHex) const noexcept;

  /**
   * @brief Gets the public key in hexadecimal format.
   * @param[in] isCompressed Whether to return the public key in compressed
   * format (0x4 or 0x2).
   * @return The public key in hexadecimal format.
   */
  ossl::OsslResult GetPublicKeyHex(std::string *publicKeyHex,
                                   bool isUncompressed = false) const noexcept;
};
} // namespace ossl
#endif // OSSL_EC_KEY_H
