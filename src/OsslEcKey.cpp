#include "../include/OsslEcKey.h"

#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <vector>

ossl::OsslResult ossl::OsslEcKey::IsPrivateKeyValid() const noexcept {
  if (m_keyPair == nullptr) {
    return OsslResult{
        OsslResult::Status::Failure,
        "Key pair is null, be sure to call a generate function first"};
  }

  if (EVP_PKEY_id(m_keyPair.get()) != EVP_PKEY_EC) {
    return OsslResult{OsslResult::Status::Failure,
                      "Key pair is not an EC key, only EC keys are supported"};
  }

  EVP_PKEY_CTX *context =
      EVP_PKEY_CTX_new_from_pkey(nullptr, m_keyPair.get(), nullptr);
  if (context == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to create context when checking private key"};
  }

  if (EVP_PKEY_private_check(context) <= 0) {
    return OsslResult{OsslResult::Status::Failure, "Private key is invalid"};
  }

  EVP_PKEY_CTX_free(context);
  return OsslResult{OsslResult::Status::Success, "Private key is valid"};
}

ossl::OsslResult ossl::OsslEcKey::IsPublicKeyValid() const noexcept {
  if (m_keyPair == nullptr) {
    return OsslResult{
        OsslResult::Status::Failure,
        "Key pair is null, be sure to call a generate function first"};
  }

  if (EVP_PKEY_id(m_keyPair.get()) != EVP_PKEY_EC) {
    return OsslResult{OsslResult::Status::Failure,
                      "Key pair is not an EC key, only EC keys are supported"};
  }

  EVP_PKEY_CTX *context =
      EVP_PKEY_CTX_new_from_pkey(nullptr, m_keyPair.get(), nullptr);
  if (context == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to create context when checking public key"};
  }

  if (EVP_PKEY_public_check(context) <= 0) {
    return OsslResult{OsslResult::Status::Failure, "Public key is invalid"};
  }

  EVP_PKEY_CTX_free(context);
  return OsslResult{OsslResult::Status::Success, "Public key is valid"};
}

ossl::OsslResult
ossl::OsslEcKey::SignData(const std::string &data,
                          std::string *signature) const noexcept {
  ERR_clear_error();

  if (!IsPrivateKeyValid()) {
    return OsslResult{OsslResult::Status::Failure, "Private key is invalid"};
  }

  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdContext(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (mdContext == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to create message digest context when "
                      "attempting to sign data"};
  }

  if (EVP_DigestSignInit(mdContext.get(), nullptr, EVP_sha256(), nullptr,
                         m_keyPair.get()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to initialize message digest when attempting "
                      "to sign data {%s}",
                      GetLastError()};
  }

  if (EVP_DigestSignUpdate(mdContext.get(), data.data(), data.size()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to update message digest when attempting to "
                      "sign data {%s}",
                      GetLastError()};
  }

  size_t signatureSize = 0;
  if (EVP_DigestSignFinal(mdContext.get(), nullptr, &signatureSize) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to get signature size when attempting to sign "
                      "data {%s}",
                      GetLastError()};
  }

  // Allow for maximum signature size.
  signature->resize(signatureSize);
  if (EVP_DigestSignFinal(mdContext.get(),
                          reinterpret_cast<unsigned char *>(signature->data()),
                          &signatureSize) <= 0) {
    return OsslResult{OsslResult::Status::Failure, "Failed to sign data {%s}",
                      GetLastError()};
  }
  // We have to resize as the signature size is changed by the call, since the
  // first size from final is the maximum size and not the actual size.
  signature->resize(signatureSize);

  return OsslResult{OsslResult::Status::Success, "Data signed successfully"};
}

ossl::OsslResult
ossl::OsslEcKey::VerifySignature(const std::string &data,
                                 const std::string &signature) const noexcept {
  ERR_clear_error();

  if (!IsPublicKeyValid()) {
    return OsslResult{OsslResult::Status::Failure, "Public key is invalid"};
  }

  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdContext(
      EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (mdContext == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to create message digest context when "
                      "attempting to verify signature"};
  }

  if (EVP_DigestVerifyInit(mdContext.get(), nullptr, EVP_sha256(), nullptr,
                           m_keyPair.get()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to initialize message digest when attempting "
                      "to verify signature {%s}",
                      GetLastError()};
  }

  if (EVP_DigestVerifyUpdate(mdContext.get(), data.data(), data.size()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to update message digest when attempting to "
                      "verify signature {%s}",
                      GetLastError()};
  }

  if (EVP_DigestVerifyFinal(
          mdContext.get(),
          reinterpret_cast<const unsigned char *>(signature.data()),
          signature.size()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to verify signature {%s}", GetLastError()};
  }

  return OsslResult{OsslResult::Status::Success,
                    "Signature verified successfully"};
}

ossl::OsslResult ossl::OsslEcKey::GenerateKeyPair() noexcept {
  ERR_clear_error();

  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> paramBld(
      OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (paramBld == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to create parameter builder when generating key "
                      "pair"};
  }

  if (OSSL_PARAM_BLD_push_utf8_string(
          paramBld.get(), OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to set group name when generating key pair {%s}",
                      GetLastError()};
  }

  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
      OSSL_PARAM_BLD_to_param(paramBld.get()), OSSL_PARAM_free);
  if (params == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to convert parameter builder to parameters when "
                      "generating key pair {%s}",
                      GetLastError()};
  }

  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
      EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
  if (context == nullptr) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to create context when generating key pair {%s}",
                      GetLastError()};
  }

  if (EVP_PKEY_keygen_init(context.get()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to initialize key generation when generating key "
                      "pair {%s}",
                      GetLastError()};
  }

  if (EVP_PKEY_CTX_set_params(context.get(), params.get()) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to set parameters when generating key pair {%s}",
                      GetLastError()};
  }

  EVP_PKEY *keyPair = nullptr;
  if (EVP_PKEY_generate(context.get(), &keyPair) <= 0) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to generate key pair {%s}", GetLastError()};
  }

  if (!IsPrivateKeyValid()) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to generate a valid private key {%s}",
                      GetLastError()};
  }

  if (!IsPublicKeyValid()) {
    return OsslResult{OsslResult::Status::Failure,
                      "Failed to generate a valid public key {%s}",
                      GetLastError()};
  }

  m_keyPair.reset(keyPair);
  return OsslResult{OsslResult::Status::Success,
                    "Key pair generated successfully"};
}

ossl::OsslResult ossl::OsslEcKey::GenerateFromSeedPhrase(
    const std::string &hexSeedPhrase) noexcept {
  // Clear out any previous errors
  ERR_clear_error();

  // First we will create the param builder
  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> paramBld(
      OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (!paramBld) {
    return {OsslResult::Status::Failure,
            "Failed to create the parameter builder {%s}", GetLastError()};
  }

  // Now we push the curve name to the parameter builder
  if (OSSL_PARAM_BLD_push_utf8_string(
          paramBld.get(), OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the curve name to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the hex seed phrase to a BIGNUM since this is the private
  // key
  std::unique_ptr<BIGNUM, decltype(&BN_free)> seedPhrase(
      HexToBigNum(hexSeedPhrase), BN_free);
  if (!seedPhrase) {
    return {OsslResult::Status::Failure,
            "Failed to convert the hex seed phrase to a BIGNUM"};
  }

  // Now we push the seed phrase to the parameter builder
  if (OSSL_PARAM_BLD_push_BN(paramBld.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                             seedPhrase.get()) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the seed phrase to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we need to calculate the public key
  std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
      EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free);
  std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> publicKey(
      EC_POINT_new(group.get()), EC_POINT_free);
  if (!publicKey) {
    return {OsslResult::Status::Failure, "Failed to create the public key {%s}",
            GetLastError()};
  }
  // Multiply the generator point by the private key to get the public key
  if (!EC_POINT_mul(group.get(), publicKey.get(), seedPhrase.get(), nullptr,
                    nullptr, nullptr)) {
    return {OsslResult::Status::Failure,
            "Failed to calculate the public key {%s}", GetLastError()};
  }
  size_t pubKeySize =
      EC_POINT_point2oct(group.get(), publicKey.get(),
                         POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (pubKeySize == 0) {
    return {OsslResult::Status::Failure,
            "Failed to get the public key size {%s}", GetLastError()};
  }
  std::vector<unsigned char> pubKey(pubKeySize);
  if (!EC_POINT_point2oct(group.get(), publicKey.get(),
                          POINT_CONVERSION_UNCOMPRESSED, pubKey.data(),
                          pubKey.size(), nullptr)) {
    return {OsslResult::Status::Failure, "Failed to get the public key {%s}",
            GetLastError()};
  }
  // Finally we set the public key in the parameter builder
  if (OSSL_PARAM_BLD_push_octet_string(paramBld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       pubKey.data(), pubKey.size()) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the public key to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the parameter builder to parameters
  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
      OSSL_PARAM_BLD_to_param(paramBld.get()), OSSL_PARAM_free);
  if (!params) {
    return {OsslResult::Status::Failure,
            "Failed to convert the parameter builder to parameters {%s}",
            GetLastError()};
  }

  // We want to create an EC key generation context
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    return {OsslResult::Status::Failure,
            "Failed to create the key generation context {%s}", GetLastError()};
  }

  // We want to create this key from existing data
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    return {OsslResult::Status::Failure,
            "Failed to initialize the key generation context from existing "
            "data {%s}",
            GetLastError()};
  }

  // Now we can generate the key pair from the data of the seed phrase
  EVP_PKEY *keyPair =
      nullptr; // Gotta set this to null or it will cause a memory leak
               // because openssl thinks the pointer is valid
  if (EVP_PKEY_fromdata(ctx.get(), &keyPair,
                        EVP_PKEY_KEY_PARAMETERS |
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                        params.get()) <= 0) {
    return {OsslResult::Status::Failure,
            "Failed to generate the key pair from the seed phrase {%s}",
            GetLastError()};
  }

  // Lets sanity check the key
  if (!IsPrivateKeyValid()) {
    return {OsslResult::Status::Failure,
            "Failed to generate a valid private key {%s}", GetLastError()};
  }
  if (!IsPublicKeyValid()) {
    return {OsslResult::Status::Failure,
            "Failed to generate a valid public key {%s}", GetLastError()};
  }

  // Now we can set the key pair
  m_keyPair.reset(keyPair);

  return {OsslResult::Status::Success};
}

ossl::OsslResult ossl::OsslEcKey::GenerateKeyFromPrivateHex(
    const std::string &privateKeyHex) noexcept {
  // Clear out any previous errors
  ERR_clear_error();

  // First we will create the param builder
  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> paramBld(
      OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (!paramBld) {
    return {OsslResult::Status::Failure,
            "Failed to create the parameter builder {%s}", GetLastError()};
  }

  // Now we push the curve name to the parameter builder
  if (OSSL_PARAM_BLD_push_utf8_string(
          paramBld.get(), OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the curve name to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the hex private key to a BIGNUM
  std::unique_ptr<BIGNUM, decltype(&BN_free)> privateKey(
      HexToBigNum(privateKeyHex), BN_free);
  if (!privateKey) {
    return {OsslResult::Status::Failure,
            "Failed to convert the hex private key to a BIGNUM"};
  }

  // Now we push the private key to the parameter builder
  if (OSSL_PARAM_BLD_push_BN(paramBld.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                             privateKey.get()) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the private key to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the parameter builder to parameters
  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
      OSSL_PARAM_BLD_to_param(paramBld.get()), OSSL_PARAM_free);
  if (!params) {
    return {OsslResult::Status::Failure,
            "Failed to convert the parameter builder to parameters {%s}",
            GetLastError()};
  }

  // We want to create an EC key generation context
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    return {OsslResult::Status::Failure,
            "Failed to create the key generation context {%s}", GetLastError()};
  }

  // We want to create this key from existing data
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    return {OsslResult::Status::Failure,
            "Failed to initialize the key generation context from existing "
            "data {%s}",
            GetLastError()};
  }

  // Now we can generate the key pair from the data of the private key
  EVP_PKEY *keyPair =
      nullptr; // Gotta set this to null or it will cause a memory leak because
               // openssl thinks the pointer is valid
  if (EVP_PKEY_fromdata(ctx.get(), &keyPair,
                        EVP_PKEY_KEY_PARAMETERS |
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                        params.get()) <= 0) {
    return {OsslResult::Status::Failure,
            "Failed to generate the key pair from the private key {%s}",
            GetLastError()};
  }

  // Lets sanity check the key
  if (!IsPrivateKeyValid()) {
    return {OsslResult::Status::Failure,
            "Failed to generate a valid private key {%s}", GetLastError()};
  }

  m_keyPair.reset(keyPair);

  return {OsslResult::Status::Success};
}

ossl::OsslResult ossl::OsslEcKey::GenerateKeyFromPublicHex(
    const std::string &publicKeyHex) noexcept {
  // Clear out any previous errors
  ERR_clear_error();

  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> paramBld(
      OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (!paramBld) {
    return {OsslResult::Status::Failure,
            "Failed to create the parameter builder {}", GetLastError()};
  }

  // Now we set the curve name, which we assume is secp256k1
  if (OSSL_PARAM_BLD_push_utf8_string(
          paramBld.get(), OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the curve name to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the hex public key to raw data.
  std::string binPublicKey;
  if (!HexToData(publicKeyHex, &binPublicKey)) {
    return {OsslResult::Status::Failure,
            "Failed to convert the hex public key to raw data"};
  }

  // Now we set the raw public key
  if (!OSSL_PARAM_BLD_push_octet_string(paramBld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                        binPublicKey.data(),
                                        binPublicKey.size())) {
    return {OsslResult::Status::Failure,
            "Failed to push the raw public key to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the parameter builder to parameters
  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
      OSSL_PARAM_BLD_to_param(paramBld.get()), OSSL_PARAM_free);
  if (!params) {
    return {OsslResult::Status::Failure,
            "Failed to convert the parameter builder to parameters {%s}",
            GetLastError()};
  }

  // Then we create the key context
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    return {OsslResult::Status::Failure,
            "Failed to create the key context {%s}", GetLastError()};
  }

  // Now we initialize the key context
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    return {OsslResult::Status::Failure,
            "Failed to initialize the key context {%s}", GetLastError()};
  }

  // Now we can create the public key object
  EVP_PKEY *temp = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &temp, EVP_PKEY_PUBLIC_KEY, params.get()) <=
      0) {
    return {OsslResult::Status::Failure,
            "Failed to create the public key object {%s}", GetLastError()};
  }

  // Lets sanity check the key
  if (!IsPublicKeyValid()) {
    return {OsslResult::Status::Failure,
            "Failed to generate a valid public key {%s}", GetLastError()};
  }

  m_keyPair.reset(temp);

  return {OsslResult::Status::Success};
}

ossl::OsslResult ossl::OsslEcKey::GenerateKeyFromPrivateAndPublicHex(
    const std::string &privateKeyHex,
    const std::string &publicKeyHex) noexcept {
  // Clear out any previous errors
  ERR_clear_error();

  std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> paramBld(
      OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (!paramBld) {
    return {OsslResult::Status::Failure,
            "Failed to create the parameter builder {}", GetLastError()};
  }

  // Now we set the curve name, which we assume is secp256k1
  if (OSSL_PARAM_BLD_push_utf8_string(
          paramBld.get(), OSSL_PKEY_PARAM_GROUP_NAME, SN_secp256k1, 0) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the curve name to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the hex private key to a BIGNUM
  std::unique_ptr<BIGNUM, decltype(&BN_free)> privateKey(
      HexToBigNum(privateKeyHex), BN_free);
  if (!privateKey) {
    return {OsslResult::Status::Failure,
            "Failed to convert the hex private key to a BIGNUM"};
  }

  // Now we convert the hex public key to raw data.
  std::string binPublicKey;
  if (!HexToData(publicKeyHex, &binPublicKey)) {
    return {OsslResult::Status::Failure,
            "Failed to convert the hex public key to raw data"};
  }

  // Now we push the private key to the parameter builder
  if (OSSL_PARAM_BLD_push_BN(paramBld.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                             privateKey.get()) != 1) {
    return {OsslResult::Status::Failure,
            "Failed to push the private key to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we set the raw public key
  if (!OSSL_PARAM_BLD_push_octet_string(paramBld.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                        binPublicKey.data(),
                                        binPublicKey.size())) {
    return {OsslResult::Status::Failure,
            "Failed to push the raw public key to the parameter builder {%s}",
            GetLastError()};
  }

  // Now we convert the parameter builder to parameters
  std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> params(
      OSSL_PARAM_BLD_to_param(paramBld.get()), OSSL_PARAM_free);
  if (!params) {
    return {OsslResult::Status::Failure,
            "Failed to convert the parameter builder to parameters {%s}",
            GetLastError()};
  }

  // Then we create the key context
  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
      EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (!ctx) {
    return {OsslResult::Status::Failure,
            "Failed to create the key context {%s}", GetLastError()};
  }

  // Now we initialize the key context
  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    return {OsslResult::Status::Failure,
            "Failed to initialize the key context {%s}", GetLastError()};
  }

  // Now we can create the public key object
  EVP_PKEY *temp = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &temp, EVP_PKEY_KEYPAIR, params.get()) <=
      0) {
    return {OsslResult::Status::Failure,
            "Failed to create the public key object {%s}", GetLastError()};
  }

  // Lets sanity check the key
  if (!IsPrivateKeyValid()) {
    return {OsslResult::Status::Failure,
            "Failed to generate a valid private key {%s}", GetLastError()};
  }

  if (!IsPublicKeyValid()) {
    return {OsslResult::Status::Failure,
            "Failed to generate a valid public key {%s}", GetLastError()};
  }

  m_keyPair.reset(temp);

  return {OsslResult::Status::Success};
}

ossl::OsslResult
ossl::OsslEcKey::GetPrivateKeyHex(std::string *privateKeyHex) const noexcept {
  // Clear out any previous errors
  ERR_clear_error();

  // The private key is stored as a BIGNUM object.
  BIGNUM *privateKey = nullptr;
  if (!EVP_PKEY_get_bn_param(m_keyPair.get(), OSSL_PKEY_PARAM_PRIV_KEY,
                             &privateKey)) {
    return {OsslResult::Status::Failure, "Failed to get the private key {%s}",
            GetLastError()};
  }

  std::unique_ptr<BIGNUM, decltype(&BN_free)> privateKeyPtr(privateKey,
                                                            BN_free);

  // Now we can convert the private key to a hex string
  *privateKeyHex = BigNumToHex(privateKey);
  if (privateKeyHex->empty()) {
    return {OsslResult::Status::Failure,
            "Failed to convert the private key to a hex string {%s}",
            GetLastError()};
  }

  return {OsslResult::Status::Success};
}

ossl::OsslResult
ossl::OsslEcKey::GetPublicKeyHex(std::string *publicKeyHex,
                                 bool isUncompressed) const noexcept {
  // Clear out any previous errors
  ERR_clear_error();

  // The public key is stored as a byte array.
  size_t keyLength = 0;
  if (!EVP_PKEY_get_octet_string_param(m_keyPair.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       nullptr, 0, &keyLength)) {
    return {OsslResult::Status::Failure,
            "Failed to get the public key length {%s}", GetLastError()};
  }

  // Now we can get the public key
  std::unique_ptr<unsigned char[]> publicKey(new unsigned char[keyLength]);
  if (!EVP_PKEY_get_octet_string_param(m_keyPair.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                       publicKey.get(), keyLength,
                                       &keyLength)) {
    return {OsslResult::Status::Failure, "Failed to get the public key {%s}",
            GetLastError()};
  }

  // If the public key is compressed we need to decompress it
  if (isUncompressed) {
    // we can convert the public key bytes to a point
    // Create a group
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(
        EC_GROUP_new_by_curve_name(NID_secp256k1), EC_GROUP_free);
    if (!group) {
      return {OsslResult::Status::Failure,
              "Failed to create the group for a compressed key {%s}",
              GetLastError()};
    }

    // Create a point
    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(
        EC_POINT_new(group.get()), EC_POINT_free);
    if (!point) {
      return {OsslResult::Status::Failure,
              "Failed to create the point for a compressed key {%s}",
              GetLastError()};
    }

    // Set the point
    if (!EC_POINT_oct2point(group.get(), point.get(), publicKey.get(),
                            keyLength, nullptr)) {
      return {OsslResult::Status::Failure,
              "Failed to set the point for a compressed key {%s}",
              GetLastError()};
    }

    // We have to re-assign the public key to a new buffer because the
    // decompressed key will be larger
    keyLength =
        EC_POINT_point2oct(group.get(), point.get(),
                           POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    if (keyLength == 0) {
      return {OsslResult::Status::Failure,
              "Failed to get the decompressed public key length {%s}",
              GetLastError()};
    }

    publicKey = std::make_unique<unsigned char[]>(keyLength);
    keyLength = EC_POINT_point2oct(group.get(), point.get(),
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   publicKey.get(), keyLength, nullptr);
    if (keyLength == 0) {
      return {OsslResult::Status::Failure,
              "Failed to get the decompressed public key length {%s}",
              GetLastError()};
    }
  }

  // Lastly we convert the byte array to a hex string
  *publicKeyHex = DataToHex(
      std::string(reinterpret_cast<char *>(publicKey.get()), keyLength));
  if (publicKeyHex->empty()) {
    return {OsslResult::Status::Failure,
            "Failed to convert the public key to a hex string {%s}",
            GetLastError()};
  }

  return {OsslResult::Status::Success};
}
