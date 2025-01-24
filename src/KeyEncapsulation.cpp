// exports.KeyEncapsulation

#include "KeyEncapsulation.h"

#include <cstdint>
#include <memory>
#include <new>
#include <vector>
#include <napi.h>

// liboqs-cpp
#include "oqs_cpp.hpp"
#include "common.hpp"

namespace KeyEncapsulation {

  using oqs::byte;
  using oqs::bytes;

  /**
   * Constructs an instance of KeyEncapsulation.
   * @name KeyEncapsulation
   * @class
   * @constructs KeyEncapsulation
   * @param {KEMs.Algorithm} algorithm - The KEM algorithm to use.
   * @param {Buffer} [secretKey] - An optional secret key. If not specified, use KeyEncapsulation#generateKeypair later to create a secret key.
   * @throws {TypeError} Will throw an error if any argument is invalid.
   */
  KeyEncapsulation::KeyEncapsulation(const Napi::CallbackInfo& info) : Napi::ObjectWrap<KeyEncapsulation>(info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
      throw Napi::TypeError::New(env, "Algorithm must be a string");
    }
    if (!info[0].IsString()) {
      throw Napi::TypeError::New(env, "Algorithm must be a string");
    }
    const auto algorithm = info[0].As<Napi::String>().Utf8Value();
    if (info.Length() >= 2) {
      if (!info[1].IsBuffer()) {
        throw Napi::TypeError::New(env, "Secret key must be a buffer");
      }
      const auto secretKeyBuffer = info[1].As<Napi::Buffer<byte>>();
      const auto secretKeyData = secretKeyBuffer.Data();
      const bytes secretKeyVec(secretKeyData, secretKeyData + secretKeyBuffer.Length());
      try {
        oqsKE = std::make_unique<oqs::KeyEncapsulation>(algorithm, secretKeyVec);
      } catch (const std::exception& ex) {
        throw Napi::TypeError::New(env, ex.what());
      }
    } else {
      try {
        oqsKE = std::make_unique<oqs::KeyEncapsulation>(algorithm);
      } catch (const std::exception& ex) {
        throw Napi::TypeError::New(env, ex.what());
      }
    }
  }

  /**
   * Gets the details for the KEM algorithm that the instance was constructed with.
   * @memberof KeyEncapsulation
   * @instance
   * @method
   * @name getDetails
   * @returns {Object} - An object containing the details of the KEM algorithm.
   */
  Napi::Value KeyEncapsulation::getDetails(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    const oqs::KeyEncapsulation::KeyEncapsulationDetails details = oqsKE->get_details();
    auto detailsObj = Napi::Object::New(env);
    detailsObj.Set(
      Napi::String::New(env, "name"),
      Napi::String::New(env, details.name)
    );
    detailsObj.Set(
      Napi::String::New(env, "version"),
      Napi::String::New(env, details.version)
    );
    detailsObj.Set(
      Napi::String::New(env, "claimedNistLevel"),
      Napi::Number::New(env, details.claimed_nist_level)
    );
    detailsObj.Set(
      Napi::String::New(env, "isINDCCA"),
      Napi::Boolean::New(env, details.is_ind_cca)
    );
    detailsObj.Set(
      Napi::String::New(env, "publicKeyLength"),
      Napi::Number::New(env, details.length_public_key)
    );
    detailsObj.Set(
      Napi::String::New(env, "secretKeyLength"),
      Napi::Number::New(env, details.length_secret_key)
    );
    detailsObj.Set(
      Napi::String::New(env, "ciphertextLength"),
      Napi::Number::New(env, details.length_ciphertext)
    );
    detailsObj.Set(
      Napi::String::New(env, "sharedSecretLength"),
      Napi::Number::New(env, details.length_shared_secret)
    );
    return detailsObj;
  }

  /**
   * Generates a keypair. Overwrites any existing secret key on the instance with the generated secret key.
   * @memberof KeyEncapsulation
   * @instance
   * @method
   * @name generateKeypair
   * @returns {Buffer} - A Buffer containing the public key.
   * @throws {Error} Will throw an error if memory cannot be allocated..
   */
Napi::Value KeyEncapsulation::generateKeypair(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  try {
    const bytes publicKeyVec = oqsKE->generate_keypair();
    Napi::Buffer<byte> buffer = Napi::Buffer<byte>::New(env, publicKeyVec.size());
    std::memcpy(buffer.Data(), publicKeyVec.data(), publicKeyVec.size());
    return buffer;
  } catch (const std::exception& ex) {
    throw Napi::Error::New(env, ex.what());
  }
}


  /**
   * Exports the secret key.
   * @memberof KeyEncapsulation
   * @instance
   * @method
   * @name exportSecretKey
   * @returns {Buffer} - A Buffer containing the secret key.
   * @throws {Error} Will throw an error if memory cannot be allocated.
   */
Napi::Value KeyEncapsulation::exportSecretKey(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  try {
    // Export the secret key
    bytes secretKeyVec = oqsKE->export_secret_key();

    // Create a Napi buffer and copy the secret key into it
    Napi::Buffer<byte> buffer = Napi::Buffer<byte>::New(env, secretKeyVec.size());
    std::memcpy(buffer.Data(), secretKeyVec.data(), secretKeyVec.size());

    // Securely clean memory of the secret key vector after copying
    oqs::mem_cleanse(secretKeyVec);

    return buffer;
  } catch (const std::exception& ex) {
    // Handle any exception from oqsKE and return an error
    throw Napi::Error::New(env, ex.what());
  }
}


  /**
   * An object with the following properties:
   * * `ciphertext`: The ciphertext to be given to the owner of the public key.
   * * `sharedSecret`: The shared secret.
   * @memberof KeyEncapsulation
   * @typedef {Object} CiphertextSharedSecretPair
   */

  /**
   * Encapsulates the shared secret using a provided public key.
   * @memberof KeyEncapsulation
   * @instance
   * @method
   * @name encapsulateSecret
   * @param {Buffer} publicKey - The public key belonging to the intended recipient of the shared secret.
   * @returns {KeyEncapsulation.CiphertextSharedSecretPair} - The ciphertext and shared secret.
   * @throws {TypeError} Will throw an error if any argument is invalid.
   * @throws {Error} Will throw an error if memory cannot be allocated.
   */
Napi::Value KeyEncapsulation::encapsulateSecret(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    throw Napi::TypeError::New(env, "Public key must be a buffer");
  }
  const auto publicKeyBuffer = info[0].As<Napi::Buffer<byte>>();
  const auto publicKeyData = publicKeyBuffer.Data();
  const bytes publicKeyVec(publicKeyData, publicKeyData + publicKeyBuffer.Length());

  try {
    std::pair<bytes, bytes> encapPair = oqsKE->encap_secret(publicKeyVec);

    // Create buffers for ciphertext and shared secret
    Napi::Buffer<byte> ciphertextBuffer = Napi::Buffer<byte>::New(env, encapPair.first.size());
    std::memcpy(ciphertextBuffer.Data(), encapPair.first.data(), encapPair.first.size());

    Napi::Buffer<byte> sharedSecretBuffer = Napi::Buffer<byte>::New(env, encapPair.second.size());
    std::memcpy(sharedSecretBuffer.Data(), encapPair.second.data(), encapPair.second.size());
    oqs::mem_cleanse(encapPair.second); // Clean after copying

    auto result = Napi::Object::New(env);
    result.Set("ciphertext", ciphertextBuffer);
    result.Set("sharedSecret", sharedSecretBuffer);
    return result;
  } catch (const std::exception& ex) {
    throw Napi::Error::New(env, ex.what());
  }
}

  /**
   * Decapsulates the shared secret using a provided public key.
   * @memberof KeyEncapsulation
   * @instance
   * @method
   * @name decapsulateSecret
   * @param {Buffer} ciphertext - The ciphertext that was encrypted using the instance's public key.
   * @returns {Buffer} - The shared secret.
   * @throws {TypeError} Will throw an error if any argument is invalid.
   * @throws {Error} Will throw an error if memory cannot be allocated.
   */
Napi::Value KeyEncapsulation::decapsulateSecret(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 1 || !info[0].IsBuffer()) {
    throw Napi::TypeError::New(env, "Ciphertext must be a buffer");
  }
  const auto ciphertextBuffer = info[0].As<Napi::Buffer<byte>>();
  const auto ciphertextData = ciphertextBuffer.Data();
  const bytes ciphertextVec(ciphertextData, ciphertextData + ciphertextBuffer.Length());

  try {
    bytes sharedSecretVec = oqsKE->decap_secret(ciphertextVec);

    Napi::Buffer<byte> buffer = Napi::Buffer<byte>::New(env, sharedSecretVec.size());
    std::memcpy(buffer.Data(), sharedSecretVec.data(), sharedSecretVec.size());
    oqs::mem_cleanse(sharedSecretVec); // Clean after copying
    return buffer;
  } catch (const std::exception& ex) {
    throw Napi::Error::New(env, ex.what());
  }
}

  void KeyEncapsulation::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "KeyEncapsulation", {
      InstanceMethod<&KeyEncapsulation::getDetails>("getDetails"),
      InstanceMethod<&KeyEncapsulation::generateKeypair>("generateKeypair"),
      InstanceMethod<&KeyEncapsulation::exportSecretKey>("exportSecretKey"),
      InstanceMethod<&KeyEncapsulation::encapsulateSecret>("encapsulateSecret"),
      InstanceMethod<&KeyEncapsulation::decapsulateSecret>("decapsulateSecret")
    });
    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    exports.Set(
      Napi::String::New(env, "KeyEncapsulation"),
      func
    );
    env.SetInstanceData<Napi::FunctionReference>(constructor);
  }

  void Init(Napi::Env env, Napi::Object exports) {
    KeyEncapsulation::Init(env, exports);
  }

} // namespace KeyEncapsulation
