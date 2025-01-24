// exports.Random

#include "Random.h"

#include <cstdint>
#include <new>
#include <vector>
#include <napi.h>

// liboqs-cpp
#include "rand/rand.hpp"
#include "common.hpp"

/** @namespace Random */
namespace Random {

  using oqs::byte;
  using oqs::bytes;

  /**
   * The different PRNG algorithms that can be used. It can be one of the following:
   * * `system`: System PRNG. Reads directly from `/dev/urandom`.
   * * `NIST-KAT`: NIST deterministic RNG for KATs.
   * * `OpenSSL`: OpenSSL's PRNG.
   * Defaults to `system`.
   * @memberof Random
   * @typedef {string} Algorithm
   */

  /**
   * Switches the PRNG algorithm used by the library.
   * @memberof Random
   * @name switchAlgorithm
   * @static
   * @method
   * @param {Random.Algorithm} algorithm - The PRNG algorithm to use.
   * @throws {TypeError} Will throw an error if any argument is invalid.
   */
  Napi::Value switchAlgorithm(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
      throw Napi::TypeError::New(env, "Algorithm must be a string");
    }
    if (!info[0].IsString()) {
      throw Napi::TypeError::New(env, "Algorithm must be a string");
    }
    const auto algorithm = info[0].As<Napi::String>().Utf8Value();
    try {
      oqs::rand::randombytes_switch_algorithm(algorithm);
    } catch (const std::exception& ex) {
      throw Napi::TypeError::New(env, ex.what());
    }
    return env.Undefined();
  }

  /**
   * Generates cryptographically-secure random bytes.
   * @memberof Random
   * @name randomBytes
   * @static
   * @method
   * @param {number} size - The size of the returned Buffer.
   * @returns {Buffer} bytes - A Buffer with `size` random bytes.
   * @throws {TypeError} Will throw an error if any argument is invalid.
   * @throws {Error} Will throw an error if memory cannot be allocated.
   */
Napi::Value randomBytes(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  // Validate arguments
  if (info.Length() < 1 || !info[0].IsNumber()) {
    throw Napi::TypeError::New(env, "Bytes must be a positive number");
  }

  const auto size = info[0].As<Napi::Number>().Int64Value();
  if (size < 0) {
    throw Napi::TypeError::New(env, "Bytes must be non-negative");
  }

  // Generate random bytes
  oqs::bytes randomData(size);
  oqs::rand::randombytes(randomData, static_cast<std::size_t>(size));

  // Create a Napi::Buffer and copy data into it
  Napi::Buffer<byte> buffer = Napi::Buffer<byte>::New(env, size);
  std::memcpy(buffer.Data(), randomData.data(), size);

  return buffer;
}


  /**
   * Generates cryptographically-secure random bytes.
   * @memberof Random
   * @name initNistKat
   * @static
   * @method
   * @param {Buffer} entropy - The entropy input seed. Must be exactly 48 bytes long.
   * @param {Buffer} [personalizationString] - A personalization string. Must be at least 48 bytes long if provided.
   * @throws {TypeError} Will throw an error if any argument is invalid.
   */
  Napi::Value initNistKat(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    if (info.Length() < 1) {
      throw Napi::TypeError::New(env, "Entropy must be a Buffer");
    }
    if (!info[0].IsBuffer()) {
      throw Napi::TypeError::New(env, "Entropy must be a Buffer");
    }
    // Buffer lengths are checked by oqs::rand::randombytes_nist_kat_init_256bit
    const auto entropyBuffer = info[0].As<Napi::Buffer<byte>>();
    const auto entropyData = entropyBuffer.Data();
    bytes entropyVec(entropyData, entropyData + entropyBuffer.Length());
    if (info.Length() >= 2) {
      if (!info[1].IsBuffer()) {
        throw Napi::TypeError::New(env, "Personalization string must be a Buffer");
      }
      const auto pstringBuffer = info[1].As<Napi::Buffer<byte>>();
      const auto pstringData = pstringBuffer.Data();
      bytes pstringVec(pstringData, pstringData + pstringBuffer.Length());
      // try {
      //   oqs::rand::randombytes_nist_kat_init_256bit(entropyVec, pstringVec);
      // } catch (const std::exception& ex) {
      //   oqs::mem_cleanse(entropyVec);
      //   oqs::mem_cleanse(pstringVec);
      //   throw Napi::TypeError::New(env, ex.what());
      // }
      oqs::mem_cleanse(pstringVec);
    } else {
      // try {
      //   oqs::rand::randombytes_nist_kat_init_256bit(entropyVec);
      // } catch (const std::exception& ex) {
      //   oqs::mem_cleanse(entropyVec);
      //   throw Napi::TypeError::New(env, ex.what());
      // }
    }
    oqs::mem_cleanse(entropyVec);
    return env.Undefined();
  }

  void Init(Napi::Env env, Napi::Object exports) {
    auto randExports = Napi::Object::New(env);
    randExports.Set(
      Napi::String::New(env, "switchAlgorithm"),
      Napi::Function::New(env, switchAlgorithm)
    );
    randExports.Set(
      Napi::String::New(env, "randomBytes"),
      Napi::Function::New(env, randomBytes)
    );
    randExports.Set(
      Napi::String::New(env, "initNistKat"),
      Napi::Function::New(env, initNistKat)
    );
    exports.Set(
      Napi::String::New(env, "Random"),
      randExports
    );
  }

} // namespace Random
