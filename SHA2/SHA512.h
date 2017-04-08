// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.If not, see <http://www.gnu.org/licenses/>.
//
// 
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 512 bit return size. 
// Written by John Underhill, July 31, 2016
// Updated March 20, 2017
// Contact: develop@vtdev.com

#ifndef _CEX_SHA512_H
#define _CEX_SHA512_H

#include "IDigest.h"
#include "SHA2Params.h"

NAMESPACE_DIGEST

/// <summary>
/// An implementation of the SHA-2 digest with a 512 bit digest return size
/// </summary> 
/// 
/// <example>
/// <description>Using the Compute method:</description>
/// <code>
/// SHA512 dgt;
/// std:vector&lt;byte&gt; hash(digest.DigestSize(), 0);
/// // compute a hash
/// dgt.Update(Input, 0, Input.size());
/// dgt.Finalize(hash, 0);
/// dgt.Reset();
/// </code>
/// </example>
/// 
/// <remarks>
/// <description>Tree Hashing Description:</description>
/// <para>The tree hashing mode is instantiated when the parallel mechanism is engaged through the constructors Parallel parameter. \n 
/// The default number of threads is 8, this can be changed using the ParallelMaxDegree(size_t) function, but not directly through the ParallelProfile accessor,
/// (state sizes must be recalculated when the thread count changes).
/// Changing the thread count from the default, will produce a different hash output. \n
/// The thread count must be an even number less or equal to the number of processing cores. \n
/// For best performance in tree hashing mode, the message input block-size (Length parameter of an Update call), should be ParallelBlockSize in length. \n
/// The ideal parallel block-size is calculated automatically based on the hardware profile and algorithm requirments. \n
/// The parallel mode uses multi-threaded parallel processing, with each thread maintaining a single unique state. \n
/// The hash finalizer processes each leaf state as contiguous message input for the root hash; i.e. R = H(S0 || S1 || S2 || ...Sn).</para>
///
/// <description>Implementation Notes:</description>
/// <list type="bullet">
/// <item><description>State block size is 128 bytes, (1024 bits), in parallel mode the ParallelBlockSize() is used (P * B * 4).</description></item>
/// <item><description>Digest output size is 64 bytes, (512 bits).</description></item>
/// <item><description>The <see cref="Compute(byte[])"/> method wraps the <see cref="Update(byte[], size_t, size_t)"/> and Finalize methods; (suitable for small data).</description>/></item>
/// <item><description>The <see cref="Update(byte)"/> and <see cref="Update(byte[], size_t, size_t)"/> methods process message input.</description></item>
/// <item><description>The <see cref="Finalize(byte[], size_t)"/> method returns the hash or MAC code and resets the internal state.</description></item>
/// <item><description>Setting Parallel to true in the constructor instantiates the multi-threaded variant.</description></item>
/// <item><description>Multi-threaded and sequential versions produce a different output hash for a message, this is expected.</description></item>
/// </list>
/// 
/// <description>Guiding Publications:</description>
/// <list type="number">
/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Standard</a>.</description></item>
/// <item><description><a href="http://keccak.noekeon.org/Sakura.pdf">Sakura:</a> a flexible coding for tree hashing.</description></item>
/// <item><description>SHA256: A <a href="https://eprint.iacr.org/2012/476.pdf">j-lanes tree hashing mode</a> and j-lanes SHA-256.</description></item>
/// <item><description>Analysis of <a href="http://scholarworks.rit.edu/theses/8312/">KECCAK Tree Hashing</a> on GPU Architectures.</description></item>
/// <item><description>Parallelized Hashing via <a href="http://file.scirp.org/pdf/JIS_2014071709515287.pdf">j-Lanes and j-Pointers</a> Tree Modes.</description></item>
/// <item><description>Analysis of SIMD Applicability to <a href="https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf">SHA Algorithms</a></description></item>
/// <item><description>Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.</description></item>
/// <item><description>NIST, 2014 SHA3 Workshop <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/Aug2014/documents/kelsey_sha3_2014_panel.pdf">What Should Be In A Parallel Hashing Standard?</a>.</description></item>
/// <item><description>Recommendation for Random Number Generation Using <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Deterministic Random Bit Generators.</a></description></item>
/// </list>
/// </remarks>
class SHA512 : public IDigest
{
private:

	static const size_t BLOCK_SIZE = 128;
	static const size_t DIGEST_SIZE = 64;
	static const ulong DEF_PRLDEGREE = 8;
	// size of reserved state buffer subtracted from parallel size calculations
	static const size_t STATE_PRECACHED = 2048;

	struct SHA512State
	{
		std::vector<ulong> H;
		std::vector<ulong> T;

		SHA512State()
			:
			H(8),
			T(2)
		{
		}

		void Increase(size_t Length)
		{
			T[0] += Length;

			if (T[0] > 0x1fffffffffffffffL)
			{
				T[1] += (int64_t)(T[0] >> 61);
				T[0] &= 0x1fffffffffffffffL;
			}
		}

		void Reset()
		{
			T[0] = 0;
			T[1] = 0;
			H[0] = 0x6a09e667f3bcc908;
			H[1] = 0xbb67ae8584caa73b;
			H[2] = 0x3c6ef372fe94f82b;
			H[3] = 0xa54ff53a5f1d36f1;
			H[4] = 0x510e527fade682d1;
			H[5] = 0x9b05688c2b3e6c1f;
			H[6] = 0x1f83d9abfb41bd6b;
			H[7] = 0x5be0cd19137e2179;
		}
	};

	SHA2Params m_treeParams;
	std::vector<SHA512State> m_dgtState;
	bool m_isDestroyed;
	std::vector<byte> m_msgBuffer;
	size_t m_msgLength;
	ParallelOptions m_parallelProfile;

public:

	SHA512(const SHA512&) = delete;
	SHA512& operator=(const SHA512&) = delete;
	SHA512& operator=(SHA512&&) = delete;

	// *** Properties *** //

	/// <summary>
	/// Get: The Digests internal blocksize in bytes
	/// </summary>
	virtual size_t BlockSize() { return BLOCK_SIZE; }

	/// <summary>
	/// Get: Size of returned digest in bytes
	/// </summary>
	virtual size_t DigestSize() { return DIGEST_SIZE; }

	/// <summary>
	/// Get: The digests type name
	/// </summary>
	virtual const Digests Enumeral() { return Digests::SHA512; }

	/// <summary>
	/// Get: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available on this system.
	/// If parallel capable, input data array passed to the Update function must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() { return m_parallelProfile.IsParallel(); }

	/// <summary>
	/// Get: The digests class name
	/// </summary>
	virtual const std::string Name() { return "SHA512"; }

	/// <summary>
	/// Get: Parallel block size; the byte-size of the input data array passed to the Update function that triggers parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.<para>
	/// </summary>
	virtual const size_t ParallelBlockSize() { return m_parallelProfile.ParallelBlockSize(); }

	/// <summary>
	/// Get/Set: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest using a SHA2Params with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() { return m_parallelProfile; }

	//~~~Constructor~~~//

	/// <summary>
	/// Initialize the class with either the Parallel or Sequential hashing engine.
	/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard SHA-2 256bit hashing instance.</para>
	/// </summary>
	/// 
	/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded SHA-2 variant.</param>
	explicit SHA512(bool Parallel = false);

	/// <summary>
	/// Initialize the class with an SHA2Params structure.
	/// <para>The parameters structure allows for tuning of the internal configuration string,
	/// and changing the number of threads used by the parallel mechanism (FanOut).
	/// If the parallel degree is greater than 1, multi-threading hash engine is instantiated.
	/// The default thread count is 8, changing this value will produce a different output hash code.</para>
	/// </summary>
	/// 
	/// <param name="Params">The SHA2Params structure, containing the tree configuration settings.</param>
	///
	/// <exception cref="CryptoDigestException">Thrown if the SHA2Params structure contains invalid values</exception>
	explicit SHA512(SHA2Params &Params);

	/// <summary>
	/// Finalize objects
	/// </summary>
	virtual ~SHA512();

	//~~~Public Functions~~~//

	/// <summary>
	/// Get the hash code for a message input array
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="Output">The hash output code array</param>
	virtual void Compute(const std::vector<byte> &Input, std::vector<byte> &Output);

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy();

	/// <summary>
	/// Finalize processing and get the hash code
	/// </summary>
	/// 
	/// <param name="Output">The hash output code array</param>
	/// <param name="OutOffset">The starting offset within the output array</param>
	/// 
	/// <returns>The byte size of the hash code</returns>
	///
	/// <exception cref="CryptoDigestException">Thrown if the output array is too short</exception>
	virtual size_t Finalize(std::vector<byte> &Output, const size_t OutOffset);

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoDigestException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Reset the internal state
	/// </summary>
	virtual void Reset();

	/// <summary>
	/// Update the hash with a single byte
	/// </summary>
	/// 
	/// <param name="Input">Input message byte</param>
	virtual void Update(byte Input);

	/// <summary>
	/// Update the buffer with a block of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input message array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Length">The number of message bytes to process</param>
	virtual void Update(const std::vector<byte> &Input, size_t InOffset, size_t Length);

private:

	void Compress(const std::vector<byte> &Input, size_t InOffset, SHA512State &State);
	void HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, SHA512State &State);
	void ProcessLeaf(const std::vector<byte> &Input, size_t InOffset, SHA512State &State, ulong Length);
};

NAMESPACE_DIGESTEND
#endif
