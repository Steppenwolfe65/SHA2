// The MIT License (MIT)
// 
// Copyright (c) 2016 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// Principal Algorithms:
// An implementation of the SHA-2 digest with a 512 bit return size.
// SHA-2 <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">Specification</a>.
// 
// Implementation Details:
// An implementation of the SHA-2 digest with a 512 bit return size. 
// Written by John Underhill, July 31, 2016
// contact: develop@vtdev.com

#ifndef _CEXENGINE_SHA512_H
#define _CEXENGINE_SHA512_H

#include "IDigest.h"
#include "MacParams.h"
#include "SHA2Params.h"

namespace SHA2
{
	/// <summary>
	/// SHA512: An implementation of the SHA-2 digest with a 512 bit digest return size.
	/// <para>Implements a sequential or parallelized hash function, HMAC, or HKDF bytes generator.</para>
	/// </summary> 
	/// 
	/// <example>
	/// <description>Using the ComputeHash method:</description>
	/// <code>
	/// SHA512 dgt;
	/// std:vector&lt;byte&gt; hash(dgt.DigestSize(), 0);
	/// // compute a hash
	/// dgt.ComputeHash(Input, hash);
	/// </code>
	///
	/// <description>Implement an HMAC:</description>
	/// <code>
	/// SHA512 dgt;
	/// std:vector&lt;byte&gt; mac(dgt.DigestSize(), 0);
	/// // initialize HMAC by loading the key
	/// dgt.LoadMacKey(MacParams(user-key));
	/// // compute mac
	/// dgt.ComputeHash(Input, mac);
	/// </code>
	///
	/// <description>HKDF Generator:</description>
	/// <code>
	/// SHA512 dgt;
	/// std:vector&lt;byte&gt; output(100);
	/// // fill output with p-rand
	/// dgt.Generate(MacParams(user-key), output);
	/// </code>
	/// </example>
	/// 
	/// <remarks>
	/// <description>Tree Hashing Description:</description>
	/// <para>Tree hashing mode is instantiated when the parallel mechanism is engaged through one of the constructors.
	/// The parallel mode uses multi-threading parallel processing, in conjunction with (if supported) SIMD multi-block concurrent processing.
	/// The hash digest creates a series of lanes using the formula ParallelDegree * ni, where ni is the maximum number of blocks that can be 
	/// processed simultaneously using SIMD instructions. With SHA-2 256, the AVX 256i instructions can process 8 blocks in parallel, 
	/// with the 512 bit version of the digest, ni is equal to 4. 
	/// All parallel processing (with or without SSE3/AVX capabilities) produces an identical hash code. 
	/// Works with or without processor intrinsics; SIMD processing is enabled through run-time cpu capabilities check.</para>
	///
	/// <para>The message input is offset across lanes, with each of the (32 for SHA256, 16 for SHA512) lanes consuming the offset input in equal amounts, staggered in a j-slice arrangement.
	/// The state from these intermediate hashes is used as input for the final hash calculation, in this way message processing can be distributed between any even number of processors.
	/// The default ParallelDegree setting is 4, (this is the number of threads created to process state), but this number can be any even number, 
	/// and should be set to the number of processor cores on the target system. 
	/// Note that changing the parallel degree, will change the output hash value.</para>
	///
	/// <para>There are two tree hashing modes, the default tree has a depth of 1, where all hash states are processed as contiguous input into the root hash finalizer, H(l1,l2,l3..ln).
	/// The other tree mode is instantiated by setting the SHA2Params TreeDepth value to 2, this seperates the state into branches consisting of SubTreeLength number of nodes on each branch.
	/// Each nodes state is used as message input for an intermediate branch hash, the branch finalizer also processes the serialized SHA2Params structure, 
	/// which contains a NodeOffset counter that is equal to the linear position of the node within the tree arrangement; H(b1= H(l1,l2..ln), b2= H(ln+1,ln+2..ln+n), ..bn).
	/// After each branch is finalized, the branch states are then used as input for the root hash calculation.</para>
	///
	/// <description>Implementation Notes:</description>
	/// <list type="bullet">
	/// <item><description>State block size is 64 bytes, (512 bits).</description></item>
	/// <item><description>Digest output size is 32 bytes, (256 bits).</description></item>
	/// <item><description>The <see cref="ComputeHash(byte[])"/> method wraps the <see cref="BlockUpdate(byte[], size_t, size_t)"/> and DoFinal methods; (suitable for small data).</description>/></item>
	/// <item><description>The <see cref="Update(byte)"/> and <see cref="BlockUpdate(byte[], size_t, size_t)"/> methods process message input.</description></item>
	/// <item><description>The <see cref="DoFinal(byte[], size_t)"/> method returns the hash or MAC code and resets the internal state.</description></item>
	/// <item><description>The Generate function produces pseudo-random bytes using an internal implementation of the HKDF Expand bytes generator.</description></item>
	/// <item><description>The LoadMacKey function initializes an HMAC implementation; used with the update and DoFinal methods for creating a MAC code.</description></item>
	/// <item><description>Setting Parallel to true in the constructor instantiates the multi-threaded variant.</description></item>
	/// <item><description>Multi-threaded and sequential versions produce a different output hash for a message, this is expected.</description></item>
	/// <item><description>Default tree hashing mode is depth 1 sequential; intermediate hashes are finalized as contiguous input.</description></item>
	/// <item><description>Setting the SHA2Params TreeDepth property to 2, finalizes branches of SubTreeLength nodes as message input for the root hash.</description></item>
	/// </list>
	/// 
	/// <description>Guiding Publications:</description>
	/// <list type="number">
	/// <item><description><a href="https://eprint.iacr.org/2012/476.pdf">SHA256: A j-lanes tree hashing mode</a> and j-lanes SHA-256.</description></item>
	/// <item><description><a href="http://file.scirp.org/pdf/JIS_2014071709515287.pdf">Parallelized Hashing via j-Lanes and j</a> - Pointers Tree Modes.</description></item>
	/// <item><description>Analysis of SIMD Applicability to <a href="https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf">SHA Algorithms</a></description></item>
	/// <item><description>NIST <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">SHA-2 Specification</a>.</description></item>
	/// <item><description>Blake2 whitepaper <a href="https://blake2.net/blake2.pdf">BLAKE2: simpler, smaller, fast as MD5</a>.</description></item>
	/// <item><description>NIST, 2014 SHA3 Workshop <a href="http://csrc.nist.gov/groups/ST/hash/sha-3/Aug2014/documents/kelsey_sha3_2014_panel.pdf">What Should Be In A Parallel Hashing Standard?</a>.</description></item>
	/// <item><description>Recommendation for Random Number Generation Using <a href="http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">Deterministic Random Bit Generators.</a></description></item>
	/// </list>
	/// </remarks>
	class SHA512 : public IDigest
	{
	private:
		static constexpr size_t BLOCK_SIZE = 128;
		static constexpr size_t ITLANE_SIZE = 4;
		static constexpr size_t ITL_BLKSIZE = BLOCK_SIZE * ITLANE_SIZE;
		static constexpr ulong PRL_BRANCHSIZE = 1024 * 1000 * 10;
		static constexpr size_t DIGEST_SIZE = 64;
		static constexpr ulong PRL_DEGREE = 4;
		static constexpr ulong MAX_PRLBLOCK = 1024 * 1000 * PRL_DEGREE * 100;
		static constexpr ulong MIN_PRLBLOCK = ITL_BLKSIZE * PRL_DEGREE;

		struct SHA512State
		{
			std::vector<ulong> H;
			std::vector<ulong> T;

			SHA512State()
				:
				H(8, 0),
				T(2, 0)
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
				if (H.size() > 0)
					memset(&H[0], 0, H.size() * sizeof(ulong));
				if (T.size() > 0)
					memset(&T[0], 0, T.size() * sizeof(ulong));
			}
		};

		bool m_hasAvx;
		std::vector<byte> m_iPad;
		bool m_isDestroyed;
		bool m_isHmac;
		bool m_isInitialized;
		bool m_isParallel;
		uint32_t m_leafSize;
		size_t m_minParallel;
		std::vector<byte> m_msgBuffer;
		size_t m_msgLength = 0;
		std::vector<byte> m_oPad;
		size_t m_parallelBlockSize;
		std::vector<SHA512State> m_State;
		bool m_treeDestroy;
		SHA2Params m_treeParams;

	public:

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
		/// Get: The digests type enumeration member
		/// </summary>
		virtual Digests Enumeral() { return Digests::SHA512; }

		/// <summary>
		/// Get: Digest name
		/// </summary>
		virtual const char *Name() { return "SHA512"; }

		/// <summary>
		/// Get: Parallel block size; set either automatically, or through the constructors Blake2Params ThreadCount() parameter. Must be a multiple of <see cref="ParallelMinimumSize"/>.
		/// </summary>
		const size_t ParallelBlockSize() { return m_parallelBlockSize; }

		/// <summary>
		/// Get: Maximum input size with parallel processing
		/// </summary>
		const size_t ParallelMaximumSize() { return MAX_PRLBLOCK; }

		/// <summary>
		/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
		/// </summary>
		const size_t ParallelMinimumSize() { return m_minParallel; }

		// *** Constructor *** //

		/// <summary>
		/// Initialize the class with either the Parallel or Sequential hashing engine.
		/// <para>Initialize as parallel instantiates tree hashing, if false uses the standard SHA-2 256bit hashing instance.</para>
		/// </summary>
		/// 
		/// <param name="Parallel">Setting the Parallel flag to true, instantiates the multi-threaded SHA-2 variant.</param>
		explicit SHA512(bool Parallel = false)
			:
			m_hasAvx(false),
			m_iPad(0),
			m_isDestroyed(false),
			m_isHmac(false),
			m_isInitialized(false),
			m_isParallel(Parallel),
			m_leafSize(BLOCK_SIZE),
			m_minParallel(MIN_PRLBLOCK),
			m_msgBuffer(Parallel ? MIN_PRLBLOCK : BLOCK_SIZE, 0),
			m_msgLength(0),
			m_oPad(0),
			m_parallelBlockSize(PRL_BRANCHSIZE * PRL_DEGREE),
			m_State(Parallel ? PRL_DEGREE * ITLANE_SIZE : 1),
			m_treeDestroy(true)
		{
			if (m_isParallel)
			{
			
				DetectCpu();
				// defaults to tree depth(1), parallel degree(4), and subtree(8) branch size
				m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 1, (uint8_t)BLOCK_SIZE, (uint8_t)PRL_DEGREE, (uint8_t)ITLANE_SIZE };
			}
			else
			{
				// fixed values for sequential mode
				m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 0, (uint8_t)BLOCK_SIZE, 0, 0 };
			}

			Initialize(m_State);
		}

		/// <summary>
		/// Initialize the class with an SHA2Params structure.
		/// <para>The parameters structure allows for tuning of the internal configuration string,
		/// and changing the number of threads used by the parallel mechanism (ParallelDegree).
		/// If the parallel degree is greater than 1, multi-threading hash engine is instantiated.
		/// The default thread count is 4, changing this value will produce a different output hash code.</para>
		/// </summary>
		/// 
		/// <param name="Params">The Blake2Params structure, containing the tree configuration settings.</param>
		///
		/// <exception cref="CryptoDigestException">Thrown if the SHA2Params structure contains invalid values</exception>
		explicit SHA512(SHA2Params &Params)
			:
			m_iPad(0),
			m_isDestroyed(false),
			m_isHmac(false),
			m_isInitialized(false),
			m_isParallel(false),
			m_leafSize(BLOCK_SIZE),
			m_minParallel(Params.ParallelDegree() * ITLANE_SIZE * BLOCK_SIZE),
			m_msgBuffer(Params.ParallelDegree() > 0 ? Params.ParallelDegree() * ITLANE_SIZE * BLOCK_SIZE : BLOCK_SIZE),
			m_msgLength(0),
			m_oPad(0),
			m_State(Params.ParallelDegree() > 0 ? Params.ParallelDegree() * ITLANE_SIZE : 1),
			m_treeDestroy(false),
			m_treeParams(Params)
		{
			m_isParallel = Params.ParallelDegree() > 1;

			if (m_isParallel)
			{
#if defined(_DEBUG)
				assert(Params.LeafLength() > BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE == 0);
				assert(Params.ParallelDegree() > 2 || Params.ParallelDegree() % 2 == 0);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
				if (Params.LeafLength() != 0 && (Params.LeafLength() < BLOCK_SIZE || Params.LeafLength() % BLOCK_SIZE != 0))
					throw CryptoDigestException("SHA512:Ctor", "The LeafLength parameter is invalid! Must be evenly divisible by digest block size.");
				if (Params.ParallelDegree() < 2 || Params.ParallelDegree() % 2 != 0)
					throw CryptoDigestException("SHA512:Ctor", "The ParallelDegree parameter is invalid! Must be an even number greater than 1.");
				if (Params.TreeDepth() > 2)
					throw CryptoDigestException("SHA512:Ctor", "The maximum tree depth is 2; valid range is 0, 1, and 2.");
				if (Params.SubTreeLength() % 2 != 0 || Params.SubTreeLength() < 2 || Params.SubTreeLength() > m_minParallel / BLOCK_SIZE)
					throw CryptoDigestException("SHA512:Ctor", "SubTreeLength must be divisible by two, and no more than minimum parallel divide by block size.");
#endif
				DetectCpu();
				m_treeParams = { (uint8_t)DIGEST_SIZE, 0, (uint8_t)(Params.TreeDepth() == 2 ? 2 : 1), (uint8_t)BLOCK_SIZE, Params.ParallelDegree(), Params.SubTreeLength() };
			}
			else
			{
				m_treeParams = { (uint8_t)DIGEST_SIZE, 0, 0, (uint8_t)BLOCK_SIZE, 0, 0 };
			}

			Initialize(m_State);
		}

		/// <summary>
		/// Finalize objects
		/// </summary>
		virtual ~SHA512()
		{
			Destroy();
		}

		// *** Public methods *** //

		/// <summary>
		/// Update the buffer with a block of bytes
		/// </summary>
		/// 
		/// <param name="Input">The input message array</param>
		/// <param name="InOffset">The starting offset within the Input array</param>
		/// <param name="Length">The number of message bytes to process</param>
		virtual void BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length);

		/// <summary>
		/// Get the hash code for a message input array
		/// </summary>
		/// 
		/// <param name="Input">The input message array</param>
		/// <param name="Output">The hash output code array</param>
		virtual void ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output);

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
		virtual size_t DoFinal(std::vector<byte> &Output, const size_t OutOffset);

		/// <summary>
		/// Generate pseudo random bytes using the digest as with an HKDF Expand bytes generator
		/// </summary>
		/// 
		/// <param name="MacKey">The input key parameters; the input Key should be at least as large as the hash output size</param>
		/// <param name="Output">The array to fill with pseudo random bytes</param>
		/// 
		/// <returns>The number of bytes generated</returns>
		///
		/// <exception cref="CryptoDigestException">Thrown if the maximum number of output bytes is exceeded</exception>
		size_t Generate(MacParams &MacKey, std::vector<uint8_t> &Output);

		/// <summary>
		/// Initialize the digest as a MAC code generator
		/// </summary>
		/// 
		/// <param name="MacKey">The input key parameters; key size should be at least as large as the hash output size</para></param>
		///
		/// <exception cref="CryptoDigestException">Thrown if the Key size is less than the required minimum</exception>
		void LoadMacKey(MacParams &MacKey);

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

	private:
		void DetectCpu();
		void Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output);
		void Expand(const std::vector<byte> &Input, size_t Count, std::vector<byte> &Output);
		void HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<SHA512State> &State, size_t StateOffset);
		void Initialize(std::vector<SHA512State> &State);
		void LoadState(std::vector<SHA512State> &State, size_t StateOffset);
		void MacFinal(std::vector<byte> &Input, const size_t Length, std::vector<SHA512State> &State, size_t StateOffset);
		void ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<SHA512State> &State, size_t StateOffset);
		void ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<SHA512State> &State, size_t StateOffset, uint64_t Length);
		void ResetMac();
		void StateToBytes(std::vector<byte> &Output, const size_t OutOffset, std::vector<SHA512State> &State, size_t StateOffset);
	};
}
#endif
