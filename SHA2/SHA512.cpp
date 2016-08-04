#include "SHA512.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "SHA512Compress.h"

namespace SHA2
{
	// *** Public methods *** //

	void SHA512::BlockUpdate(const std::vector<byte> &Input, size_t InOffset, size_t Length)
	{
#if defined(_DEBUG)
		assert(Input.size() - InOffset >= Length);
#endif
		if (Length == 0)
			return;

		if (m_isParallel)
		{
			size_t stateOffset = m_State.size() / m_treeParams.ParallelDegree();

			if (m_msgLength != 0 && Length + m_msgLength >= m_msgBuffer.size())
			{
				// fill buffer
				size_t rmd = m_msgBuffer.size() - m_msgLength;
				if (rmd != 0)
					memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

				// empty the message buffer
				ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset, stateOffset](size_t i)
				{
					ProcessBlock(m_msgBuffer, i * ITL_BLKSIZE, m_State, i * stateOffset);
				});

				m_msgLength = 0;
				Length -= rmd;
				InOffset += rmd;
			}

			if (Length >= m_minParallel)
			{
				// calculate working set size
				size_t prcLen = Length - (Length % m_minParallel);

				// process large blocks
				ParallelUtils::ParallelFor(0, m_treeParams.ParallelDegree(), [this, &Input, InOffset, prcLen, stateOffset](size_t i)
				{
					ProcessLeaf(Input, InOffset + (i * ITL_BLKSIZE), m_State, i * stateOffset, prcLen);
				});

				Length -= prcLen;
				InOffset += prcLen;
			}
		}
		else
		{
			if (m_msgLength != 0 && m_msgLength + Length >= BLOCK_SIZE)
			{
				size_t rmd = BLOCK_SIZE - m_msgLength;
				if (rmd != 0)
					memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], rmd);

				ProcessBlock(m_msgBuffer, 0, m_State, 0);
				m_msgLength = 0;
				InOffset += rmd;
				Length -= rmd;
			}

			// loop until last block
			while (Length > BLOCK_SIZE)
			{
				ProcessBlock(Input, InOffset, m_State, 0);
				InOffset += BLOCK_SIZE;
				Length -= BLOCK_SIZE;
			}
		}

		// store unaligned bytes
		if (Length != 0)
		{
			memcpy(&m_msgBuffer[m_msgLength], &Input[InOffset], Length);
			m_msgLength += Length;
		}
	}

	void SHA512::ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output)
	{
		if (Input.size() < m_minParallel)
			m_isParallel = false;

		Output.resize(DIGEST_SIZE);
		BlockUpdate(Input, 0, Input.size());
		DoFinal(Output, 0);
	}

	void SHA512::Destroy()
	{
		if (!m_isDestroyed)
		{
			m_isDestroyed = true;

			for (size_t i = 0; i < m_State.size(); ++i)
				m_State[i].Reset();

			if (m_treeDestroy)
				m_treeParams.Reset();

			m_hasAvx = false;
			m_isHmac = false;
			m_isInitialized = false;
			m_isParallel = false;
			m_leafSize = 0;
			m_minParallel = 0;
			m_msgLength = 0;
			m_parallelBlockSize = 0;
			m_treeDestroy = false;

			IntUtils::ClearVector(m_iPad);
			IntUtils::ClearVector(m_oPad);
			IntUtils::ClearVector(m_msgBuffer);
			IntUtils::ClearVector(m_State);
		}
	}

	size_t SHA512::DoFinal(std::vector<byte> &Output, const size_t OutOffset)
	{
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Output.size() - OutOffset < DigestSize())
			throw CryptoDigestException("SHA512:DoFinal", "The Output buffer is too short!");
#endif

		// rtm: too small for parallel
		if (!m_isHmac && m_isParallel && m_State[0].T[0] == 0)
		{
			m_isParallel = false;
			size_t len = m_msgLength;
			m_msgLength = 0;
			BlockUpdate(m_msgBuffer, 0, len);
		}

		if (m_isParallel && !m_isHmac)
		{
			std::vector<byte> leaf(BLOCK_SIZE);

			//  depth 2: hash into intermediate branch states
			if (m_treeParams.TreeDepth() == 2)
			{
				// create the temp state buffers
				std::vector<SHA512State> branchState(m_State.size() / m_treeParams.SubTreeLength());
				Initialize(branchState);

				// compress the leaves into subtree state hashes
				for (size_t i = 0, j = 0; i < m_State.size(); i += 2)
				{
					// no empty block processing
					if (m_State[i].T[0] != 0)
					{
						// copy state as input message block
						memcpy(&leaf[0], &m_State[i].H[0], DIGEST_SIZE);
						memcpy(&leaf[DIGEST_SIZE], &m_State[i + 1].H[0], DIGEST_SIZE);
						SHA512Compress::Compress128(leaf, 0, branchState, j);

						// finalize at subtree boundary
						if (i != 0 && i % m_treeParams.SubTreeLength() == 0)
						{
							// increment node state counter
							m_treeParams.NodeOffset() += 1;
							memcpy(&leaf[0], &m_treeParams.ToBytes()[0], m_treeParams.GetHeaderSize());
							// process the params as final state
							HashFinal(leaf, 0, m_treeParams.GetHeaderSize(), branchState, j++);
						}
					}
				}

				// compress the subtree hashes into root hash
				for (size_t i = 0; i < branchState.size(); i += 2)
				{
					if (branchState[i].T[0] != 0)
					{
						// copy subtree hashes
						memcpy(&leaf[0], &branchState[i].H[0], DIGEST_SIZE);
						memcpy(&leaf[DIGEST_SIZE], &branchState[i + 1].H[0], DIGEST_SIZE);
						// subtree branch hashes are compressed into root state
						SHA512Compress::Compress128(leaf, 0, m_State, 0);
					}
				}
			}
			else
			{
				// depth 1: process state blocks as contiguous input
				for (size_t i = 0; i < m_State.size(); i += 2)
				{
					// skip empty state
					if (m_State[i].T[0] != 0)
					{
						// copy hashes as input blocks
						memcpy(&leaf[0], &m_State[i].H[0], DIGEST_SIZE);
						memcpy(&leaf[DIGEST_SIZE], &m_State[i + 1].H[0], DIGEST_SIZE);
						// compress into root state
						SHA512Compress::Compress128(leaf, 0, m_State, 0);
					}
				}
			}
		}

		// Note: I considered mac on each state in parallel mode, but I'm not sure I see the benefit.
		// If mac is secure, once on last state should be enough(?) this may change at some point..
		if (m_isHmac)
			MacFinal(m_msgBuffer, m_msgLength, m_State, 0);
		else
			HashFinal(m_msgBuffer, 0, m_msgLength, m_State, 0);

		StateToBytes(Output, OutOffset, m_State, 0);
		Reset();

		return DIGEST_SIZE;
	}

	size_t SHA512::Generate(MacParams &MacKey, std::vector<uint8_t> &Output)
	{
#if defined(_DEBUG)
		assert(Output.size() != 0);
		assert(Output.size() < 255 * DIGEST_SIZE);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (Output.size() > 255 * DIGEST_SIZE)
			throw CryptoDigestException("SHA512:Generate", "Maximum output size is 255 times the digest return size!");
#endif

		size_t prcLen = DIGEST_SIZE;
		std::vector<uint8_t> state(DIGEST_SIZE);
		std::vector<byte> prk;

		Extract(MacKey.Key(), MacKey.Salt(), prk);
		LoadMacKey(MacParams(prk));
		Expand(MacKey.Info(), 0, state);

		if (prcLen < Output.size())
		{
			memcpy(&Output[0], &state[0], DIGEST_SIZE);
			int32_t rmd = (int32_t)(Output.size() - prcLen);

			while (rmd > 0)
			{
				Expand(MacKey.Info(), prcLen, state);

				if (rmd > (int32_t)DIGEST_SIZE)
				{
					memcpy(&Output[prcLen], &state[0], DIGEST_SIZE);
					prcLen += DIGEST_SIZE;
					rmd -= (int32_t)DIGEST_SIZE;
				}
				else
				{
					rmd = (int32_t)(Output.size() - prcLen);
					memcpy(&Output[prcLen], &state[0], rmd);
					rmd = 0;
				}
			}
		}
		else
		{
			memcpy(&Output[0], &state[0], Output.size());
		}

		Reset();
		m_isHmac = false;

		return Output.size();
	}

	void SHA512::LoadMacKey(MacParams &MacKey)
	{
#if defined(_DEBUG)
		assert(MacKey.Key().size() > 3);
#endif
#if defined(CPPEXCEPTIONS_ENABLED)
		if (MacKey.Key().size() < 4)
			throw CryptoDigestException("SHA512:LoadMacKey", "The minimum key size is 4 bytes, key length equal to digest output size is recommended!");
#endif

		m_isHmac = true;
		m_treeParams.KeyLength() = MacKey.Key().size();
		Reset();

		size_t klen = MacKey.Key().size() + MacKey.Salt().size() + MacKey.Info().size();
		std::vector<byte> key(klen, 0);
		memcpy(&key[0], &MacKey.Key()[0], MacKey.Key().size());

		if (MacKey.Salt().size() != 0)
			memcpy(&key[MacKey.Key().size()], &MacKey.Salt()[0], MacKey.Salt().size());
		if (MacKey.Info().size() != 0)
			memcpy(&key[MacKey.Key().size() + MacKey.Salt().size()], &MacKey.Info()[0], MacKey.Info().size());

		if (m_iPad.size() != BLOCK_SIZE)
			m_iPad.resize(BLOCK_SIZE, 0x36);
		else
			memset(&m_iPad[0], (byte)0x36, m_iPad.size());

		if (m_oPad.size() != BLOCK_SIZE)
			m_oPad.resize(BLOCK_SIZE, 0x5C);
		else
			memset(&m_oPad[0], (byte)0x5C, m_oPad.size());

		if (klen > BLOCK_SIZE)
		{
			BlockUpdate(key, 0, key.size());
			key.resize(DIGEST_SIZE);
			HashFinal(m_msgBuffer, 0, m_msgLength, m_State, 0);
			StateToBytes(key, 0, m_State, 0);
			Reset();
		}

		for (size_t i = 0; i < key.size(); ++i)
			m_iPad[i] ^= key[i];
		for (size_t i = 0; i < key.size(); ++i)
			m_oPad[i] ^= key[i];

		ResetMac();
	}

	void SHA512::Reset()
	{
		m_msgLength = 0;
		memset(&m_msgBuffer[0], 0, m_msgBuffer.size());
		Initialize(m_State);
	}

	void SHA512::Update(byte Input)
	{
		std::vector<uint8_t> inp(1, Input);
		BlockUpdate(inp, 0, 1);
	}

	// *** Private methods *** //

	void SHA512::DetectCpu()
	{
		CpuDetect detect;
		m_hasAvx = detect.HasAVX();
	}

	void SHA512::Extract(const std::vector<byte> &Key, const std::vector<byte> &Salt, std::vector<byte> &Output)
	{
		if (Output.size() != DIGEST_SIZE)
			Output.resize(DIGEST_SIZE);

		LoadMacKey(MacParams(Key));

		if (Salt.size() == 0)
		{
			std::vector<byte> zeros(DIGEST_SIZE, 0);
			LoadMacKey(MacParams(zeros));
		}
		else
		{
			LoadMacKey(MacParams(Salt));
		}

		BlockUpdate(Key, 0, Key.size());
		DoFinal(Output, 0);
		ResetMac();
	}

	void SHA512::Expand(const std::vector<byte> &Input, size_t Count, std::vector<byte> &Output)
	{
		const size_t N = Count / DIGEST_SIZE + 1;

		if (Count != 0)
			BlockUpdate(Output, 0, DIGEST_SIZE);
		if (Input.size() > 0)
			BlockUpdate(Input, 0, Input.size());

		Update((byte)N);
		DoFinal(Output, 0);
		ResetMac();
	}

	void SHA512::HashFinal(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<SHA512State> &State, size_t StateOffset)
	{
		State[StateOffset].Increase(Length);
		ulong bitLen = (State[StateOffset].T[0] << 3);

		if (Length == BLOCK_SIZE)
		{
			SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
			Length = 0;
		}

		Input[InOffset + Length] = (byte)128;
		++Length;

		// padding
		if (Length < BLOCK_SIZE)
			memset(&Input[InOffset + Length], 0, BLOCK_SIZE - Length);

		if (Length > 112)
		{
			SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
			memset(&Input[InOffset], 0, BLOCK_SIZE);
		}

		// finalize state with counter and last compression
		IntUtils::Be64ToBytes(State[StateOffset].T[1], Input, InOffset + 112);
		IntUtils::Be64ToBytes(bitLen, Input, InOffset + 120);
		SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
	}

	void SHA512::Initialize(std::vector<SHA512State> &State)
	{
		LoadState(State, 0);

		if (State.size() > 1)
		{
			for (size_t i = 0; i < State.size(); ++i)
			{
				memcpy(&State[i].H[0], &State[0].H[0], State[0].H.size() * sizeof(ulong));
				State[i].T[0] = 0;
				State[i].T[1] = 0;
			}
		}

		m_isInitialized = true;
	}

	void SHA512::LoadState(std::vector<SHA512State> &State, size_t StateOffset)
	{
		State[StateOffset].T[0] = 0;
		State[StateOffset].T[1] = 0;
		State[StateOffset].H[0] = 0x6a09e667f3bcc908;
		State[StateOffset].H[1] = 0xbb67ae8584caa73b;
		State[StateOffset].H[2] = 0x3c6ef372fe94f82b;
		State[StateOffset].H[3] = 0xa54ff53a5f1d36f1;
		State[StateOffset].H[4] = 0x510e527fade682d1;
		State[StateOffset].H[5] = 0x9b05688c2b3e6c1f;
		State[StateOffset].H[6] = 0x1f83d9abfb41bd6b;
		State[StateOffset].H[7] = 0x5be0cd19137e2179;
	}

	void SHA512::MacFinal(std::vector<byte> &Input, const size_t Length, std::vector<SHA512State> &State, size_t StateOffset)
	{
		HashFinal(Input, 0, Length, State, StateOffset);
		StateToBytes(Input, 0, State, StateOffset);
		LoadState(State, StateOffset);
		SHA512Compress::Compress128(m_oPad, 0, State, StateOffset);
		HashFinal(Input, 0, DIGEST_SIZE, State, StateOffset);
	}

	void SHA512::ProcessBlock(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<SHA512State> &State, size_t StateOffset)
	{
		if (m_isParallel)
		{
			// 4 lanes in reverse order for future simd compatability
			SHA512Compress::Compress128(Input, InOffset, State, StateOffset + 3);
			SHA512Compress::Compress128(Input, InOffset + BLOCK_SIZE, State, StateOffset + 2);
			SHA512Compress::Compress128(Input, InOffset + BLOCK_SIZE * 2, State, StateOffset + 1);
			SHA512Compress::Compress128(Input, InOffset + BLOCK_SIZE * 3, State, StateOffset);
		}
		else
		{
			SHA512Compress::Compress128(Input, InOffset, State, StateOffset);
		}
	}

	void SHA512::ProcessLeaf(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<SHA512State> &State, size_t StateOffset, uint64_t Length)
	{
		do
		{
			ProcessBlock(Input, InOffset, State, StateOffset);
			InOffset += m_minParallel;
			Length -= m_minParallel;
		} while (Length > 0);
	}

	void SHA512::ResetMac()
	{
		LoadState(m_State, 0);
		SHA512Compress::Compress128(m_iPad, 0, m_State, 0);
	}

	void SHA512::StateToBytes(std::vector<byte> &Output, const size_t OutOffset, std::vector<SHA512State> &State, size_t StateOffset)
	{
#if defined(IS_BIG_ENDIAN)
		memcpy(&Output[OutOffset], &State[StateOffset].H[0], State[StateOffset].H.size() * sizeof(ulong));
#else
		IntUtils::Be64ToBytes(m_State[StateOffset].H[0], Output, OutOffset);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[1], Output, OutOffset + 8);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[2], Output, OutOffset + 16);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[3], Output, OutOffset + 24);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[4], Output, OutOffset + 32);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[5], Output, OutOffset + 40);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[6], Output, OutOffset + 48);
		IntUtils::Be64ToBytes(m_State[StateOffset].H[7], Output, OutOffset + 56);
#endif
	}
}