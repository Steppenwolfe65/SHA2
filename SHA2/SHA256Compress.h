#include "IntUtils.h"

#if defined(HAS_AVX)
#	include "UInt256.h"
#endif

namespace SHA2
{
	class SHA256Compress
	{
	private:
		static constexpr uint K32[] =
		{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};

		static constexpr size_t BLOCK_SIZE = 64;

		template <typename T>
		static inline T BigSigma0(T &W)
		{
			return ((W >> 2) | (W << 30)) ^ ((W >> 13) | (W << 19)) ^ ((W >> 22) | (W << 10));
		}

		template <typename T>
		static inline T BigSigma1(T &W)
		{
			return ((W >> 6) | (W << 26)) ^ ((W >> 11) | (W << 21)) ^ ((W >> 25) | (W << 7));
		}

		template <typename T>
		static inline T Ch(T &B, T &C, T &D)
		{
			return (B & C) ^ (~B & D);
		}

		template <typename T>
		static inline T Maj(T &B, T &C, T &D)
		{
			return (B & C) ^ (B & D) ^ (C & D);
		}

		template <typename T>
		static inline T Sigma0(T &W)
		{
			return ((W >> 7) | (W << 25)) ^ ((W >> 18) | (W << 14)) ^ (W >> 3);
		}

		template <typename T>
		static inline T Sigma1(T &W)
		{
			return ((W >> 17) | (W << 15)) ^ ((W >> 19) | (W << 13)) ^ (W >> 10);
		}

		template <typename T>
		static inline void SHA256Round(T &A, T &B, T &C, T &D, T &E, T &F, T &G, T &H, T &M, size_t Index)
		{
			T R0(H + BigSigma1(E) + Ch(E, F, G) + T(K32[Index]) + M);
			D += R0;
			T R1(BigSigma0(A) + Maj(A, B, C));
			H = R0 + R1;
		}

		template <typename T, typename R>
		static inline void ShuffleLoad32(std::vector<T> &Input, size_t InOffset, size_t Index, R &W)
		{
			W.LoadLE(
				Input[InOffset].H[Index], 
				Input[InOffset + 1].H[Index], 
				Input[InOffset + 2].H[Index], 
				Input[InOffset + 3].H[Index],
				Input[InOffset + 4].H[Index],
				Input[InOffset + 5].H[Index],
				Input[InOffset + 6].H[Index],
				Input[InOffset + 7].H[Index]
			);
		}

		template <typename T, typename R>
		static inline void ShuffleStore32(R &W, std::vector<T> &Output, size_t OutOffset, size_t Index)
		{
			std::vector<uint> tmp(8);
			W.StoreLE(tmp, 0);

			Output[OutOffset].H[Index] = tmp[0];
			Output[OutOffset + 1].H[Index] = tmp[1];
			Output[OutOffset + 2].H[Index] = tmp[2];
			Output[OutOffset + 3].H[Index] = tmp[3];
			Output[OutOffset + 4].H[Index] = tmp[4];
			Output[OutOffset + 5].H[Index] = tmp[5];
			Output[OutOffset + 6].H[Index] = tmp[6];
			Output[OutOffset + 7].H[Index] = tmp[7];
		}

	public:

		template <typename T>
		static inline void Compress64(const std::vector<byte> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
		{
			uint A = Output[OutOffset].H[0];
			uint B = Output[OutOffset].H[1];
			uint C = Output[OutOffset].H[2];
			uint D = Output[OutOffset].H[3];
			uint E = Output[OutOffset].H[4];
			uint F = Output[OutOffset].H[5];
			uint G = Output[OutOffset].H[6];
			uint H = Output[OutOffset].H[7];
			uint W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

			W0 = IntUtils::BytesToBe32(Input, InOffset);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 0);
			W1 = IntUtils::BytesToBe32(Input, InOffset + 4);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 1);
			W2 = IntUtils::BytesToBe32(Input, InOffset + 8);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 2);
			W3 = IntUtils::BytesToBe32(Input, InOffset + 12);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 3);
			W4 = IntUtils::BytesToBe32(Input, InOffset + 16);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 4);
			W5 = IntUtils::BytesToBe32(Input, InOffset + 20);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 5);
			W6 = IntUtils::BytesToBe32(Input, InOffset + 24);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 6);
			W7 = IntUtils::BytesToBe32(Input, InOffset + 28);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 7);
			W8 = IntUtils::BytesToBe32(Input, InOffset + 32);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 8);
			W9 = IntUtils::BytesToBe32(Input, InOffset + 36);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 9);
			W10 = IntUtils::BytesToBe32(Input, InOffset + 40);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 10);
			W11 = IntUtils::BytesToBe32(Input, InOffset + 44);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 11);
			W12 = IntUtils::BytesToBe32(Input, InOffset + 48);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 12);
			W13 = IntUtils::BytesToBe32(Input, InOffset + 52);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 13);
			W14 = IntUtils::BytesToBe32(Input, InOffset + 56);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 14);
			W15 = IntUtils::BytesToBe32(Input, InOffset + 60);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 15);

			W0 += Sigma1(W14) + W9 + Sigma0(W1);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 16);
			W1 += Sigma1(W15) + W10 + Sigma0(W2);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 17);
			W2 += Sigma1(W0) + W11 + Sigma0(W3);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 18);
			W3 += Sigma1(W1) + W12 + Sigma0(W4);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 19);
			W4 += Sigma1(W2) + W13 + Sigma0(W5);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 20);
			W5 += Sigma1(W3) + W14 + Sigma0(W6);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 21);
			W6 += Sigma1(W4) + W15 + Sigma0(W7);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 22);
			W7 += Sigma1(W5) + W0 + Sigma0(W8);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 23);
			W8 += Sigma1(W6) + W1 + Sigma0(W9);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 24);
			W9 += Sigma1(W7) + W2 + Sigma0(W10);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 25);
			W10 += Sigma1(W8) + W3 + Sigma0(W11);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 26);
			W11 += Sigma1(W9) + W4 + Sigma0(W12);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 27);
			W12 += Sigma1(W10) + W5 + Sigma0(W13);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 28);
			W13 += Sigma1(W11) + W6 + Sigma0(W14);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 29);
			W14 += Sigma1(W12) + W7 + Sigma0(W15);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 30);
			W15 += Sigma1(W13) + W8 + Sigma0(W0);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 31);

			W0 += Sigma1(W14) + W9 + Sigma0(W1);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 32);
			W1 += Sigma1(W15) + W10 + Sigma0(W2);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 33);
			W2 += Sigma1(W0) + W11 + Sigma0(W3);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 34);
			W3 += Sigma1(W1) + W12 + Sigma0(W4);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 35);
			W4 += Sigma1(W2) + W13 + Sigma0(W5);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 36);
			W5 += Sigma1(W3) + W14 + Sigma0(W6);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 37);
			W6 += Sigma1(W4) + W15 + Sigma0(W7);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 38);
			W7 += Sigma1(W5) + W0 + Sigma0(W8);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 39);
			W8 += Sigma1(W6) + W1 + Sigma0(W9);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 40);
			W9 += Sigma1(W7) + W2 + Sigma0(W10);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 41);
			W10 += Sigma1(W8) + W3 + Sigma0(W11);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 42);
			W11 += Sigma1(W9) + W4 + Sigma0(W12);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 43);
			W12 += Sigma1(W10) + W5 + Sigma0(W13);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 44);
			W13 += Sigma1(W11) + W6 + Sigma0(W14);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 45);
			W14 += Sigma1(W12) + W7 + Sigma0(W15);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 46);
			W15 += Sigma1(W13) + W8 + Sigma0(W0);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 47);

			W0 += Sigma1(W14) + W9 + Sigma0(W1);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 48);
			W1 += Sigma1(W15) + W10 + Sigma0(W2);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 49);
			W2 += Sigma1(W0) + W11 + Sigma0(W3);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 50);
			W3 += Sigma1(W1) + W12 + Sigma0(W4);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 51);
			W4 += Sigma1(W2) + W13 + Sigma0(W5);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 52);
			W5 += Sigma1(W3) + W14 + Sigma0(W6);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 53);
			W6 += Sigma1(W4) + W15 + Sigma0(W7);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 54);
			W7 += Sigma1(W5) + W0 + Sigma0(W8);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 55);
			W8 += Sigma1(W6) + W1 + Sigma0(W9);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 56);
			W9 += Sigma1(W7) + W2 + Sigma0(W10);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 57);
			W10 += Sigma1(W8) + W3 + Sigma0(W11);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 58);
			W11 += Sigma1(W9) + W4 + Sigma0(W12);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 59);
			W12 += Sigma1(W10) + W5 + Sigma0(W13);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 60);
			W13 += Sigma1(W11) + W6 + Sigma0(W14);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 61);
			W14 += Sigma1(W12) + W7 + Sigma0(W15);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 62);
			W15 += Sigma1(W13) + W8 + Sigma0(W0);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 63);

			Output[OutOffset].H[0] += A;
			Output[OutOffset].H[1] += B;
			Output[OutOffset].H[2] += C;
			Output[OutOffset].H[3] += D;
			Output[OutOffset].H[4] += E;
			Output[OutOffset].H[5] += F;
			Output[OutOffset].H[6] += G;
			Output[OutOffset].H[7] += H;

			Output[OutOffset].T += BLOCK_SIZE;
		}

		template <typename T>
		static inline void Compress512(const std::vector<byte> &Input, size_t InOffset, std::vector<T> &Output, size_t OutOffset)
		{
#if defined(HAS_AVX)

			UInt256 A, B, C, D, E, F, G, H;
			ShuffleLoad32(Output, OutOffset, 0, A);
			ShuffleLoad32(Output, OutOffset, 1, B);
			ShuffleLoad32(Output, OutOffset, 2, C);
			ShuffleLoad32(Output, OutOffset, 3, D);
			ShuffleLoad32(Output, OutOffset, 4, E);
			ShuffleLoad32(Output, OutOffset, 5, F);
			ShuffleLoad32(Output, OutOffset, 6, G);
			ShuffleLoad32(Output, OutOffset, 7, H);

			UInt256 H0 = A, H1 = B, H2 = C, H3 = D, H4 = E, H5 = F, H6 = G, H7 = H;
			UInt256 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;

			W0 = UInt256::ShuffleLoadBE(Input, InOffset, 64);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 0);
			W1 = UInt256::ShuffleLoadBE(Input, InOffset + 4, 64);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 1);
			W2 = UInt256::ShuffleLoadBE(Input, InOffset + 8, 64);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 2);
			W3 = UInt256::ShuffleLoadBE(Input, InOffset + 12, 64);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 3);
			W4 = UInt256::ShuffleLoadBE(Input, InOffset + 16, 64);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 4);
			W5 = UInt256::ShuffleLoadBE(Input, InOffset + 20, 64);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 5);
			W6 = UInt256::ShuffleLoadBE(Input, InOffset + 24, 64);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 6);
			W7 = UInt256::ShuffleLoadBE(Input, InOffset + 28, 64);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 7);
			W8 = UInt256::ShuffleLoadBE(Input, InOffset + 32, 64);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 8);
			W9 = UInt256::ShuffleLoadBE(Input, InOffset + 36, 64);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 9);
			W10 = UInt256::ShuffleLoadBE(Input, InOffset + 40, 64);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 10);
			W11 = UInt256::ShuffleLoadBE(Input, InOffset + 44, 64);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 11);
			W12 = UInt256::ShuffleLoadBE(Input, InOffset + 48, 64);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 12);
			W13 = UInt256::ShuffleLoadBE(Input, InOffset + 52, 64);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 13);
			W14 = UInt256::ShuffleLoadBE(Input, InOffset + 56, 64);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 14);
			W15 = UInt256::ShuffleLoadBE(Input, InOffset + 60, 64);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 15);

			W0 += Sigma1(W14) + W9 + Sigma0(W1);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 16);
			W1 += Sigma1(W15) + W10 + Sigma0(W2);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 17);
			W2 += Sigma1(W0) + W11 + Sigma0(W3);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 18);
			W3 += Sigma1(W1) + W12 + Sigma0(W4);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 19);
			W4 += Sigma1(W2) + W13 + Sigma0(W5);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 20);
			W5 += Sigma1(W3) + W14 + Sigma0(W6);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 21);
			W6 += Sigma1(W4) + W15 + Sigma0(W7);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 22);
			W7 += Sigma1(W5) + W0 + Sigma0(W8);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 23);
			W8 += Sigma1(W6) + W1 + Sigma0(W9);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 24);
			W9 += Sigma1(W7) + W2 + Sigma0(W10);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 25);
			W10 += Sigma1(W8) + W3 + Sigma0(W11);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 26);
			W11 += Sigma1(W9) + W4 + Sigma0(W12);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 27);
			W12 += Sigma1(W10) + W5 + Sigma0(W13);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 28);
			W13 += Sigma1(W11) + W6 + Sigma0(W14);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 29);
			W14 += Sigma1(W12) + W7 + Sigma0(W15);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 30);
			W15 += Sigma1(W13) + W8 + Sigma0(W0);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 31);

			W0 += Sigma1(W14) + W9 + Sigma0(W1);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 32);
			W1 += Sigma1(W15) + W10 + Sigma0(W2);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 33);
			W2 += Sigma1(W0) + W11 + Sigma0(W3);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 34);
			W3 += Sigma1(W1) + W12 + Sigma0(W4);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 35);
			W4 += Sigma1(W2) + W13 + Sigma0(W5);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 36);
			W5 += Sigma1(W3) + W14 + Sigma0(W6);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 37);
			W6 += Sigma1(W4) + W15 + Sigma0(W7);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 38);
			W7 += Sigma1(W5) + W0 + Sigma0(W8);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 39);
			W8 += Sigma1(W6) + W1 + Sigma0(W9);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 40);
			W9 += Sigma1(W7) + W2 + Sigma0(W10);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 41);
			W10 += Sigma1(W8) + W3 + Sigma0(W11);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 42);
			W11 += Sigma1(W9) + W4 + Sigma0(W12);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 43);
			W12 += Sigma1(W10) + W5 + Sigma0(W13);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 44);
			W13 += Sigma1(W11) + W6 + Sigma0(W14);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 45);
			W14 += Sigma1(W12) + W7 + Sigma0(W15);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 46);
			W15 += Sigma1(W13) + W8 + Sigma0(W0);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 47);

			W0 += Sigma1(W14) + W9 + Sigma0(W1);
			SHA256Round(A, B, C, D, E, F, G, H, W0, 48);
			W1 += Sigma1(W15) + W10 + Sigma0(W2);
			SHA256Round(H, A, B, C, D, E, F, G, W1, 49);
			W2 += Sigma1(W0) + W11 + Sigma0(W3);
			SHA256Round(G, H, A, B, C, D, E, F, W2, 50);
			W3 += Sigma1(W1) + W12 + Sigma0(W4);
			SHA256Round(F, G, H, A, B, C, D, E, W3, 51);
			W4 += Sigma1(W2) + W13 + Sigma0(W5);
			SHA256Round(E, F, G, H, A, B, C, D, W4, 52);
			W5 += Sigma1(W3) + W14 + Sigma0(W6);
			SHA256Round(D, E, F, G, H, A, B, C, W5, 53);
			W6 += Sigma1(W4) + W15 + Sigma0(W7);
			SHA256Round(C, D, E, F, G, H, A, B, W6, 54);
			W7 += Sigma1(W5) + W0 + Sigma0(W8);
			SHA256Round(B, C, D, E, F, G, H, A, W7, 55);
			W8 += Sigma1(W6) + W1 + Sigma0(W9);
			SHA256Round(A, B, C, D, E, F, G, H, W8, 56);
			W9 += Sigma1(W7) + W2 + Sigma0(W10);
			SHA256Round(H, A, B, C, D, E, F, G, W9, 57);
			W10 += Sigma1(W8) + W3 + Sigma0(W11);
			SHA256Round(G, H, A, B, C, D, E, F, W10, 58);
			W11 += Sigma1(W9) + W4 + Sigma0(W12);
			SHA256Round(F, G, H, A, B, C, D, E, W11, 59);
			W12 += Sigma1(W10) + W5 + Sigma0(W13);
			SHA256Round(E, F, G, H, A, B, C, D, W12, 60);
			W13 += Sigma1(W11) + W6 + Sigma0(W14);
			SHA256Round(D, E, F, G, H, A, B, C, W13, 61);
			W14 += Sigma1(W12) + W7 + Sigma0(W15);
			SHA256Round(C, D, E, F, G, H, A, B, W14, 62);
			W15 += Sigma1(W13) + W8 + Sigma0(W0);
			SHA256Round(B, C, D, E, F, G, H, A, W15, 63);

			A += H0;
			B += H1;
			C += H2;
			D += H3;
			E += H4;
			F += H5;
			G += H6;
			H += H7;

			ShuffleStore32(A, Output, OutOffset, 0);
			ShuffleStore32(B, Output, OutOffset, 1);
			ShuffleStore32(C, Output, OutOffset, 2);
			ShuffleStore32(D, Output, OutOffset, 3);
			ShuffleStore32(E, Output, OutOffset, 4);
			ShuffleStore32(F, Output, OutOffset, 5);
			ShuffleStore32(G, Output, OutOffset, 6);
			ShuffleStore32(H, Output, OutOffset, 7);

			Output[OutOffset].T += BLOCK_SIZE;
			Output[OutOffset + 1].T += BLOCK_SIZE;
			Output[OutOffset + 2].T += BLOCK_SIZE;
			Output[OutOffset + 3].T += BLOCK_SIZE;
			Output[OutOffset + 4].T += BLOCK_SIZE;
			Output[OutOffset + 5].T += BLOCK_SIZE;
			Output[OutOffset + 6].T += BLOCK_SIZE;
			Output[OutOffset + 7].T += BLOCK_SIZE;

#else

			Compress64(Input, InOffset, Output, OutOffset);
			Compress64(Input, InOffset + 64, Output, OutOffset + 1);
			Compress64(Input, InOffset + 128, Output, OutOffset + 2);
			Compress64(Input, InOffset + 192, Output, OutOffset + 3);
			Compress64(Input, InOffset + 256, Output, OutOffset + 4);
			Compress64(Input, InOffset + 320, Output, OutOffset + 5);
			Compress64(Input, InOffset + 384, Output, OutOffset + 6);
			Compress64(Input, InOffset + 448, Output, OutOffset + 7);

#endif
		}
	};
}