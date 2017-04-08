#ifndef _CEXTEST_TESTUTILS_H
#define _CEXTEST_TESTUTILS_H

#include "../SHA2/CexDomain.h"

namespace Test
{
	class TestUtils
	{
	public:

		static void CopyVector(const std::vector<int> &SrcArray, size_t SrcIndex, std::vector<int> &DstArray, size_t DstIndex, size_t Length);
		static bool IsEqual(std::vector<byte> &A, std::vector<byte> &B);
		static uint64_t GetTimeMs64();
		static void GetRandom(std::vector<byte> &Data);
		static bool Read(const std::string &FilePath, std::string &Contents);
		static std::vector<byte> Reduce(std::vector<byte> Seed);
		static void Reverse(std::vector<byte> &Data);
	};
}
#endif
