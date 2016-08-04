#include "DigestSpeedTest.h"
#include "../SHA2/SHA256.h"
#include "../SHA2/SHA512.h"

namespace TestSHA2
{
	void DigestSpeedTest::SHA256Loop(size_t SampleSize, size_t Loops, uint8_t Threads)
	{
		std::vector<uint8_t> hash(32, 0);
		std::vector<uint8_t> buffer(MB10, 0);
		std::vector<uint8_t> key(0, 0);
		const char* name = "SHA256";
		uint64_t start = TestUtils::GetTimeMs64();
		SHA2::SHA2Params params(32, 0, Threads > 0 ? 1 : 0, 64, Threads, 8, 0, 0, 0);
		SHA2::SHA256 dgt(params);

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				dgt.BlockUpdate(buffer, 0, buffer.size());
				counter += buffer.size();
			}

			dgt.DoFinal(hash, 0);
			std::string calc = IntToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(const_cast<char*>(calc.c_str()));
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * SampleSize;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string glen = IntToString(len / GB1);
		std::string mbps = IntToString((rate / MB1));
		std::string secs = IntToString((double)dur / 1000.0);
		std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");

		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	void DigestSpeedTest::SHA512Loop(size_t SampleSize, size_t Loops, uint8_t Threads)
	{
		std::vector<uint8_t> hash(64, 0);
		std::vector<uint8_t> buffer(MB10, 0);
		std::vector<uint8_t> key(0, 0);
		const char* name = "SHA512";
		uint64_t start = TestUtils::GetTimeMs64();
		SHA2::SHA2Params params(64, 0, Threads > 0 ? 1 : 0, 128, Threads, 4, 0, 0, 0);
		SHA2::SHA512 dgt(params);

		for (size_t i = 0; i < Loops; ++i)
		{
			size_t counter = 0;
			uint64_t lstart = TestUtils::GetTimeMs64();

			while (counter < SampleSize)
			{
				dgt.BlockUpdate(buffer, 0, buffer.size());
				counter += buffer.size();
			}

			dgt.DoFinal(hash, 0);
			std::string calc = IntToString((TestUtils::GetTimeMs64() - lstart) / 1000.0);
			OnProgress(const_cast<char*>(calc.c_str()));
		}

		uint64_t dur = TestUtils::GetTimeMs64() - start;
		uint64_t len = Loops * SampleSize;
		uint64_t rate = GetBytesPerSecond(dur, len);
		std::string glen = IntToString(len / GB1);
		std::string mbps = IntToString((rate / MB1));
		std::string secs = IntToString((double)dur / 1000.0);
		std::string resp = std::string(glen + "GB in " + secs + " seconds, avg. " + mbps + " MB per Second");

		OnProgress(const_cast<char*>(resp.c_str()));
		OnProgress("");
	}

	uint64_t DigestSpeedTest::GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize)
	{
		double sec = (double)DurationTicks / 1000.0;
		double sze = (double)DataSize;

		return (uint64_t)(sze / sec);
	}

	void DigestSpeedTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}