#ifndef _BLAKE2TEST_DIGESTSPEEDTEST_H
#define _BLAKE2TEST_DIGESTSPEEDTEST_H

#include "ITest.h"
#include <sstream>

namespace TestSHA2
{
	/// <summary>
	/// Blake2 Digest Speed Tests
	/// </summary>
	class DigestSpeedTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "Digest Speed Tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string MESSAGE = "COMPLETE! Speed tests have executed succesfully.";
		static constexpr uint64_t KB1 = 1000;
		static constexpr uint64_t MB1 = KB1 * 1000;
		static constexpr uint64_t MB10 = MB1 * 10;
		static constexpr uint64_t MB100 = MB1 * 100;
		static constexpr uint64_t GB1 = MB1 * 1000;
		static constexpr uint64_t GB10 = GB1 * 10;
		static constexpr uint64_t DEFITER = 10;

		int m_testCycle;
		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// Test Blake2 for performance
		/// </summary>
		///
		/// <param name="TestCycle">The type of speed test to run; standard(0), long(1), or extended parallel degree (4 or greater, must be divisible by 4)</param>
		DigestSpeedTest(int TestCycle = 0)
			:
			m_testCycle(TestCycle)
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				if (m_testCycle == 0)
				{
					OnProgress("*** TEST PARAMETERS ***");
					OnProgress("Measures performance using the Parallelized Tree Hashing configuration.");
					OnProgress("Parallel Degree is set to the default of 4 threads.");
					OnProgress("Speed is measured in MegaBytes (1,000,000 bytes) per Second, with a sample size of 1 GB.");
					OnProgress("Block update sizes are fixed at 10MB * 100 iterations per 1GB loop cycle.");
					OnProgress("10 * 1GB loops are run and added for the combined average over 10 GigaByte of data.");
					OnProgress("");
					OnProgress("### CEX C++ SHA2-256 Message Digest: 10 loops * 1000 MB ###");
					SHA256Loop(GB1, 10, 4);
					OnProgress("### CEX C++ SHA2-512 Message Digest: 10 loops * 1000 MB ###");
					SHA512Loop(GB1, 10, 4);
				}
				else if (m_testCycle == 1)
				{
					OnProgress("*** TEST PARAMETERS ***");
					OnProgress("Measures performance using the Parallelized Tree Hashing configuration.");
					OnProgress("Parallel Degree is set to 8 threads.");
					OnProgress("Speed is measured in MegaBytes (1,000,000 bytes) per Second, with a sample size of 1 GB.");
					OnProgress("Block update sizes are fixed at 10MB * 100 iterations per 1GB loop cycle.");
					OnProgress("10 * 1GB loops are run and added for the combined average over 10 GigaByte of data.");
					OnProgress("");
					OnProgress("### CEX C++ SHA2-256 Message Digest: 10 loops * 1000 MB ###");
					SHA256Loop(GB1, 10, 8);
					OnProgress("### CEX C++ SHA2-512 Message Digest: 10 loops * 1000 MB ###");
					SHA512Loop(GB1, 10, 8);

				}
				else
				{
					OnProgress("*** TEST PARAMETERS ***");
					OnProgress("Measures performance using the sequential mode standard configuration.");
					OnProgress("Parallel Degree is set to 1 thread.");
					OnProgress("Speed is measured in MegaBytes (1,000,000 bytes) per Second, with a sample size of 1 GB.");
					OnProgress("Block update sizes are fixed at 10MB * 100 iterations per 1GB loop cycle.");
					OnProgress("10 * 1GB loops are run and added for the combined average over 10 GigaByte of data.");
					OnProgress("");
					OnProgress("### CEX C++ SHA2-256 Message Digest: 10 loops * 1000 MB ###");
					SHA256Loop(GB1, 10);
					OnProgress("### CEX C++ SHA2-512 Message Digest: 10 loops * 1000 MB ###");
					SHA512Loop(GB1, 10);
				}

				return MESSAGE;
			}
			catch (std::string &ex)
			{
				return FAILURE + " : " + ex;
			}
			catch (...)
			{
				return FAILURE + " : Internal Error";
			}
		}

	private:
		void SHA256Loop(size_t SampleSize, size_t Loops = DEFITER, uint8_t Threads = 1);
		void SHA512Loop(size_t SampleSize, size_t Loops = DEFITER, uint8_t Threads = 1);
		uint64_t GetBytesPerSecond(uint64_t DurationTicks, uint64_t DataSize);
		void OnProgress(char* Data);

		template<typename T>
		static inline std::string IntToString(const T& Value)
		{
			std::ostringstream oss;
			oss << Value;
			return oss.str();
		}
	};
}

#endif