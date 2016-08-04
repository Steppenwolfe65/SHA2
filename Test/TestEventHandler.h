#ifndef _SHA2TEST_TESTEVENTHANDLER_H
#define _SHA2TEST_TESTEVENTHANDLER_H

#include "TestEvent.h"
#include "ConsoleUtils.h"

namespace TestSHA2
{
	class TestEventHandler : public TestEvent<TestEventHandler>
	{
	public:
		void operator()(const char* Data)
		{
			ConsoleUtils::WriteLine(std::string(Data));
		}
	};
}

#endif