/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include "scap.h"
#include "gvisor.h"
#include <gtest/gtest.h>

TEST(gvisor_runsc, list_create)
{
	char last_err[SCAP_LASTERR_SIZE];
	scap_gvisor::engine engine(last_err);

	engine.runsc_list();
	for(int i = 0; i < engine.m_running_sandboxes.size(); i++)
	{
		std::cout << engine.m_running_sandboxes[i];
	}
	EXPECT_EQ(engine.m_running_sandboxes.size(), 1);

	engine.runsc_trace_create(engine.m_running_sandboxes[0]);
}