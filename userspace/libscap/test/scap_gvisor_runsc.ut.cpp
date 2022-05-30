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

#include "engine/gvisor/runsc.h"
#include <gtest/gtest.h>

TEST(gvisor_runsc, start_tracing)
{
	runsc_manager manager(
		"/var/run/docker/runtime-runc/moby",
		"/home/ubuntu/falcosecurity/libs/userspace/libscap/engine/gvisor/config.json"
	);

	manager.start_trace_session();
}