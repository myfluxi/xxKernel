/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <pthread.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>
#include <ump/ump_ref_drv.h>

#include "gralloc_priv.h"
#include "alloc_device.h"
#include "framebuffer_device.h"

static pthread_mutex_t s_map_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_ump_is_open = 0;

static int gralloc_device_open(const hw_module_t* module, const char* name, hw_device_t** device)
{
	int status = -EINVAL;

	if (!strcmp(name, GRALLOC_HARDWARE_GPU0))
	{
		status = alloc_device_open(module, name, device);
	}
	else if (!strcmp(name, GRALLOC_HARDWARE_FB0))
	{
		status = framebuffer_device_open(module, name, device);
	}

	return status;
}

static int gralloc_register_buffer(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		LOGE("Registering invalid buffer, returning error");
		return -EINVAL;
	}

	// if this handle was created in this process, then we keep it as is.
	private_handle_t* hnd = (private_handle_t*)handle;
	if (hnd->pid == getpid())
	{
		return 0;
	}

	int retval = -EINVAL;

	pthread_mutex_lock(&s_map_lock);

	if (!s_ump_is_open)
	{
		ump_result res = ump_open();
		if (res != UMP_OK)
		{
			pthread_mutex_unlock(&s_map_lock);
			LOGE("Failed to open UMP library");
			return retval;
		}
		s_ump_is_open = 1;
	}

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
	{
		hnd->ump_mem_handle = (int)ump_handle_create_from_secure_id(hnd->ump_id);
		if (UMP_INVALID_MEMORY_HANDLE != (ump_handle)hnd->ump_mem_handle)
		{
			hnd->base = (int)ump_mapped_pointer_get((ump_handle)hnd->ump_mem_handle);
			if (0 != hnd->base)
			{
				hnd->lockState = private_handle_t::LOCK_STATE_MAPPED;
				hnd->writeOwner = 0;
				hnd->lockState = 0;

				pthread_mutex_unlock(&s_map_lock);
				return 0;
			}
			else
			{
				LOGE("Failed to map UMP handle");
			}

			ump_reference_release((ump_handle)hnd->ump_mem_handle);
		}
		else
		{
			LOGE("Failed to create UMP handle");
		}
	}
	else
	{
		LOGE("registering non-UMP buffer not supported");
	}

	pthread_mutex_unlock(&s_map_lock);
	return retval;
}

static int gralloc_unregister_buffer(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		LOGE("unregistering invalid buffer, returning error");
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	LOGE_IF(hnd->lockState & private_handle_t::LOCK_STATE_READ_MASK, "[unregister] handle %p still locked (state=%08x)", hnd, hnd->lockState);

	// never unmap buffers that were created in this process
	if (hnd->pid != getpid())
	{
		pthread_mutex_lock(&s_map_lock);

		if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
		{
			ump_mapped_pointer_release((ump_handle)hnd->ump_mem_handle);
			hnd->base = 0;
			ump_reference_release((ump_handle)hnd->ump_mem_handle);
			hnd->ump_mem_handle = (int)UMP_INVALID_MEMORY_HANDLE;
		}
		else
		{
			LOGE("unregistering non-UMP buffer not supported");
		}

		hnd->base = 0;
		hnd->lockState  = 0;
		hnd->writeOwner = 0;

		pthread_mutex_unlock(&s_map_lock);
	}

	return 0;
}

static int gralloc_lock(gralloc_module_t const* module, buffer_handle_t handle, int usage, int l, int t, int w, int h, void** vaddr)
{
	if (private_handle_t::validate(handle) < 0)
	{
		LOGE("Locking invalid buffer, returning error");
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
	{
		hnd->writeOwner = usage & GRALLOC_USAGE_SW_WRITE_MASK;
	}

	if (usage & (GRALLOC_USAGE_SW_READ_MASK | GRALLOC_USAGE_SW_WRITE_MASK))
	{
		*vaddr = (void*)hnd->base;
	}
	return 0;
}

static int gralloc_unlock(gralloc_module_t const* module, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		LOGE("Unlocking invalid buffer, returning error");
		return -EINVAL;
	}

	private_handle_t* hnd = (private_handle_t*)handle;
	int32_t current_value;
	int32_t new_value;
	int retry;

	if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP && hnd->writeOwner)
	{
		ump_cpu_msync_now((ump_handle)hnd->ump_mem_handle, UMP_MSYNC_CLEAN_AND_INVALIDATE, NULL, 0);
	}
	return 0;
}

// There is one global instance of the module

static struct hw_module_methods_t gralloc_module_methods =
{
	open: gralloc_device_open
};

struct private_module_t HAL_MODULE_INFO_SYM =
{
	base:
	{
		common:
		{
			tag: HARDWARE_MODULE_TAG,
			version_major: 1,
			version_minor: 0,
			id: GRALLOC_HARDWARE_MODULE_ID,
			name: "Graphics Memory Allocator Module",
			author: "ARM Ltd.",
			methods: &gralloc_module_methods,
			dso: NULL,
			reserved : {0,},
		},
		registerBuffer: gralloc_register_buffer,
		unregisterBuffer: gralloc_unregister_buffer,
		lock: gralloc_lock,
		unlock: gralloc_unlock,
		perform: NULL,
		reserved_proc: {0,},
	},
	framebuffer: NULL,
	flags: 0,
	numBuffers: 0,
	bufferMask: 0,
	lock: PTHREAD_MUTEX_INITIALIZER,
	currentBuffer: NULL,
};
