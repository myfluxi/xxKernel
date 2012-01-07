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

#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <cutils/log.h>
#include <cutils/atomic.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>

#include "alloc_device.h"
#include "gralloc_priv.h"
#include "gralloc_helper.h"
#include "framebuffer_device.h"

#include <ump/ump.h>
#include <ump/ump_ref_drv.h>



static int gralloc_alloc_buffer(alloc_device_t* dev, size_t size, int usage, buffer_handle_t* pHandle)
{
	ump_handle ump_mem_handle;
	void *cpu_ptr;
	ump_secure_id ump_id;
	ump_alloc_constraints constraints;

	size = round_up_to_page_size(size);

	if( (usage&GRALLOC_USAGE_SW_READ_MASK) == GRALLOC_USAGE_SW_READ_OFTEN )
	{
		constraints =  UMP_REF_DRV_CONSTRAINT_USE_CACHE;
	}
	else
	{
		constraints = UMP_REF_DRV_CONSTRAINT_NONE;
	}

	ump_mem_handle = ump_ref_drv_allocate(size, constraints);
	if (UMP_INVALID_MEMORY_HANDLE != ump_mem_handle)
	{
		cpu_ptr = ump_mapped_pointer_get(ump_mem_handle);
		if (NULL != cpu_ptr)
		{
			ump_id = ump_secure_id_get(ump_mem_handle);
			if (UMP_INVALID_SECURE_ID != ump_id)
			{
				private_handle_t* hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_USES_UMP, size, (int)cpu_ptr,
				                                             private_handle_t::LOCK_STATE_MAPPED, ump_id, ump_mem_handle);
				if (NULL != hnd)
				{
					*pHandle = hnd;
					return 0;
				}
				else
				{
					LOGE("gralloc_alloc_buffer() failed to allocate handle");
				}
			}
			else
			{
				LOGE("gralloc_alloc_buffer() failed to retrieve valid secure id");
			}

			ump_mapped_pointer_release(ump_mem_handle);
		}
		else
		{
			LOGE("gralloc_alloc_buffer() failed to map UMP memory");
		}

		ump_reference_release(ump_mem_handle);
	}
	else
	{
		LOGE("gralloc_alloc_buffer() failed to allcoate UMP memory");
	}

	return -1;
}

static int gralloc_alloc_framebuffer_locked(alloc_device_t* dev, size_t size, int usage, buffer_handle_t* pHandle)
{
	private_module_t* m = reinterpret_cast<private_module_t*>(dev->common.module);

	// allocate the framebuffer
	if (m->framebuffer == NULL)
	{
		// initialize the framebuffer, the framebuffer is mapped once and forever.
		int err = init_frame_buffer_locked(m);
		if (err < 0)
		{
			return err;
		}
	}

	const uint32_t bufferMask = m->bufferMask;
	const uint32_t numBuffers = m->numBuffers;
	const size_t bufferSize = m->finfo.line_length * m->info.yres;
	if (numBuffers == 1)
	{
		// If we have only one buffer, we never use page-flipping. Instead,
		// we return a regular buffer which will be memcpy'ed to the main
		// screen when post is called.
		int newUsage = (usage & ~GRALLOC_USAGE_HW_FB) | GRALLOC_USAGE_HW_2D;
		LOGE("fallback to single buffering");
		return gralloc_alloc_buffer(dev, bufferSize, newUsage, pHandle);
	}

	if (bufferMask >= ((1LU<<numBuffers)-1))
	{
		// We ran out of buffers.
		return -ENOMEM;
	}

	int vaddr = m->framebuffer->base;
	// find a free slot
	for (uint32_t i=0 ; i<numBuffers ; i++)
	{
		if ((bufferMask & (1LU<<i)) == 0)
		{
			m->bufferMask |= (1LU<<i);
			break;
		}
		vaddr += bufferSize;
	}

	// The entire framebuffer memory is already mapped, now create a buffer object for parts of this memory
	private_handle_t* hnd = new private_handle_t(private_handle_t::PRIV_FLAGS_FRAMEBUFFER, size, vaddr,
	                                             0, dup(m->framebuffer->fd), vaddr - m->framebuffer->base);
	*pHandle = hnd;

	return 0;
}

static int gralloc_alloc_framebuffer(alloc_device_t* dev, size_t size, int usage, buffer_handle_t* pHandle)
{
	private_module_t* m = reinterpret_cast<private_module_t*>(dev->common.module);
	pthread_mutex_lock(&m->lock);
	int err = gralloc_alloc_framebuffer_locked(dev, size, usage, pHandle);
	pthread_mutex_unlock(&m->lock);
	return err;
}

static int alloc_device_alloc(alloc_device_t* dev, int w, int h, int format, int usage, buffer_handle_t* pHandle, int* pStride)
{
	if (!pHandle || !pStride)
	{
		return -EINVAL;
	}

	size_t size;
	size_t stride;
	if (format == HAL_PIXEL_FORMAT_YCbCr_420_SP ||
	    format == HAL_PIXEL_FORMAT_YCbCr_422_SP ||
		 format == HAL_PIXEL_FORMAT_YV12 )
	{
		int vstride;
		switch (format)
		{
			case HAL_PIXEL_FORMAT_YCbCr_420_SP:
				stride = (w + 1) & ~1;
				size = stride * h * 2;
				break;
			case HAL_PIXEL_FORMAT_YCbCr_422_SP:
				stride = (w + 1) & ~1;
				vstride = (h+1) & ~1;
				size = (stride * vstride) + (w/2 * h/2) * 2;
				break;
			case HAL_PIXEL_FORMAT_YV12:
				stride = (w + 15) & ~15;
				size = h * (stride + stride/2);
				break;
			default:
				return -EINVAL;
		}
	}
	else
	{
		int align = 8;
		int bpp = 0;
		switch (format)
		{
		case HAL_PIXEL_FORMAT_RGBA_8888:
		case HAL_PIXEL_FORMAT_RGBX_8888:
		case HAL_PIXEL_FORMAT_BGRA_8888:
			bpp = 4;
			break;
		case HAL_PIXEL_FORMAT_RGB_888:
			bpp = 3;
			break;
		case HAL_PIXEL_FORMAT_RGB_565:
		case HAL_PIXEL_FORMAT_RGBA_5551:
		case HAL_PIXEL_FORMAT_RGBA_4444:
			bpp = 2;
			break;
		default:
			return -EINVAL;
		}
		size_t bpr = (w*bpp + (align-1)) & ~(align-1);
		size = bpr * h;
		stride = bpr / bpp;
	}

	int err;
	if (usage & GRALLOC_USAGE_HW_FB)
	{
		err = gralloc_alloc_framebuffer(dev, size, usage, pHandle);
	}
	else
	{
		err = gralloc_alloc_buffer(dev, size, usage, pHandle);
	}

	if (err < 0)
	{
		return err;
	}

	*pStride = stride;
	return 0;
}

static int alloc_device_free(alloc_device_t* dev, buffer_handle_t handle)
{
	if (private_handle_t::validate(handle) < 0)
	{
		return -EINVAL;
	}

	private_handle_t const* hnd = reinterpret_cast<private_handle_t const*>(handle);
	if (hnd->flags & private_handle_t::PRIV_FLAGS_FRAMEBUFFER)
	{
		// free this buffer
		private_module_t* m = reinterpret_cast<private_module_t*>(dev->common.module);
		const size_t bufferSize = m->finfo.line_length * m->info.yres;
		int index = (hnd->base - m->framebuffer->base) / bufferSize;
		m->bufferMask &= ~(1<<index);
		close(hnd->fd);
	}
	else if (hnd->flags & private_handle_t::PRIV_FLAGS_USES_UMP)
	{
		ump_mapped_pointer_release((ump_handle)hnd->ump_mem_handle);
		ump_reference_release((ump_handle)hnd->ump_mem_handle);
	}

	delete hnd;

	return 0;
}

static int alloc_device_close(struct hw_device_t *device)
{
	alloc_device_t* dev = reinterpret_cast<alloc_device_t*>(device);
	if (dev)
	{
		delete dev;
		ump_close(); // Our UMP memory refs will be released automatically here...
	}
	return 0;
}

int alloc_device_open(hw_module_t const* module, const char* name, hw_device_t** device)
{
	alloc_device_t *dev;

	dev = new alloc_device_t;
	if (NULL == dev)
	{
		return -1;
	}

	ump_result ump_res = ump_open();
	if (UMP_OK != ump_res)
	{
		LOGE("UMP open failed");
		delete dev;
		return -1;
	}

	/* initialize our state here */
	memset(dev, 0, sizeof(*dev));

	/* initialize the procs */
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = const_cast<hw_module_t*>(module);
	dev->common.close = alloc_device_close;
	dev->alloc = alloc_device_alloc;
	dev->free = alloc_device_free;

	*device = &dev->common;

	return 0;
}
