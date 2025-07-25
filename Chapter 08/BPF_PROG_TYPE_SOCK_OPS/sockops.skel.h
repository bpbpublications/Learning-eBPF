/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __SOCKOPS_BPF_SKEL_H__
#define __SOCKOPS_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct sockops_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_program *modify_buffers;
	} progs;
	struct {
		struct bpf_link *modify_buffers;
	} links;

#ifdef __cplusplus
	static inline struct sockops_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct sockops_bpf *open_and_load();
	static inline int load(struct sockops_bpf *skel);
	static inline int attach(struct sockops_bpf *skel);
	static inline void detach(struct sockops_bpf *skel);
	static inline void destroy(struct sockops_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
sockops_bpf__destroy(struct sockops_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
sockops_bpf__create_skeleton(struct sockops_bpf *obj);

static inline struct sockops_bpf *
sockops_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct sockops_bpf *obj;
	int err;

	obj = (struct sockops_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = sockops_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	sockops_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct sockops_bpf *
sockops_bpf__open(void)
{
	return sockops_bpf__open_opts(NULL);
}

static inline int
sockops_bpf__load(struct sockops_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct sockops_bpf *
sockops_bpf__open_and_load(void)
{
	struct sockops_bpf *obj;
	int err;

	obj = sockops_bpf__open();
	if (!obj)
		return NULL;
	err = sockops_bpf__load(obj);
	if (err) {
		sockops_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
sockops_bpf__attach(struct sockops_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
sockops_bpf__detach(struct sockops_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *sockops_bpf__elf_bytes(size_t *sz);

static inline int
sockops_bpf__create_skeleton(struct sockops_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "sockops_bpf";
	s->obj = &obj->obj;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "modify_buffers";
	s->progs[0].prog = &obj->progs.modify_buffers;
	s->progs[0].link = &obj->links.modify_buffers;

	s->data = (void *)sockops_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *sockops_bpf__elf_bytes(size_t *sz)
{
	*sz = 3560;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x28\x0b\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0b\0\
\x01\0\xbf\x16\0\0\0\0\0\0\xb7\x01\0\0\x30\x75\0\0\x63\x1a\xfc\xff\0\0\0\0\x61\
\x61\0\0\0\0\0\0\x15\x01\x03\0\x05\0\0\0\x18\0\0\0\xff\xff\xff\xff\0\0\0\0\0\0\
\0\0\x55\x01\x10\0\x03\0\0\0\xbf\xa7\0\0\0\0\0\0\x07\x07\0\0\xfc\xff\xff\xff\
\xbf\x61\0\0\0\0\0\0\xb7\x02\0\0\x01\0\0\0\xb7\x03\0\0\x07\0\0\0\xbf\x74\0\0\0\
\0\0\0\xb7\x05\0\0\x04\0\0\0\x85\0\0\0\x31\0\0\0\xbf\x08\0\0\0\0\0\0\xbf\x61\0\
\0\0\0\0\0\xb7\x02\0\0\x01\0\0\0\xb7\x03\0\0\x08\0\0\0\xbf\x74\0\0\0\0\0\0\xb7\
\x05\0\0\x04\0\0\0\x85\0\0\0\x31\0\0\0\x0f\x80\0\0\0\0\0\0\x63\x06\x04\0\0\0\0\
\0\xb7\0\0\0\x01\0\0\0\x95\0\0\0\0\0\0\0\x47\x50\x4c\0\x9f\xeb\x01\0\x18\0\0\0\
\0\0\0\0\x74\x03\0\0\x74\x03\0\0\xd5\x03\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\x01\0\
\0\0\x28\0\0\x04\xd8\0\0\0\x0e\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\x20\0\
\0\0\x11\0\0\0\x03\0\0\0\xa0\0\0\0\x18\0\0\0\x03\0\0\0\xc0\0\0\0\x23\0\0\0\x03\
\0\0\0\xe0\0\0\0\x2d\0\0\0\x06\0\0\0\0\x01\0\0\x38\0\0\0\x06\0\0\0\x80\x01\0\0\
\x42\0\0\0\x03\0\0\0\0\x02\0\0\x4e\0\0\0\x03\0\0\0\x20\x02\0\0\x59\0\0\0\x03\0\
\0\0\x40\x02\0\0\x65\0\0\0\x03\0\0\0\x60\x02\0\0\x6e\0\0\0\x03\0\0\0\x80\x02\0\
\0\x76\0\0\0\x03\0\0\0\xa0\x02\0\0\x8c\0\0\0\x03\0\0\0\xc0\x02\0\0\x92\0\0\0\
\x03\0\0\0\xe0\x02\0\0\x9a\0\0\0\x03\0\0\0\0\x03\0\0\xa7\0\0\0\x03\0\0\0\x20\
\x03\0\0\xaf\0\0\0\x03\0\0\0\x40\x03\0\0\xb7\0\0\0\x03\0\0\0\x60\x03\0\0\xbf\0\
\0\0\x03\0\0\0\x80\x03\0\0\xc9\0\0\0\x03\0\0\0\xa0\x03\0\0\xd3\0\0\0\x03\0\0\0\
\xc0\x03\0\0\xe2\0\0\0\x03\0\0\0\xe0\x03\0\0\xf3\0\0\0\x03\0\0\0\0\x04\0\0\xff\
\0\0\0\x03\0\0\0\x20\x04\0\0\x0b\x01\0\0\x03\0\0\0\x40\x04\0\0\x19\x01\0\0\x03\
\0\0\0\x60\x04\0\0\x21\x01\0\0\x03\0\0\0\x80\x04\0\0\x2e\x01\0\0\x03\0\0\0\xa0\
\x04\0\0\x37\x01\0\0\x03\0\0\0\xc0\x04\0\0\x45\x01\0\0\x03\0\0\0\xe0\x04\0\0\
\x4e\x01\0\0\x03\0\0\0\0\x05\0\0\x59\x01\0\0\x03\0\0\0\x20\x05\0\0\x63\x01\0\0\
\x08\0\0\0\x40\x05\0\0\x72\x01\0\0\x08\0\0\0\x80\x05\0\0\0\0\0\0\x0a\0\0\0\xc0\
\x05\0\0\0\0\0\0\x0c\0\0\0\0\x06\0\0\0\0\0\0\x0e\0\0\0\x40\x06\0\0\x7e\x01\0\0\
\x03\0\0\0\x80\x06\0\0\x86\x01\0\0\x03\0\0\0\xa0\x06\0\0\x94\x01\0\0\0\0\0\x08\
\x04\0\0\0\x9a\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\x05\x10\0\
\0\0\xa7\x01\0\0\x06\0\0\0\0\0\0\0\xac\x01\0\0\x03\0\0\0\0\0\0\0\xb2\x01\0\0\
\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x03\0\0\0\x07\0\0\0\x04\0\0\0\xbc\
\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\xd0\x01\0\0\0\0\0\x08\x09\0\0\0\xd6\x01\
\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x05\x08\0\0\0\xe9\x01\0\0\
\x0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x16\0\0\0\0\0\0\0\x01\0\0\x05\x08\0\0\0\
\xec\x01\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\0\x05\
\x08\0\0\0\xf5\x01\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x0d\x10\0\0\0\x02\x02\
\0\0\x01\0\0\0\x08\x02\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x0c\x02\0\0\x01\0\0\
\x0c\x0f\0\0\0\xb7\x03\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\
\0\0\0\x12\0\0\0\x07\0\0\0\x04\0\0\0\xbc\x03\0\0\0\0\0\x0e\x13\0\0\0\x01\0\0\0\
\xc4\x03\0\0\x01\0\0\x0f\0\0\0\0\x14\0\0\0\0\0\0\0\x04\0\0\0\xcc\x03\0\0\0\0\0\
\x07\0\0\0\0\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\x5f\x6f\x70\x73\0\x6f\x70\0\x66\
\x61\x6d\x69\x6c\x79\0\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x34\0\x6c\x6f\x63\
\x61\x6c\x5f\x69\x70\x34\0\x72\x65\x6d\x6f\x74\x65\x5f\x69\x70\x36\0\x6c\x6f\
\x63\x61\x6c\x5f\x69\x70\x36\0\x72\x65\x6d\x6f\x74\x65\x5f\x70\x6f\x72\x74\0\
\x6c\x6f\x63\x61\x6c\x5f\x70\x6f\x72\x74\0\x69\x73\x5f\x66\x75\x6c\x6c\x73\x6f\
\x63\x6b\0\x73\x6e\x64\x5f\x63\x77\x6e\x64\0\x73\x72\x74\x74\x5f\x75\x73\0\x62\
\x70\x66\x5f\x73\x6f\x63\x6b\x5f\x6f\x70\x73\x5f\x63\x62\x5f\x66\x6c\x61\x67\
\x73\0\x73\x74\x61\x74\x65\0\x72\x74\x74\x5f\x6d\x69\x6e\0\x73\x6e\x64\x5f\x73\
\x73\x74\x68\x72\x65\x73\x68\0\x72\x63\x76\x5f\x6e\x78\x74\0\x73\x6e\x64\x5f\
\x6e\x78\x74\0\x73\x6e\x64\x5f\x75\x6e\x61\0\x6d\x73\x73\x5f\x63\x61\x63\x68\
\x65\0\x65\x63\x6e\x5f\x66\x6c\x61\x67\x73\0\x72\x61\x74\x65\x5f\x64\x65\x6c\
\x69\x76\x65\x72\x65\x64\0\x72\x61\x74\x65\x5f\x69\x6e\x74\x65\x72\x76\x61\x6c\
\x5f\x75\x73\0\x70\x61\x63\x6b\x65\x74\x73\x5f\x6f\x75\x74\0\x72\x65\x74\x72\
\x61\x6e\x73\x5f\x6f\x75\x74\0\x74\x6f\x74\x61\x6c\x5f\x72\x65\x74\x72\x61\x6e\
\x73\0\x73\x65\x67\x73\x5f\x69\x6e\0\x64\x61\x74\x61\x5f\x73\x65\x67\x73\x5f\
\x69\x6e\0\x73\x65\x67\x73\x5f\x6f\x75\x74\0\x64\x61\x74\x61\x5f\x73\x65\x67\
\x73\x5f\x6f\x75\x74\0\x6c\x6f\x73\x74\x5f\x6f\x75\x74\0\x73\x61\x63\x6b\x65\
\x64\x5f\x6f\x75\x74\0\x73\x6b\x5f\x74\x78\x68\x61\x73\x68\0\x62\x79\x74\x65\
\x73\x5f\x72\x65\x63\x65\x69\x76\x65\x64\0\x62\x79\x74\x65\x73\x5f\x61\x63\x6b\
\x65\x64\0\x73\x6b\x62\x5f\x6c\x65\x6e\0\x73\x6b\x62\x5f\x74\x63\x70\x5f\x66\
\x6c\x61\x67\x73\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\
\x69\x6e\x74\0\x61\x72\x67\x73\0\x72\x65\x70\x6c\x79\0\x72\x65\x70\x6c\x79\x6c\
\x6f\x6e\x67\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\
\x45\x5f\x5f\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\
\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x73\x6b\0\x73\x6b\x62\x5f\x64\x61\x74\x61\0\
\x73\x6b\x62\x5f\x64\x61\x74\x61\x5f\x65\x6e\x64\0\x73\x6b\x6f\x70\x73\0\x69\
\x6e\x74\0\x6d\x6f\x64\x69\x66\x79\x5f\x62\x75\x66\x66\x65\x72\x73\0\x73\x6f\
\x63\x6b\x6f\x70\x73\0\x2f\x68\x6f\x6d\x65\x2f\x62\x75\x69\x6c\x64\x2f\x50\x72\
\x6f\x6a\x65\x63\x74\x73\x2f\x66\x69\x6e\x61\x6c\x2d\x65\x62\x70\x66\x2d\x63\
\x6f\x64\x65\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x68\x30\x38\x2f\x42\
\x50\x46\x5f\x50\x52\x4f\x47\x5f\x54\x59\x50\x45\x5f\x53\x4f\x43\x4b\x5f\x4f\
\x50\x53\x2f\x73\x6f\x63\x6b\x6f\x70\x73\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\
\x20\x6d\x6f\x64\x69\x66\x79\x5f\x62\x75\x66\x66\x65\x72\x73\x28\x73\x74\x72\
\x75\x63\x74\x20\x62\x70\x66\x5f\x73\x6f\x63\x6b\x5f\x6f\x70\x73\x20\x2a\x73\
\x6b\x6f\x70\x73\x29\x20\x7b\0\x20\x20\x69\x6e\x74\x20\x62\x75\x66\x73\x69\x7a\
\x65\x20\x3d\x20\x33\x30\x30\x30\x30\x3b\0\x20\x20\x6f\x70\x20\x3d\x20\x28\x69\
\x6e\x74\x29\x73\x6b\x6f\x70\x73\x2d\x3e\x6f\x70\x3b\0\x20\x20\x73\x77\x69\x74\
\x63\x68\x20\x28\x6f\x70\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\
\x66\x5f\x73\x65\x74\x73\x6f\x63\x6b\x6f\x70\x74\x28\x73\x6b\x6f\x70\x73\x2c\
\x20\x53\x4f\x4c\x5f\x53\x4f\x43\x4b\x45\x54\x2c\x20\x53\x4f\x5f\x53\x4e\x44\
\x42\x55\x46\x2c\x20\x26\x62\x75\x66\x73\x69\x7a\x65\x2c\x20\x73\x69\x7a\x65\
\x6f\x66\x28\x62\x75\x66\x73\x69\x7a\x65\x29\x29\x3b\0\x20\x20\x20\x20\x20\x20\
\x20\x20\x62\x70\x66\x5f\x73\x65\x74\x73\x6f\x63\x6b\x6f\x70\x74\x28\x73\x6b\
\x6f\x70\x73\x2c\x20\x53\x4f\x4c\x5f\x53\x4f\x43\x4b\x45\x54\x2c\x20\x53\x4f\
\x5f\x52\x43\x56\x42\x55\x46\x2c\x20\x26\x62\x75\x66\x73\x69\x7a\x65\x2c\x20\
\x73\x69\x7a\x65\x6f\x66\x28\x62\x75\x66\x73\x69\x7a\x65\x29\x29\x3b\0\x20\x20\
\x20\x20\x72\x76\x20\x2b\x3d\0\x20\x20\x73\x6b\x6f\x70\x73\x2d\x3e\x72\x65\x70\
\x6c\x79\x20\x3d\x20\x72\x76\x3b\0\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x31\x3b\
\0\x63\x68\x61\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x6c\x69\x63\x65\x6e\x73\x65\
\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\0\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\
\0\0\0\x14\0\0\0\xac\0\0\0\xc0\0\0\0\0\0\0\0\x08\0\0\0\x1b\x02\0\0\x01\0\0\0\0\
\0\0\0\x11\0\0\0\x10\0\0\0\x1b\x02\0\0\x0a\0\0\0\0\0\0\0\x23\x02\0\0\x7b\x02\0\
\0\0\x38\0\0\x10\0\0\0\x23\x02\0\0\xac\x02\0\0\x07\x3c\0\0\x18\0\0\0\x23\x02\0\
\0\xc3\x02\0\0\x14\x48\0\0\x20\0\0\0\x23\x02\0\0\xda\x02\0\0\x03\x50\0\0\x48\0\
\0\0\x23\x02\0\0\0\0\0\0\0\0\0\0\x50\0\0\0\x23\x02\0\0\xea\x02\0\0\x09\x60\0\0\
\x88\0\0\0\x23\x02\0\0\x3b\x03\0\0\x09\x68\0\0\xb8\0\0\0\x23\x02\0\0\x8c\x03\0\
\0\x08\x64\0\0\xc0\0\0\0\x23\x02\0\0\x96\x03\0\0\x10\x7c\0\0\xc8\0\0\0\x23\x02\
\0\0\xab\x03\0\0\x03\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x69\0\0\0\0\0\x03\0\x40\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x62\0\0\0\0\0\x03\0\xc0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x14\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\x5a\0\0\0\x11\0\x04\
\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x78\x03\0\0\0\0\0\0\x04\0\0\0\x05\0\0\0\
\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xb0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xc0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xd0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x0d\x0e\0\x2e\x74\x65\x78\x74\0\x2e\x72\
\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x6d\x6f\x64\x69\x66\x79\x5f\x62\x75\
\x66\x66\x65\x72\x73\0\x73\x6f\x63\x6b\x6f\x70\x73\0\x2e\x6c\x6c\x76\x6d\x5f\
\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x73\x74\x72\
\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\
\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\x42\x30\x5f\x33\0\x4c\x42\x42\x30\x5f\
\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x41\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb2\x0a\0\0\0\0\0\0\x70\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x23\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x40\0\0\0\0\0\0\0\xd8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x39\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\
\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x55\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1c\x01\0\0\0\0\0\0\
\x61\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x51\0\0\
\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\x09\0\0\0\0\0\0\x10\0\0\0\0\
\0\0\0\x0a\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x08\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x0a\0\0\0\0\0\0\xb0\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x2b\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\
\0\0\0\0\0\0\0\0\0\xb0\x0a\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x49\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x60\x09\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\
\x18\0\0\0\0\0\0\0";
}

#ifdef __cplusplus
struct sockops_bpf *sockops_bpf::open(const struct bpf_object_open_opts *opts) { return sockops_bpf__open_opts(opts); }
struct sockops_bpf *sockops_bpf::open_and_load() { return sockops_bpf__open_and_load(); }
int sockops_bpf::load(struct sockops_bpf *skel) { return sockops_bpf__load(skel); }
int sockops_bpf::attach(struct sockops_bpf *skel) { return sockops_bpf__attach(skel); }
void sockops_bpf::detach(struct sockops_bpf *skel) { sockops_bpf__detach(skel); }
void sockops_bpf::destroy(struct sockops_bpf *skel) { sockops_bpf__destroy(skel); }
const void *sockops_bpf::elf_bytes(size_t *sz) { return sockops_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
sockops_bpf__assert(struct sockops_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __SOCKOPS_BPF_SKEL_H__ */
