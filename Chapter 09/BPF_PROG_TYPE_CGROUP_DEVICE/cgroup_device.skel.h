/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __CGROUP_DEVICE_BPF_SKEL_H__
#define __CGROUP_DEVICE_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct cgroup_device_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata_str1_1;
	} maps;
	struct {
		struct bpf_program *bpf_prog1;
	} progs;
	struct {
		struct bpf_link *bpf_prog1;
	} links;

#ifdef __cplusplus
	static inline struct cgroup_device_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct cgroup_device_bpf *open_and_load();
	static inline int load(struct cgroup_device_bpf *skel);
	static inline int attach(struct cgroup_device_bpf *skel);
	static inline void detach(struct cgroup_device_bpf *skel);
	static inline void destroy(struct cgroup_device_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
cgroup_device_bpf__destroy(struct cgroup_device_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
cgroup_device_bpf__create_skeleton(struct cgroup_device_bpf *obj);

static inline struct cgroup_device_bpf *
cgroup_device_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct cgroup_device_bpf *obj;
	int err;

	obj = (struct cgroup_device_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = cgroup_device_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	cgroup_device_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct cgroup_device_bpf *
cgroup_device_bpf__open(void)
{
	return cgroup_device_bpf__open_opts(NULL);
}

static inline int
cgroup_device_bpf__load(struct cgroup_device_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct cgroup_device_bpf *
cgroup_device_bpf__open_and_load(void)
{
	struct cgroup_device_bpf *obj;
	int err;

	obj = cgroup_device_bpf__open();
	if (!obj)
		return NULL;
	err = cgroup_device_bpf__load(obj);
	if (err) {
		cgroup_device_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
cgroup_device_bpf__attach(struct cgroup_device_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
cgroup_device_bpf__detach(struct cgroup_device_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *cgroup_device_bpf__elf_bytes(size_t *sz);

static inline int
cgroup_device_bpf__create_skeleton(struct cgroup_device_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "cgroup_device_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = ".rodata.str1.1";
	s->maps[0].map = &obj->maps.rodata_str1_1;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "bpf_prog1";
	s->progs[0].prog = &obj->progs.bpf_prog1;
	s->progs[0].link = &obj->links.bpf_prog1;

	s->data = (void *)cgroup_device_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *cgroup_device_bpf__elf_bytes(size_t *sz)
{
	*sz = 3648;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\x0b\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0c\0\
\x01\0\xbf\x17\0\0\0\0\0\0\x61\x78\0\0\0\0\0\0\xb7\x06\0\0\0\0\0\0\x73\x6a\xfa\
\xff\0\0\0\0\xb7\x01\0\0\x64\x0a\0\0\x6b\x1a\xf8\xff\0\0\0\0\x18\x01\0\0\x61\
\x74\x74\x65\0\0\0\0\x6d\x70\x74\x65\x7b\x1a\xf0\xff\0\0\0\0\x18\x01\0\0\x3a\
\x20\x25\x64\0\0\0\0\x3a\x25\x64\x20\x7b\x1a\xe8\xff\0\0\0\0\x18\x01\0\0\x6f\
\x20\x64\x65\0\0\0\0\x76\x69\x63\x65\x7b\x1a\xe0\xff\0\0\0\0\x18\x01\0\0\x41\
\x63\x63\x65\0\0\0\0\x73\x73\x20\x74\x7b\x1a\xd8\xff\0\0\0\0\x61\x74\x08\0\0\0\
\0\0\x61\x73\x04\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xd8\xff\xff\xff\xb7\
\x02\0\0\x23\0\0\0\x85\0\0\0\x06\0\0\0\xb7\x01\0\0\x25\x64\x0a\0\x63\x1a\xd0\
\xff\0\0\0\0\x18\x01\0\0\x41\x63\x63\x65\0\0\0\0\x73\x73\x3a\x20\x7b\x1a\xc8\
\xff\0\0\0\0\x18\x01\0\0\x79\x70\x65\x3a\0\0\0\0\x20\x25\x64\x20\x7b\x1a\xc0\
\xff\0\0\0\0\x18\x01\0\0\x41\x63\x63\x65\0\0\0\0\x73\x73\x20\x54\x7b\x1a\xb8\
\xff\0\0\0\0\xbf\x83\0\0\0\0\0\0\x67\x03\0\0\x30\0\0\0\xc7\x03\0\0\x30\0\0\0\
\xbf\x84\0\0\0\0\0\0\x67\x04\0\0\x20\0\0\0\xc7\x04\0\0\x30\0\0\0\xbf\xa1\0\0\0\
\0\0\0\x07\x01\0\0\xb8\xff\xff\xff\xb7\x02\0\0\x1c\0\0\0\x85\0\0\0\x06\0\0\0\
\x67\x08\0\0\x10\0\0\0\x67\x08\0\0\x20\0\0\0\x77\x08\0\0\x20\0\0\0\x15\x08\x11\
\0\0\0\x02\0\xb7\x01\0\0\x63\x65\0\0\x6b\x1a\xb4\xff\0\0\0\0\xb7\x01\0\0\x64\
\x65\x76\x69\x63\x1a\xb0\xff\0\0\0\0\x18\x01\0\0\x61\x72\x61\x63\0\0\0\0\x74\
\x65\x72\x20\x7b\x1a\xa8\xff\0\0\0\0\x18\x01\0\0\x4e\x6f\x74\x20\0\0\0\0\x61\
\x20\x63\x68\x7b\x1a\xa0\xff\0\0\0\0\x73\x6a\xb6\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\
\0\x07\x01\0\0\xa0\xff\xff\xff\xb7\x02\0\0\x17\0\0\0\x85\0\0\0\x06\0\0\0\xbf\
\x60\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x61\x71\x04\0\0\0\0\0\xb7\x06\0\0\0\0\0\0\
\x55\x01\xfb\xff\x01\0\0\0\x61\x71\x08\0\0\0\0\0\x25\x01\x05\0\x09\0\0\0\xb7\
\x06\0\0\x01\0\0\0\xb7\x02\0\0\x01\0\0\0\x6f\x12\0\0\0\0\0\0\x57\x02\0\0\x28\
\x02\0\0\x55\x02\xf4\xff\0\0\0\0\xb7\x06\0\0\0\0\0\0\x05\0\xf2\xff\0\0\0\0\x41\
\x63\x63\x65\x73\x73\x20\x74\x6f\x20\x64\x65\x76\x69\x63\x65\x3a\x20\x25\x64\
\x3a\x25\x64\x20\x61\x74\x74\x65\x6d\x70\x74\x65\x64\x0a\0\x41\x63\x63\x65\x73\
\x73\x20\x54\x79\x70\x65\x3a\x20\x25\x64\x20\x41\x63\x63\x65\x73\x73\x3a\x20\
\x25\x64\x0a\0\x4e\x6f\x74\x20\x61\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\
\x64\x65\x76\x69\x63\x65\0\x47\x50\x4c\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\
\xe8\0\0\0\xe8\0\0\0\x06\x03\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\x01\0\0\0\x03\0\0\
\x04\x0c\0\0\0\x14\0\0\0\x03\0\0\0\0\0\0\0\x20\0\0\0\x03\0\0\0\x20\0\0\0\x26\0\
\0\0\x03\0\0\0\x40\0\0\0\x2c\0\0\0\0\0\0\x08\x04\0\0\0\x32\0\0\0\0\0\0\x01\x04\
\0\0\0\x20\0\0\0\0\0\0\0\x01\0\0\x0d\x06\0\0\0\x3f\0\0\0\x01\0\0\0\x43\0\0\0\0\
\0\0\x01\x04\0\0\0\x20\0\0\x01\x47\0\0\0\x01\0\0\x0c\x05\0\0\0\xdc\x02\0\0\0\0\
\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x08\0\0\0\x0a\0\0\0\x04\
\0\0\0\xe1\x02\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\xf5\x02\0\0\0\0\0\x0e\x09\0\0\
\0\x01\0\0\0\xfe\x02\0\0\x01\0\0\x0f\0\0\0\0\x0b\0\0\0\0\0\0\0\x04\0\0\0\0\x62\
\x70\x66\x5f\x63\x67\x72\x6f\x75\x70\x5f\x64\x65\x76\x5f\x63\x74\x78\0\x61\x63\
\x63\x65\x73\x73\x5f\x74\x79\x70\x65\0\x6d\x61\x6a\x6f\x72\0\x6d\x69\x6e\x6f\
\x72\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\
\x63\x74\x78\0\x69\x6e\x74\0\x62\x70\x66\x5f\x70\x72\x6f\x67\x31\0\x63\x67\x72\
\x6f\x75\x70\x2f\x64\x65\x76\0\x2f\x68\x6f\x6d\x65\x2f\x62\x75\x69\x6c\x64\x2f\
\x50\x72\x6f\x6a\x65\x63\x74\x73\x2f\x65\x62\x70\x66\x2d\x62\x6f\x6f\x6b\x2d\
\x63\x6f\x64\x65\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x68\x30\x39\x2f\
\x42\x50\x46\x5f\x50\x52\x4f\x47\x5f\x54\x59\x50\x45\x5f\x43\x47\x52\x4f\x55\
\x50\x5f\x44\x45\x56\x49\x43\x45\x2f\x63\x67\x72\x6f\x75\x70\x5f\x64\x65\x76\
\x69\x63\x65\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x62\x70\x66\x5f\x70\x72\
\x6f\x67\x31\x28\x73\x74\x72\x75\x63\x74\x20\x62\x70\x66\x5f\x63\x67\x72\x6f\
\x75\x70\x5f\x64\x65\x76\x5f\x63\x74\x78\x20\x2a\x63\x74\x78\x29\0\x20\x20\x20\
\x20\x73\x68\x6f\x72\x74\x20\x74\x79\x70\x65\x20\x3d\x20\x63\x74\x78\x2d\x3e\
\x61\x63\x63\x65\x73\x73\x5f\x74\x79\x70\x65\x20\x26\x20\x30\x78\x46\x46\x46\
\x46\x3b\0\x20\x20\x20\x20\x63\x68\x61\x72\x20\x66\x6d\x74\x5b\x5d\x20\x3d\x20\
\x22\x41\x63\x63\x65\x73\x73\x20\x74\x6f\x20\x64\x65\x76\x69\x63\x65\x3a\x20\
\x25\x64\x3a\x25\x64\x20\x61\x74\x74\x65\x6d\x70\x74\x65\x64\x5c\x6e\x22\x3b\0\
\x20\x20\x20\x20\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\
\x6b\x28\x66\x6d\x74\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x66\x6d\x74\x29\x2c\
\x20\x63\x74\x78\x2d\x3e\x6d\x61\x6a\x6f\x72\x2c\x20\x63\x74\x78\x2d\x3e\x6d\
\x69\x6e\x6f\x72\x29\x3b\0\x20\x20\x20\x20\x63\x68\x61\x72\x20\x66\x6d\x74\x32\
\x5b\x5d\x20\x3d\x20\x22\x41\x63\x63\x65\x73\x73\x20\x54\x79\x70\x65\x3a\x20\
\x25\x64\x20\x41\x63\x63\x65\x73\x73\x3a\x20\x25\x64\x5c\x6e\x22\x3b\0\x20\x20\
\x20\x20\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\x28\
\x66\x6d\x74\x32\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x66\x6d\x74\x32\x29\x2c\
\x20\x74\x79\x70\x65\x2c\x20\x61\x63\x63\x65\x73\x73\x29\x3b\0\x20\x20\x20\x20\
\x69\x66\x20\x28\x74\x79\x70\x65\x20\x21\x3d\x20\x42\x50\x46\x5f\x44\x45\x56\
\x43\x47\x5f\x44\x45\x56\x5f\x43\x48\x41\x52\x29\x20\x7b\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x63\x68\x61\x72\x20\x66\x6d\x74\x33\x5b\x5d\x20\x3d\x20\x22\x4e\
\x6f\x74\x20\x61\x20\x63\x68\x61\x72\x61\x63\x74\x65\x72\x20\x64\x65\x76\x69\
\x63\x65\x22\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\x66\x5f\x74\x72\x61\
\x63\x65\x5f\x70\x72\x69\x6e\x74\x6b\x28\x66\x6d\x74\x33\x2c\x20\x73\x69\x7a\
\x65\x6f\x66\x28\x66\x6d\x74\x33\x29\x29\x3b\0\x7d\0\x20\x20\x20\x20\x69\x66\
\x20\x28\x63\x74\x78\x2d\x3e\x6d\x61\x6a\x6f\x72\x20\x21\x3d\x20\x31\x29\x20\
\x7b\0\x20\x20\x20\x20\x69\x66\x20\x28\x63\x74\x78\x2d\x3e\x6d\x69\x6e\x6f\x72\
\x20\x3d\x3d\x20\x33\x20\x7c\x7c\x20\x63\x74\x78\x2d\x3e\x6d\x69\x6e\x6f\x72\
\x20\x3d\x3d\x20\x35\x20\x7c\x7c\x20\x63\x74\x78\x2d\x3e\x6d\x69\x6e\x6f\x72\
\x20\x3d\x3d\x20\x39\x29\x20\x7b\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\
\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x5f\x6c\x69\x63\x65\x6e\
\x73\x65\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\
\x14\0\0\0\x14\0\0\0\x5c\x01\0\0\x70\x01\0\0\0\0\0\0\x08\0\0\0\x51\0\0\0\x01\0\
\0\0\0\0\0\0\x07\0\0\0\x10\0\0\0\x51\0\0\0\x15\0\0\0\0\0\0\0\x5c\0\0\0\xbe\0\0\
\0\0\x18\0\0\x08\0\0\0\x5c\0\0\0\xec\0\0\0\x17\x20\0\0\x18\0\0\0\x5c\0\0\0\x18\
\x01\0\0\x0a\x28\0\0\x90\0\0\0\x5c\0\0\0\x50\x01\0\0\x05\x2c\0\0\xa8\0\0\0\x5c\
\0\0\0\0\0\0\0\0\0\0\0\xb0\0\0\0\x5c\0\0\0\x50\x01\0\0\x05\x2c\0\0\xc8\0\0\0\
\x5c\0\0\0\x90\x01\0\0\x0a\x30\0\0\x18\x01\0\0\x5c\0\0\0\xc2\x01\0\0\x2a\x34\0\
\0\x30\x01\0\0\x5c\0\0\0\xec\0\0\0\x17\x20\0\0\x40\x01\0\0\x5c\0\0\0\xc2\x01\0\
\0\x30\x34\0\0\x50\x01\0\0\x5c\0\0\0\0\0\0\0\0\0\0\0\x58\x01\0\0\x5c\0\0\0\xc2\
\x01\0\0\x05\x34\0\0\x68\x01\0\0\x5c\0\0\0\xc2\x01\0\0\x2a\x34\0\0\x80\x01\0\0\
\x5c\0\0\0\xfa\x01\0\0\x09\x40\0\0\x90\x01\0\0\x5c\0\0\0\x20\x02\0\0\x0e\x44\0\
\0\xf0\x01\0\0\x5c\0\0\0\x50\x02\0\0\x09\x48\0\0\0\x02\0\0\x5c\0\0\0\x7e\x02\0\
\0\x01\x84\0\0\x10\x02\0\0\x5c\0\0\0\x80\x02\0\0\x0e\x5c\0\0\x20\x02\0\0\x5c\0\
\0\0\x80\x02\0\0\x09\x5c\0\0\x28\x02\0\0\x5c\0\0\0\x9b\x02\0\0\x0e\x70\0\0\x30\
\x02\0\0\x5c\0\0\0\x9b\x02\0\0\x19\x70\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5d\0\
\0\0\0\0\x03\0\x10\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4f\0\0\0\0\0\x03\0\0\x02\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x56\0\0\0\0\0\x03\0\x60\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x64\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x70\x02\0\0\0\0\0\0\x2d\0\0\0\x11\0\
\x05\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\x04\0\0\0\x06\0\0\0\
\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xb0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xc0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xd0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xe0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xf0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x10\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x20\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\
\0\x30\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\
\0\0\x50\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\x01\0\0\0\0\0\0\x04\0\0\0\x01\
\0\0\0\x70\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\x01\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\x0e\x0f\0\x63\x67\x72\x6f\x75\x70\x2f\x64\x65\x76\0\x2e\x74\x65\x78\
\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x2e\x6c\x6c\x76\x6d\
\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x73\
\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\
\x54\x46\0\x4c\x42\x42\x30\x5f\x36\0\x4c\x42\x42\x30\x5f\x35\0\x4c\x42\x42\x30\
\x5f\x32\0\x62\x70\x66\x5f\x70\x72\x6f\x67\x31\0\x2e\x72\x6f\x64\x61\x74\x61\
\x2e\x73\x74\x72\x31\x2e\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x36\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc2\x0a\0\0\0\0\0\0\
\x7d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0c\0\0\0\
\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x70\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6e\0\0\0\x01\0\0\0\x32\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xb0\x02\0\0\0\0\0\0\x56\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\x2e\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x06\x03\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x4a\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0c\x03\0\0\0\0\
\0\0\x06\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x46\
\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x50\x09\0\0\0\0\0\0\x10\0\0\
\0\0\0\0\0\x0b\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x16\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\x07\0\0\0\0\0\0\x90\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x12\0\0\0\x09\0\0\0\x40\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x09\0\0\0\0\0\0\x60\x01\0\0\0\0\0\0\x0b\0\0\
\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1f\0\0\0\x03\x4c\xff\x6f\0\0\
\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x0a\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3e\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xa8\x08\0\0\0\0\0\0\xa8\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\x08\0\
\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";
}

#ifdef __cplusplus
struct cgroup_device_bpf *cgroup_device_bpf::open(const struct bpf_object_open_opts *opts) { return cgroup_device_bpf__open_opts(opts); }
struct cgroup_device_bpf *cgroup_device_bpf::open_and_load() { return cgroup_device_bpf__open_and_load(); }
int cgroup_device_bpf::load(struct cgroup_device_bpf *skel) { return cgroup_device_bpf__load(skel); }
int cgroup_device_bpf::attach(struct cgroup_device_bpf *skel) { return cgroup_device_bpf__attach(skel); }
void cgroup_device_bpf::detach(struct cgroup_device_bpf *skel) { cgroup_device_bpf__detach(skel); }
void cgroup_device_bpf::destroy(struct cgroup_device_bpf *skel) { cgroup_device_bpf__destroy(skel); }
const void *cgroup_device_bpf::elf_bytes(size_t *sz) { return cgroup_device_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
cgroup_device_bpf__assert(struct cgroup_device_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __CGROUP_DEVICE_BPF_SKEL_H__ */
