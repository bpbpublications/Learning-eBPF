/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __SCHED_ACT_BPF_SKEL_H__
#define __SCHED_ACT_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct sched_act_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_program *drop_icmp_randomly;
	} progs;
	struct {
		struct bpf_link *drop_icmp_randomly;
	} links;

#ifdef __cplusplus
	static inline struct sched_act_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct sched_act_bpf *open_and_load();
	static inline int load(struct sched_act_bpf *skel);
	static inline int attach(struct sched_act_bpf *skel);
	static inline void detach(struct sched_act_bpf *skel);
	static inline void destroy(struct sched_act_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
sched_act_bpf__destroy(struct sched_act_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
sched_act_bpf__create_skeleton(struct sched_act_bpf *obj);

static inline struct sched_act_bpf *
sched_act_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct sched_act_bpf *obj;
	int err;

	obj = (struct sched_act_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = sched_act_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	sched_act_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct sched_act_bpf *
sched_act_bpf__open(void)
{
	return sched_act_bpf__open_opts(NULL);
}

static inline int
sched_act_bpf__load(struct sched_act_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct sched_act_bpf *
sched_act_bpf__open_and_load(void)
{
	struct sched_act_bpf *obj;
	int err;

	obj = sched_act_bpf__open();
	if (!obj)
		return NULL;
	err = sched_act_bpf__load(obj);
	if (err) {
		sched_act_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
sched_act_bpf__attach(struct sched_act_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
sched_act_bpf__detach(struct sched_act_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *sched_act_bpf__elf_bytes(size_t *sz);

static inline int
sched_act_bpf__create_skeleton(struct sched_act_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "sched_act_bpf";
	s->obj = &obj->obj;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "drop_icmp_randomly";
	s->progs[0].prog = &obj->progs.drop_icmp_randomly;
	s->progs[0].link = &obj->links.drop_icmp_randomly;

	s->data = (void *)sched_act_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *sched_act_bpf__elf_bytes(size_t *sz)
{
	*sz = 3560;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x28\x0b\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0b\0\
\x01\0\xb7\x06\0\0\0\0\0\0\x61\x12\x50\0\0\0\0\0\x61\x11\x4c\0\0\0\0\0\xbf\x13\
\0\0\0\0\0\0\x07\x03\0\0\x0e\0\0\0\x2d\x23\x16\0\0\0\0\0\x71\x13\x0c\0\0\0\0\0\
\x71\x14\x0d\0\0\0\0\0\x67\x04\0\0\x08\0\0\0\x4f\x34\0\0\0\0\0\0\x55\x04\x11\0\
\x08\0\0\0\xb7\x03\0\0\0\0\0\0\xbf\x14\0\0\0\0\0\0\x07\x04\0\0\x22\0\0\0\x2d\
\x24\x0c\0\0\0\0\0\xb7\x06\0\0\0\0\0\0\x71\x11\x17\0\0\0\0\0\x55\x01\x0a\0\x01\
\0\0\0\x85\0\0\0\x07\0\0\0\x67\0\0\0\x20\0\0\0\x77\0\0\0\x20\0\0\0\xbf\x01\0\0\
\0\0\0\0\x37\x01\0\0\x64\0\0\0\x27\x01\0\0\x64\0\0\0\x1f\x10\0\0\0\0\0\0\xb7\
\x03\0\0\x02\0\0\0\x25\0\x01\0\x06\0\0\0\xbf\x36\0\0\0\0\0\0\xbf\x60\0\0\0\0\0\
\0\x95\0\0\0\0\0\0\0\x47\x50\x4c\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xf0\x02\0\0\
\xf0\x02\0\0\xc6\x03\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\x01\0\0\0\x20\0\0\x04\xb8\
\0\0\0\x0b\0\0\0\x03\0\0\0\0\0\0\0\x0f\0\0\0\x03\0\0\0\x20\0\0\0\x18\0\0\0\x03\
\0\0\0\x40\0\0\0\x1d\0\0\0\x03\0\0\0\x60\0\0\0\x2b\0\0\0\x03\0\0\0\x80\0\0\0\
\x34\0\0\0\x03\0\0\0\xa0\0\0\0\x41\0\0\0\x03\0\0\0\xc0\0\0\0\x4a\0\0\0\x03\0\0\
\0\xe0\0\0\0\x55\0\0\0\x03\0\0\0\0\x01\0\0\x5e\0\0\0\x03\0\0\0\x20\x01\0\0\x6e\
\0\0\0\x03\0\0\0\x40\x01\0\0\x76\0\0\0\x03\0\0\0\x60\x01\0\0\x7f\0\0\0\x05\0\0\
\0\x80\x01\0\0\x82\0\0\0\x03\0\0\0\x20\x02\0\0\x87\0\0\0\x03\0\0\0\x40\x02\0\0\
\x92\0\0\0\x03\0\0\0\x60\x02\0\0\x97\0\0\0\x03\0\0\0\x80\x02\0\0\xa0\0\0\0\x03\
\0\0\0\xa0\x02\0\0\xa8\0\0\0\x03\0\0\0\xc0\x02\0\0\xaf\0\0\0\x03\0\0\0\xe0\x02\
\0\0\xba\0\0\0\x03\0\0\0\0\x03\0\0\xc4\0\0\0\x07\0\0\0\x20\x03\0\0\xcf\0\0\0\
\x07\0\0\0\xa0\x03\0\0\xd9\0\0\0\x03\0\0\0\x20\x04\0\0\xe5\0\0\0\x03\0\0\0\x40\
\x04\0\0\xf0\0\0\0\x03\0\0\0\x60\x04\0\0\0\0\0\0\x08\0\0\0\x80\x04\0\0\xfa\0\0\
\0\x0a\0\0\0\xc0\x04\0\0\x01\x01\0\0\x03\0\0\0\0\x05\0\0\x0a\x01\0\0\x03\0\0\0\
\x20\x05\0\0\0\0\0\0\x0c\0\0\0\x40\x05\0\0\x13\x01\0\0\x03\0\0\0\x80\x05\0\0\
\x1c\x01\0\0\0\0\0\x08\x04\0\0\0\x22\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\
\0\0\0\0\0\x03\0\0\0\0\x03\0\0\0\x06\0\0\0\x05\0\0\0\x2f\x01\0\0\0\0\0\x01\x04\
\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x03\0\0\0\x06\0\0\0\x04\0\0\0\0\0\0\
\0\x01\0\0\x05\x08\0\0\0\x43\x01\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x15\0\
\0\0\x4d\x01\0\0\0\0\0\x08\x0b\0\0\0\x53\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\
\0\0\0\0\x01\0\0\x05\x08\0\0\0\x66\x01\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\
\x16\0\0\0\0\0\0\0\x01\0\0\x0d\x0f\0\0\0\x69\x01\0\0\x01\0\0\0\x6d\x01\0\0\0\0\
\0\x01\x04\0\0\0\x20\0\0\x01\x71\x01\0\0\x01\0\0\x0c\x0e\0\0\0\x99\x03\0\0\0\0\
\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x06\0\0\0\x04\
\0\0\0\x9e\x03\0\0\0\0\0\x0e\x12\0\0\0\x01\0\0\0\xa7\x03\0\0\x01\0\0\x0f\0\0\0\
\0\x13\0\0\0\0\0\0\0\x04\0\0\0\xaf\x03\0\0\0\0\0\x07\0\0\0\0\xbd\x03\0\0\0\0\0\
\x07\0\0\0\0\0\x5f\x5f\x73\x6b\x5f\x62\x75\x66\x66\0\x6c\x65\x6e\0\x70\x6b\x74\
\x5f\x74\x79\x70\x65\0\x6d\x61\x72\x6b\0\x71\x75\x65\x75\x65\x5f\x6d\x61\x70\
\x70\x69\x6e\x67\0\x70\x72\x6f\x74\x6f\x63\x6f\x6c\0\x76\x6c\x61\x6e\x5f\x70\
\x72\x65\x73\x65\x6e\x74\0\x76\x6c\x61\x6e\x5f\x74\x63\x69\0\x76\x6c\x61\x6e\
\x5f\x70\x72\x6f\x74\x6f\0\x70\x72\x69\x6f\x72\x69\x74\x79\0\x69\x6e\x67\x72\
\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x69\x66\x69\x6e\x64\x65\x78\0\
\x74\x63\x5f\x69\x6e\x64\x65\x78\0\x63\x62\0\x68\x61\x73\x68\0\x74\x63\x5f\x63\
\x6c\x61\x73\x73\x69\x64\0\x64\x61\x74\x61\0\x64\x61\x74\x61\x5f\x65\x6e\x64\0\
\x6e\x61\x70\x69\x5f\x69\x64\0\x66\x61\x6d\x69\x6c\x79\0\x72\x65\x6d\x6f\x74\
\x65\x5f\x69\x70\x34\0\x6c\x6f\x63\x61\x6c\x5f\x69\x70\x34\0\x72\x65\x6d\x6f\
\x74\x65\x5f\x69\x70\x36\0\x6c\x6f\x63\x61\x6c\x5f\x69\x70\x36\0\x72\x65\x6d\
\x6f\x74\x65\x5f\x70\x6f\x72\x74\0\x6c\x6f\x63\x61\x6c\x5f\x70\x6f\x72\x74\0\
\x64\x61\x74\x61\x5f\x6d\x65\x74\x61\0\x74\x73\x74\x61\x6d\x70\0\x77\x69\x72\
\x65\x5f\x6c\x65\x6e\0\x67\x73\x6f\x5f\x73\x65\x67\x73\0\x67\x73\x6f\x5f\x73\
\x69\x7a\x65\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\
\x5f\x5f\0\x66\x6c\x6f\x77\x5f\x6b\x65\x79\x73\0\x5f\x5f\x75\x36\x34\0\x75\x6e\
\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x73\x6b\0\
\x63\x74\x78\0\x69\x6e\x74\0\x64\x72\x6f\x70\x5f\x69\x63\x6d\x70\x5f\x72\x61\
\x6e\x64\x6f\x6d\x6c\x79\0\x61\x63\x74\x69\x6f\x6e\0\x2f\x68\x6f\x6d\x65\x2f\
\x62\x75\x69\x6c\x64\x2f\x50\x72\x6f\x6a\x65\x63\x74\x73\x2f\x66\x69\x6e\x61\
\x6c\x2d\x65\x62\x70\x66\x2d\x63\x6f\x64\x65\x2d\x65\x78\x61\x6d\x70\x6c\x65\
\x73\x2f\x63\x68\x30\x38\x2f\x42\x50\x46\x5f\x50\x52\x4f\x47\x5f\x54\x59\x50\
\x45\x5f\x53\x43\x48\x45\x44\x5f\x41\x43\x54\x2f\x73\x63\x68\x65\x64\x5f\x61\
\x63\x74\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x64\x72\x6f\x70\x5f\x69\x63\
\x6d\x70\x5f\x72\x61\x6e\x64\x6f\x6d\x6c\x79\x28\x73\x74\x72\x75\x63\x74\x20\
\x5f\x5f\x73\x6b\x5f\x62\x75\x66\x66\x20\x2a\x63\x74\x78\x29\x20\x7b\0\x20\x20\
\x76\x6f\x69\x64\x20\x2a\x64\x61\x74\x61\x5f\x65\x6e\x64\x20\x3d\x20\x28\x76\
\x6f\x69\x64\x20\x2a\x29\x28\x6c\x6f\x6e\x67\x29\x63\x74\x78\x2d\x3e\x64\x61\
\x74\x61\x5f\x65\x6e\x64\x3b\0\x20\x20\x76\x6f\x69\x64\x20\x2a\x64\x61\x74\x61\
\x20\x3d\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x28\x6c\x6f\x6e\x67\x29\x63\x74\
\x78\x2d\x3e\x64\x61\x74\x61\x3b\0\x20\x20\x69\x66\x20\x28\x64\x61\x74\x61\x20\
\x2b\x20\x73\x69\x7a\x65\x6f\x66\x28\x2a\x65\x74\x68\x29\x20\x3e\x20\x64\x61\
\x74\x61\x5f\x65\x6e\x64\x29\x20\x7b\0\x20\x20\x69\x66\x20\x28\x65\x74\x68\x2d\
\x3e\x68\x5f\x70\x72\x6f\x74\x6f\x20\x3d\x3d\x20\x5f\x5f\x62\x70\x66\x5f\x63\
\x6f\x6e\x73\x74\x61\x6e\x74\x5f\x68\x74\x6f\x6e\x73\x28\x45\x54\x48\x5f\x50\
\x5f\x49\x50\x29\x29\x20\x7b\0\x20\x20\x20\x20\x69\x66\x20\x28\x28\x76\x6f\x69\
\x64\x20\x2a\x29\x69\x70\x20\x2b\x20\x73\x69\x7a\x65\x6f\x66\x28\x2a\x69\x70\
\x29\x20\x3e\x20\x64\x61\x74\x61\x5f\x65\x6e\x64\x29\x20\x7b\0\x20\x20\x20\x20\
\x69\x66\x20\x28\x69\x70\x2d\x3e\x70\x72\x6f\x74\x6f\x63\x6f\x6c\x20\x3d\x3d\
\x20\x49\x50\x50\x52\x4f\x54\x4f\x5f\x49\x43\x4d\x50\x29\x20\x7b\0\x20\x20\x20\
\x20\x20\x20\x5f\x5f\x75\x33\x32\x20\x72\x61\x6e\x64\x6f\x6d\x5f\x76\x61\x6c\
\x75\x65\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x70\x72\x61\x6e\x64\x6f\
\x6d\x5f\x75\x33\x32\x28\x29\x3b\0\x20\x20\x20\x20\x20\x20\x69\x66\x20\x28\x72\
\x61\x6e\x64\x6f\x6d\x5f\x76\x61\x6c\x75\x65\x20\x25\x20\x31\x30\x30\x20\x3c\
\x20\x37\x29\x20\x7b\x20\x2f\x2f\x20\x44\x72\x6f\x70\x20\x77\x69\x74\x68\x20\
\x37\x25\x20\x70\x72\x6f\x62\x61\x62\x69\x6c\x69\x74\x79\0\x7d\0\x63\x68\x61\
\x72\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x6c\x69\x63\x65\x6e\x73\x65\0\x62\x70\
\x66\x5f\x66\x6c\x6f\x77\x5f\x6b\x65\x79\x73\0\x62\x70\x66\x5f\x73\x6f\x63\x6b\
\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\xec\0\0\0\0\x01\0\0\
\0\0\0\0\x08\0\0\0\x84\x01\0\0\x01\0\0\0\0\0\0\0\x10\0\0\0\x10\0\0\0\x84\x01\0\
\0\x0e\0\0\0\0\0\0\0\x8b\x01\0\0\xe6\x01\0\0\0\x28\0\0\x08\0\0\0\x8b\x01\0\0\
\x16\x02\0\0\x27\x2c\0\0\x10\0\0\0\x8b\x01\0\0\x46\x02\0\0\x23\x30\0\0\x18\0\0\
\0\x8b\x01\0\0\x6e\x02\0\0\x0c\x3c\0\0\x28\0\0\0\x8b\x01\0\0\x6e\x02\0\0\x07\
\x3c\0\0\x30\0\0\0\x8b\x01\0\0\x96\x02\0\0\x0c\x4c\0\0\x50\0\0\0\x8b\x01\0\0\
\x96\x02\0\0\x07\x4c\0\0\x60\0\0\0\x8b\x01\0\0\xce\x02\0\0\x14\x58\0\0\x70\0\0\
\0\x8b\x01\0\0\xce\x02\0\0\x09\x58\0\0\x80\0\0\0\x8b\x01\0\0\xfd\x02\0\0\x0d\
\x68\0\0\x88\0\0\0\x8b\x01\0\0\xfd\x02\0\0\x09\x68\0\0\x90\0\0\0\x8b\x01\0\0\
\x25\x03\0\0\x1c\x6c\0\0\xa8\0\0\0\x8b\x01\0\0\x57\x03\0\0\x18\x70\0\0\xe0\0\0\
\0\x8b\x01\0\0\x97\x03\0\0\x01\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5e\0\0\0\
\0\0\x03\0\xe0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x65\0\0\0\0\0\x03\0\xd8\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\
\x3c\0\0\0\x11\0\x04\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\xe8\x02\0\0\0\0\0\0\
\x04\0\0\0\x05\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x40\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x60\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x80\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xa0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xc0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\xd0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xe0\0\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\xf0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\0\x01\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x10\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x0d\x0e\0\x64\x72\
\x6f\x70\x5f\x69\x63\x6d\x70\x5f\x72\x61\x6e\x64\x6f\x6d\x6c\x79\0\x2e\x74\x65\
\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x61\x63\x74\x69\
\x6f\x6e\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\
\x63\x65\x6e\x73\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\
\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x36\0\x4c\x42\x42\
\x30\x5f\x35\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x45\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xba\x0a\0\0\0\0\0\0\x6c\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\0\0\0\x01\0\0\0\x06\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x27\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x40\0\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x3d\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\
\x01\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x59\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\x01\0\0\0\0\0\0\
\xce\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x55\0\0\
\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x09\0\0\0\0\0\0\x10\0\0\0\0\
\0\0\0\x0a\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1e\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\x08\0\0\0\0\0\0\x20\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1a\0\0\0\x09\0\0\0\x40\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xc8\x09\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\
\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x2e\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\
\0\0\0\0\0\0\0\0\0\0\0\xb8\x0a\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4d\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x28\x09\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x01\0\0\0\x04\0\0\0\x08\0\0\0\0\
\0\0\0\x18\0\0\0\0\0\0\0";
}

#ifdef __cplusplus
struct sched_act_bpf *sched_act_bpf::open(const struct bpf_object_open_opts *opts) { return sched_act_bpf__open_opts(opts); }
struct sched_act_bpf *sched_act_bpf::open_and_load() { return sched_act_bpf__open_and_load(); }
int sched_act_bpf::load(struct sched_act_bpf *skel) { return sched_act_bpf__load(skel); }
int sched_act_bpf::attach(struct sched_act_bpf *skel) { return sched_act_bpf__attach(skel); }
void sched_act_bpf::detach(struct sched_act_bpf *skel) { sched_act_bpf__detach(skel); }
void sched_act_bpf::destroy(struct sched_act_bpf *skel) { sched_act_bpf__destroy(skel); }
const void *sched_act_bpf::elf_bytes(size_t *sz) { return sched_act_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
sched_act_bpf__assert(struct sched_act_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __SCHED_ACT_BPF_SKEL_H__ */
