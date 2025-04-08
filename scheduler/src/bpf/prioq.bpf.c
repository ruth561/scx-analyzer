#include "prioq.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Priority queue
 */

struct prioq_node {
	s32 pid;
	s64 prio;
	struct bpf_rb_node node;
};

private(PRIOQ) struct bpf_spin_lock lock;
private(PRIOQ) struct bpf_rb_root root __contains(prioq_node, node);

static bool less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct prioq_node *node_a;
	struct prioq_node *node_b;

	node_a = container_of(a, struct prioq_node, node);
	node_b = container_of(b, struct prioq_node, node);

	return node_a->prio < node_b->prio;
}

__hidden
s32 prioq_push_elem(s32 pid, s64 prio)
{
	s32 err;
	struct prioq_node *prioq_node;

	prioq_node = bpf_obj_new(typeof(*prioq_node));
	if (!prioq_node)
		return -ENOMEM;

	prioq_node->pid = pid;
	prioq_node->prio = prio;

	bpf_spin_lock(&lock);
	err = bpf_rbtree_add(&root, &prioq_node->node, less);
	bpf_spin_unlock(&lock);

	return err;
}

__hidden
s32 prioq_pop_elem(s32 *pid, s64 *prio)
{
	struct bpf_rb_node *node;
	struct prioq_node *prioq_node;

	bpf_spin_lock(&lock);
	node = bpf_rbtree_first(&root);
	if (!node) {
		bpf_spin_unlock(&lock);
		return -ENOENT;
	}
	node = bpf_rbtree_remove(&root, node);
	bpf_spin_unlock(&lock);

	if (!node)
		return -ENOENT;
	prioq_node = container_of(node, struct prioq_node, node);

	*pid = prioq_node->pid;
	*prio = prioq_node->prio;

	bpf_obj_drop(prioq_node);

	return 0; /* success */
}

__hidden
s32 prioq_get_first(s32 *pid, s64 *prio)
{
	struct bpf_rb_node *node;
	struct prioq_node *prioq_node;

	bpf_spin_lock(&lock);
	node = bpf_rbtree_first(&root);
	if (!node) {
		bpf_spin_unlock(&lock);
		return -ENOENT;
	}
	prioq_node = container_of(node, struct prioq_node, node);
	*pid = prioq_node->pid;
	*prio = prioq_node->prio;
	bpf_spin_unlock(&lock);

	return 0; /* success */
}
