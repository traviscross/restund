/**
 * @file tcp.c TCP Transport
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <re.h>
#include <restund.h>
#include "stund.h"


struct tcp_lstnr {
	struct le le;
	struct sa bnd_addr;
	struct tcp_sock *ts;
};

/** Defines a TCP connection */
struct conn {
	struct le le;         /**< Linked list element          */
	struct tcp_conn *tc;  /**< TCP Connection               */
};


static struct list lstnrl;   /**< List of TCP Sockets (struct tcp_lstnr) */
static struct list tcl;      /**< List of TCP connections (struct conn)  */


static void conn_destructor(void *data)
{
	struct conn *conn = data;

	list_unlink(&conn->le);
	conn->tc = mem_deref(conn->tc);

	/* TODO explicit delete TURN mapping here */
}


static struct conn *conn_alloc(void)
{
	struct conn *conn;

	conn = mem_zalloc(sizeof(*conn), conn_destructor);
	if (!conn)
		return NULL;

	list_append(&tcl, &conn->le, conn);

	return conn;
}


/* todo: buffering */
static void tcp_recv(struct mbuf *mb, void *arg)
{
	struct conn *conn = arg;
	struct sa local, peer;

	(void)tcp_conn_local_get(conn->tc, &local);
	(void)tcp_conn_peer_get(conn->tc, &peer);

	restund_process_msg(IPPROTO_TCP, conn->tc, &peer, &local, mb);
}


static void tcp_close(int err, void *arg)
{
	struct conn *conn = arg;

	(void)err;

	restund_info("TCP close: (%s)\n", strerror(err));

	mem_deref(conn);
}


static void tcp_conn_handler(const struct sa *peer, void *arg)
{
	struct tcp_lstnr *tl = arg;
	struct conn *conn;
	int err;

	restund_info("TCP connect: peer=%J\n", peer);

	conn = conn_alloc();
	if (!conn) {
		restund_warning("tcp conn: conn_alloc() failed\n");
		return;
	}

	err = tcp_accept(&conn->tc, tl->ts, NULL, tcp_recv, tcp_close,
			 conn);
	if (err) {
		restund_warning("tcp conn: tcp_accept() %s\n", strerror(err));
		mem_deref(conn);
	}
}


static void lstnr_destructor(void *arg)
{
	struct tcp_lstnr *tl = arg;

	list_unlink(&tl->le);
	tl->ts = mem_deref(tl->ts);
}


static int listen_handler(const struct pl *addrport, void *arg)
{
	struct tcp_lstnr *tl = NULL;
	int err = ENOMEM;

	(void)arg;

	tl = mem_zalloc(sizeof(*tl), lstnr_destructor);
	if (!tl) {
		restund_warning("tcp listen error: %s\n", strerror(err));
		goto out;
	}

	list_append(&lstnrl, &tl->le, tl);

	err = sa_decode(&tl->bnd_addr, addrport->p, addrport->l);
	if (err || sa_is_any(&tl->bnd_addr) || !sa_port(&tl->bnd_addr)) {
		restund_warning("bad tcp_listen directive: '%r'\n", addrport);
		err = EINVAL;
		goto out;
	}

	err = tcp_listen(&tl->ts, &tl->bnd_addr, tcp_conn_handler, tl);
	if (err) {
		restund_warning("tcp error: %s\n", strerror(err));
		goto out;
	}

	restund_debug("tcp listen: %J\n", &tl->bnd_addr);

 out:
	if (err)
		mem_deref(tl);

	return err;
}


int restund_tcp_init(void)
{
	int err;

	list_init(&lstnrl);
	list_init(&tcl);

	/* tcp config */
	err = conf_apply(restund_conf(), "tcp_listen", listen_handler, NULL);
	if (err)
		goto out;

 out:
	if (err)
		restund_tcp_close();

	return err;
}


void restund_tcp_close(void)
{
	list_flush(&lstnrl);
	list_flush(&tcl);
}


struct tcp_sock *restund_tcp_socket(struct sa *sa, const struct sa *orig,
				    bool ch_ip, bool ch_port)
{
	struct le *le = list_head(&lstnrl);

	while (le) {
		struct tcp_lstnr *tl = le->data;
		le = le->next;

		if (ch_ip && sa_cmp(orig, &tl->bnd_addr, SA_ADDR))
			continue;

		if (ch_port && (sa_port(orig) == sa_port(&tl->bnd_addr)))
			continue;

		sa_cpy(sa, &tl->bnd_addr);
		return tl->ts;
	}

	return NULL;
}
