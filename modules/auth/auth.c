/**
 * @file auth.c Implements STUN Authentication and Message-Integrity Mechanisms
 *
 * Copyright (C) 2010 Creytiv.com
 */

#include <string.h>
#include <time.h>
#include <re.h>
#include <restund.h>


enum {
	NONCE_EXPIRY = 3600,
	NONCE_SIZE   = 16,

};


static struct {
	uint32_t nonce_expiry;
	uint32_t rand_time;
	uint32_t rand_addr;
} auth;


static const char *mknonce(char *nonce, uint32_t now, const struct sa *src)
{
	(void)re_snprintf(nonce, NONCE_SIZE + 1, "%08x%08x",
			  auth.rand_time ^ now,
			  auth.rand_addr ^ sa_hash(src, SA_ADDR));
	return nonce;
}


static bool nonce_validate(char *nonce, uint32_t now, const struct sa *src)
{
	struct pl pl;
	uint32_t v;

	if (strlen(nonce) != NONCE_SIZE) {
		restund_info("auth: bad nonce length (%u)\n", strlen(nonce));
		return false;
	}

	pl.p = nonce;
	pl.l = 8;
	v = pl_x32(&pl) ^ auth.rand_time;

	if (v + auth.nonce_expiry < now) {
		restund_debug("auth: nonce expired\n");
		return false;
	}


	pl.p += 8;
	v = pl_x32(&pl) ^ auth.rand_addr;

	if (v != sa_hash(src, SA_ADDR)) {
		restund_info("auth: bad nonce src address (%j)\n", src);
		return false;
	}

	return true;
}


static bool request_handler(struct restund_msgctx *ctx, int proto, void *sock,
			    const struct sa *src, const struct sa *dst,
			    const struct stun_msg *msg)
{
	struct stun_attr *mi, *user, *realm, *nonce;
	const uint32_t now = (uint32_t)time(NULL);
	char nstr[NONCE_SIZE + 1];
	int err;
	(void)dst;

	if (ctx->key)
		return false;

	mi    = stun_msg_attr(msg, STUN_ATTR_MSG_INTEGRITY);
	user  = stun_msg_attr(msg, STUN_ATTR_USERNAME);
	realm = stun_msg_attr(msg, STUN_ATTR_REALM);
	nonce = stun_msg_attr(msg, STUN_ATTR_NONCE);

	if (!mi) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  401, "Unauthorized",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	if (!user || !realm || !nonce) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  400, "Bad Request",
				  NULL, 0, ctx->fp, 1,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	if (!nonce_validate(nonce->v.nonce, now, src)) {
		err = stun_ereply(proto, sock, src, 0, msg,
				  438, "Stale Nonce",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	ctx->key = mem_alloc(MD5_SIZE, NULL);
	if (!ctx->key) {
		restund_warning("auth: can't to allocate memory for MI key\n");
		err = stun_ereply(proto, sock, src, 0, msg,
				  500, "Server Error",
				  NULL, 0, ctx->fp, 1,
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	ctx->keylen = MD5_SIZE;

	if (restund_get_ha1(user->v.username, ctx->key)) {
		restund_info("auth: unknown user '%s'\n", user->v.username);
		err = stun_ereply(proto, sock, src, 0, msg,
				  401, "Unauthorized",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	if (stun_msg_chk_mi(msg, ctx->key, ctx->keylen)) {
		restund_info("auth: bad passwd for '%s'\n", user->v.username);
		err = stun_ereply(proto, sock, src, 0, msg,
				  401, "Unauthorized",
				  NULL, 0, ctx->fp, 3,
				  STUN_ATTR_REALM, restund_realm(),
				  STUN_ATTR_NONCE, mknonce(nstr, now, src),
				  STUN_ATTR_SOFTWARE, restund_software);
		goto unauth;
	}

	return false;

 unauth:
	if (err) {
		restund_warning("auth reply error: %s\n", strerror(err));
	}

	return true;
}


static struct restund_stun stun = {
	.reqh = request_handler
};


static int module_init(void)
{
	auth.nonce_expiry = NONCE_EXPIRY;
	auth.rand_time = rand_u32();
	auth.rand_addr = rand_u32();

	conf_get_u32(restund_conf(), "auth_nonce_expiry", &auth.nonce_expiry);

	restund_stun_register_handler(&stun);

	restund_debug("auth: module loaded (nonce_expiry=%us)\n",
		      auth.nonce_expiry);

	return 0;
}


static int module_close(void)
{
	restund_stun_unregister_handler(&stun);

	restund_debug("auth: module closed\n");

	return 0;
}


const struct mod_export exports = {
	.name  = "auth",
	.type  = "stun",
	.init  = module_init,
	.close = module_close
};
