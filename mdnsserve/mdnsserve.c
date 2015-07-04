/*
 * Copyright (c) 2010,2011 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2006 Michele Marchetto <mydecay@openbeer.it>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <yaml.h>

#include <imsg.h>

#include "log.h"
#include "mdns.h"

#define MDNSSERVE_USER "_mdnsserve"

__dead void	usage(void);

void add_group(struct mdns* mdns, int index, yaml_document_t* document, yaml_node_pair_t* pair);
void add_service(struct mdns* mdns, char const* group, int index, yaml_document_t* document, yaml_node_t* item);

void mdnsserve_group_hook(struct mdns*, int, char const*);

int main(int argc, char *argv[])
{
	int debug = 0;

	int ch;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	log_init(1); /* log to stderr before we daemonise */

	argc -= optind;
	argv += optind;

	if (!argc)
		usage();

	yaml_parser_t parser;

	if (!yaml_parser_initialize(&parser))
		log_fatalx("failed to initialise config parser");

	FILE* config;

	if (!(config = fopen(*argv, "rb")))
		log_fatal("failed to open '%s'", *argv);

	yaml_parser_set_input_file(&parser, config);

	struct mdns mdns;
	int initialised = 0;

	for (;;) {
		yaml_document_t document;

		if (!yaml_parser_load(&parser, &document))
			log_fatalx("failed to parse '%s'", *argv);

		yaml_node_t* root = yaml_document_get_root_node(&document);

		if (!root)
			break;

		if (root->type != YAML_MAPPING_NODE)
			log_fatalx(
				"expecting a map at document root, got type %d (line %d column %d)",
				root->type, root->start_mark.line, root->start_mark.column);

		if (!initialised) {
			if (mdns_open(&mdns) == -1)
				log_fatal("mdns_open failed");

			mdns_set_group_hook(&mdns, mdnsserve_group_hook);

			log_init(debug);
			if (!debug)
				daemon(1, 0);
			log_notice("connected to mdnsd socket");

			initialised = 1;
		}

		for (yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair)
			add_group(&mdns, pair - root->data.mapping.pairs.start + 1, &document, pair);

		yaml_document_delete(&document);
	}

	fclose(config);

	if (!debug) {
		struct passwd* pw;

		if ((pw = getpwnam(MDNSSERVE_USER)) == NULL)
			log_fatal("getpwnam failed, make sure you have user and group _mdnsserve");

		if (chroot(pw->pw_dir) == -1)
			log_fatal("chroot(\"%s\") failed", pw->pw_dir);
		if (chdir("/") == -1)
			log_fatal("chdir(\"/\") failed");

		setproctitle("mdnsserve");

		if (!geteuid()) {
			if (setgroups(1, &pw->pw_gid) ||
				setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
				setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
				log_fatal("failed to drop privileges");
		}
	}

	for (;;) {
		int n = mdns_read(&mdns);

		if (n == -1)
			log_fatal("mdns_read failed");
		else if (n == 0) {
			log_notice("socket closed by mdnsd, shutting down");
			break;
		}
	}

	return 0;
}

__dead void usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-d] config.yaml\n", __progname);
	exit(1);
}

void add_group(struct mdns* mdns, int index, yaml_document_t* document, yaml_node_pair_t* pair)
{
	yaml_node_t* key = yaml_document_get_node(document, pair->key);
	yaml_node_t* value = yaml_document_get_node(document, pair->value);

	if (!key)
		log_fatalx("invalid node index %d for group %d key", pair->key, index);

	if (!value)
		log_fatalx("invalid node index %d for group %d value", pair->value, index);

	if (key->type != YAML_SCALAR_NODE || !key->data.scalar.length) {
		log_warnx(
			"expecting scalar at line %d column %d for group %d, got %d, ignoring group",
			key->start_mark.line, key->start_mark.column, index, key->type);
		return;
	}

	char const* group = key->data.scalar.value;

	if (key->data.scalar.length >= MAXHOSTNAMELEN) {
		log_warnx(
			"group name '%s' too long (line %d column %d), ignoring group",
			group, key->start_mark.line, key->start_mark.column);
		return;
	}

	if (value->type != YAML_SEQUENCE_NODE) {
		log_warnx(
			"expecting array of services for group '%s' (line %d column %d), got type %d, ignoring group",
			group, value->start_mark.line, value->start_mark.column, value->type);
		return;
	}

	if (mdns_group_add(mdns, group) == -1)
		log_fatal("failed to add group '%s'", group);

	for (yaml_node_item_t* i = value->data.sequence.items.start; i < value->data.sequence.items.top; ++i)
		add_service(mdns, group, i - value->data.sequence.items.start + 1, document, yaml_document_get_node(document, *i));

	if (mdns_group_commit(mdns, group) == -1)
		log_fatalx("failed to commit group '%s'", group);
}

void add_service(struct mdns* mdns, char const* group, int index, yaml_document_t* document, yaml_node_t* item)
{
	if (!item)
		log_fatalx("invalid node index for item %d of group '%s'", index, group);

	if (item->type != YAML_MAPPING_NODE) {
		log_warnx(
			"expecting a map for item %d of group '%s' (line %d column %d), got type %d, ignoring service",
			index, group, item->start_mark.line, item->start_mark.column, item->type);
		return;
	}

	char const* service = NULL;
	char const* protocol = NULL;
	char const* hostname = NULL;
	struct in_addr addr, *address = NULL;
	int port = 0;
	char const* text = "";

	for (yaml_node_pair_t* pair = item->data.mapping.pairs.start; pair < item->data.mapping.pairs.top; ++pair) {
		int i = pair - item->data.mapping.pairs.start + 1;
		yaml_node_t* key = yaml_document_get_node(document, pair->key);
		yaml_node_t* value = yaml_document_get_node(document, pair->value);

		if (!key)
			log_fatalx(
				"invalid node index %d for key %d in item %d of group '%s'",
				pair->key, i, index, group);

		if (!value)
			log_fatalx(
				"invalid node index %d for value %d in item %d of group '%s'",
				pair->value, i, index, group);

		if (key->type != YAML_SCALAR_NODE || !key->data.scalar.length) {
			log_warnx(
				"expecting scalar for key %d in item %d of group '%s' (line %d column %d), got type %d, ignoring service",
				i, index, group, key->start_mark.line, key->start_mark.column, key->type);
			return;
		}

		if (value->type != YAML_SCALAR_NODE || !value->data.scalar.length) {
			log_warnx(
				"expecting scalar for value %d in item %d of group '%s' (line %d column %d), got type %d, ignoring service",
				i, index, group, value->start_mark.line, value->start_mark.column, value->type);
			return;
		}

		if (!strcmp("service", key->data.scalar.value))
			service = value->data.scalar.value;
		else if (!strcmp("protocol", key->data.scalar.value))
			protocol = value->data.scalar.value;
		else if (!strcmp("hostname", key->data.scalar.value))
			hostname = value->data.scalar.value;
		else if (!strcmp("address", key->data.scalar.value)) {
			if (inet_pton(AF_INET, value->data.scalar.value, &addr) != 1) {
				log_warn(
					"invalid address '%s' for item %d of group '%s', ignoring service",
					value->data.scalar.value, index, group);
				return;
			}
			address = &addr;
		}
		else if (!strcmp("port", key->data.scalar.value)) {
			char const* errstr = NULL;
			port = strtonum(value->data.scalar.value, 0, UINT16_MAX, &errstr);
			if (errstr) {
				log_warnx(
					"invalid port '%s' (%s) for item %d of group '%s', ignoring service",
					value->data.scalar.value, errstr, index, group);
				return;
			}
		}
		else if (!strcmp("text", key->data.scalar.value))
			text = value->data.scalar.value;
	}

	if (!service) {
		log_warnx(
			"missing 'service' in item %d of group '%s', ignoring service",
			index, group);
		return;
	}

	if (!protocol || (strcmp("tcp", protocol) && strcmp("udp", protocol))) {
		log_warnx(
			"invalid protocol '%s' in item %d of group '%s', ignoring service",
			protocol, index, group);
		return;
	}

	if (!!hostname != !!address) {
		log_warnx(
			"'hostname' and 'address' must be both empty or valid in item %d of group '%s', ignoring service",
			index, group);
		return;
	}

	struct mdns_service ms;

	if (mdns_service_init(&ms, group, service, protocol, port, text, hostname, address) == -1) {
		log_warnx("failed to initialise _%s._%s for group '%s'", service, protocol, group);
		return;
	}

	if (mdns_group_add_service(mdns, group, &ms) == -1) {
		log_warnx("failed to add service _%s._%s to group '%s'", service, protocol, group);
		return;
	}

	if (hostname) {
		char addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, address, addr, INET_ADDRSTRLEN);
		addr[INET_ADDRSTRLEN - 1] = 0;

		log_notice(
			"added _%s._%s on host %s (%s) port %d with text '%s' to group '%s'",
			service, protocol, hostname, addr, port, text, group);
	}
	else {
		log_notice(
			"added _%s._%s on port %d with text '%s' to group '%s'",
			service, protocol, port, text, group);
	}
}

void mdnsserve_group_hook(struct mdns* mdns, int event, const char* group)
{
	switch (event) {
	case MDNS_GROUP_ERR_COLLISION:
		log_warnx("collision on group '%s', not published", group);
		break;

	case MDNS_GROUP_ERR_NOT_FOUND:
		log_fatalx("group '%s' not found, shutting down", group);
		break;

	case MDNS_GROUP_ERR_DOUBLE_ADD:
		log_warnx("group '%s' already added, not published", group);
		break;

	case MDNS_GROUP_PROBING:
		log_debug("probing group '%s'...", group);
		break;

	case MDNS_GROUP_ANNOUNCING:
		log_debug("announcing group '%s'...", group);
		break;

	case MDNS_GROUP_PUBLISHED:
		log_notice("group '%s' published", group);
		break;

	default:
		log_warnx("unhandled group event %d", event);
		break;
	}
}
