
#include "everything.h"

s32 test_getmeshid(unsigned int if_idx, char *mesh_id)
{
	struct nl60211msg *nlres;
	struct nl60211_getmeshid_res *res;

	printf("get mesh id of :idx = %d\n", if_idx);

	if_nl_send(NL60211_GETMESHID, if_idx, 0);
	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_getmeshid_res *)nlres->buf;
	if (res->return_code) {
		printf("getmeshid error ...\n");
		exit(-1);
	}
	printf("id = %s\n", res->id);
	printf("getmeshid OK ...\n");
	strcpy(mesh_id, (char *)res->id);
	return res->return_code;
}

s32 test_setmeshid(unsigned int if_idx, char *mesh_id)
{
	//request
	struct nl60211_setmeshid_req *req;
	//response
	struct nl60211msg *nlres;
	struct nl60211_setmeshid_res *res;

	req = (struct nl60211_setmeshid_req *)sk_msg_send.nl_msg.buf;
	req->id_len = strlen(mesh_id);
	if (req->id_len > 32) {
		printf("Error: mesh id must less or equal than 32\n");
		exit(-1);
	}

	memcpy(req->id, mesh_id, req->id_len);
	req->id[req->id_len] = 0; // '\0' for the end of C string
	if_nl_send(
		NL60211_SETMESHID,
		if_idx,
		sizeof(struct nl60211_setmeshid_req) +
			req->id_len +
			1/* '\0' for teh end of C string */);

	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_setmeshid_res *)nlres->buf;
	if (res->return_code) {
		printf("setmeshid error ...\n");
		exit(-1);
	}
	return res->return_code;
}

s32 test_getsa(unsigned int if_idx)
{
	uint32_t i;
	//request
	//response
	struct nl60211msg *nlres;
	struct nl60211_getsa_res *res;

	if_nl_send(NL60211_GETSA, if_idx, 0);
	if_nl_recv();
	nlres = (struct nl60211msg *)&sk_msg_recv.nl_msg;
	res = (struct nl60211_getsa_res *)nlres->buf;
	if (res->return_code) {
		printf("get sa error ...\n");
		exit(-1);
	}
	printf("sa = ");
	for (i = 0; i < res->sa_len; i++)
		printf("%02X ", res->sa[i]);
	printf("\n");
	printf("get sa OK ...\n");
	return res->return_code;
}

void self_test_proc_000(unsigned int if_idx)
{
	s32 ret;
	char old_mesh_id[33];
	char old_mesh_id2[33];
	char new_mesh_id[33] = "mesh996633";

	printf("%s() : local test [START]\n", __func__);
	test_getmeshid(if_idx, old_mesh_id);

	ret = test_setmeshid(if_idx, new_mesh_id);
	if (ret == 0) {
		test_getmeshid(if_idx, old_mesh_id2);
		if (strcmp(old_mesh_id2, new_mesh_id) == 0) {
			printf("new mesh id set OK ...\n");
			test_setmeshid(if_idx, old_mesh_id); //restore mesh id
		} else {
			printf("new mesh id set FAILED ...\n");
			exit(-1);
		}
	}

	test_getsa(if_idx);

	printf("%s() : local test [PASS]\n", __func__);
}

void self_test_proc(u32 ctrl_code, unsigned int if_idx)
{
	switch(ctrl_code)
	{
		case NL60211_CTRL_SELF_TEST_001:
			self_test_proc_000(if_idx);
			break;
		case NL60211_CTRL_SELF_TEST_002:
			break;
		case NL60211_CTRL_SELF_TEST_003:
			break;
		case NL60211_CTRL_SELF_TEST_004:
			break;
		default:
			break;
	}
}

