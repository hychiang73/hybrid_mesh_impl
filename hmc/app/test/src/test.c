
#include "everything.h"

// Test Print
#define tpr(f, ...) printf("[%s] " f, __func__, ##__VA_ARGS__)
#define tpr_start() tpr("start\n")

int if_nl_send_w_2_buf(uint16_t type, unsigned int if_index, u8* buf1, u32 buf1_len, u8* buf2, u32 buf2_len)
{
	memcpy(sk_msg_send.nl_msg.buf, buf1, buf1_len);
	memcpy(sk_msg_send.nl_msg.buf+buf1_len, buf2, buf2_len);
	if_nl_send(type, if_index, buf1_len+buf2_len);
	return 0;
}

unsigned int g_if_idx_from_shell_input;
u8 g_sa[6];
u8 g_peer_mac[6];
u8 g_peer_ip[4];

template <typename REQ, typename RES>
class NL60211_User_Command : public MyBasics {
public:
	REQ *pReq;
	RES *pRes;
	u16 cmdType;
	unsigned int if_idx;
	u8 *reqAddiBuf;
	u32 reqAddiBufLen;

	struct nlmsghdr res_nl_msghdr;
	unsigned int res_if_idx;
	u8 *resAddiBuf;
	u32 resAddiBufLen;

	NL60211_User_Command()
	{
		reqAddiBuf = NULL;
		reqAddiBufLen = 0;
		resAddiBuf = NULL;
		resAddiBufLen = 0;
		if_idx = g_if_idx_from_shell_input;
		pReq = (REQ *)malloc(sizeof(REQ));
		pRes = (RES *)malloc(sizeof(RES));
	};
	virtual ~NL60211_User_Command() //allow delete object with base class type
	{
		free(pReq);
		free(pRes);
		if (reqAddiBuf)
			free(reqAddiBuf);
		if (resAddiBuf)
			free(resAddiBuf);
	};
	void SetParam(REQ *inReq)
	{
		*pReq = *inReq;
	}
	virtual void SendReq()
	{
		if_nl_send_w_2_buf(cmdType, if_idx, (u8 *)pReq, sizeof(REQ), reqAddiBuf, reqAddiBufLen);
	};
	virtual void SendReq_Verbose(){};
	virtual void RecvRes_SyncMode()
	{
		if_nl_recv();
		res_nl_msghdr = sk_msg_recv.nl_msg.nl_msghdr;
		res_if_idx = sk_msg_recv.nl_msg.if_index;
		memcpy(pRes, sk_msg_recv.nl_msg.buf, sizeof(RES));
		RecvRes_CopyAddition((u8 *)sk_msg_recv.nl_msg.buf);
	};
	virtual void RecvRes_AsyncMode(){};
	virtual void RecvRes_CopyAddition(u8 *buf)
	{
		u32 outRecvLen = 0;
		u8 *outRecvBuf;
		RecvRes_CopyAddition_Parsing(buf, &outRecvLen, &outRecvBuf);
		if (outRecvLen == 0)
			return;
		//re-allocate
		if (outRecvLen > resAddiBufLen) {
			if (resAddiBuf)
				free(resAddiBuf);
			resAddiBuf = (u8 *)malloc(outRecvLen);
		} else {
			if (resAddiBuf == NULL)
				resAddiBuf = (u8 *)malloc(outRecvLen);
		}
		resAddiBufLen = outRecvLen;
		memcpy(resAddiBuf, outRecvBuf, outRecvLen);
	};
	virtual void RecvRes_CopyAddition_Parsing(u8 *buf, u32 *pOutRecvLen, u8 **pOutRecvBuf){};
	virtual void RecvRes_Verbose(){};
	virtual void CheckResponseHeader()
	{
		if (res_nl_msghdr.nlmsg_type != cmdType) {
			PrintClassName();
			printf("Error, nlmsg_type in response! res_nl_msghdr.nlmsg_type=0x%X, cmdType=0x%0X\n",
				res_nl_msghdr.nlmsg_type,
				cmdType);
			exit(-1);
		}
		if (res_if_idx != if_idx) {
			PrintClassName();
			printf("Error, if_index in response! res_if_idx=%d, if_idx=%d\n",
				res_if_idx,
				if_idx);
			exit(-1);
		}
	};
	virtual void CheckResponseReturnCode()
	{
		s32 *res_return_code = (s32 *)pRes;
		if (*res_return_code != 0) {
			PrintClassName();
			printf(" Error, none-zero return_code in response! (%d)\n", *res_return_code);
			exit(-1);
		}
	}
	virtual void CheckResponseReturnCode_Fail()
	{
		s32 *res_return_code = (s32 *)pRes;
		if (*res_return_code == 0) {
			PrintClassName();
			printf(" Error, zero return_code in response! (%d)\n", *res_return_code);
			exit(-1);
		}
	}
	virtual void CheckResponse()
	{
		s32 *res_return_code = (s32 *)pRes;

		PrintClassName();
		printf(" (%d) PASS!!!\n", *res_return_code);
	};
	virtual s32 RunTest()
	{
		s32 *res_return_code;

		SendReq();
		SendReq_Verbose();
		RecvRes_SyncMode();
		CheckResponseHeader();
		CheckResponseReturnCode();
		RecvRes_Verbose();
		CheckResponse();
		res_return_code = (s32 *)pRes;
		return *res_return_code;
	};
	virtual s32 RunFailTest()
	{
		s32 *res_return_code;

		SendReq();
		SendReq_Verbose();
		RecvRes_SyncMode();
		CheckResponseHeader();
		CheckResponseReturnCode_Fail();
		RecvRes_Verbose();
		CheckResponse();
		res_return_code = (s32 *)pRes;
		return *res_return_code;
	};
	virtual s32 Run()
	{
		s32 *res_return_code;

		SendReq();
		RecvRes_SyncMode();
		CheckResponseHeader();
		CheckResponseReturnCode();
		res_return_code = (s32 *)pRes;
		return *res_return_code;
	};
	virtual u8 *GetReqAddiBuf_Safely()
	{
		if (reqAddiBuf == NULL) {
			PrintClassName();
			printf(" Error, get un-allocted req additional buf!\n");
			exit(-1);
		}
		return reqAddiBuf;
	};
	virtual u8 *GetResAddiBuf_Safely()
	{
		if (resAddiBuf == NULL) {
			PrintClassName();
			printf(" Error, get un-allocted res additional buf!\n");
			exit(-1);
		}
		return resAddiBuf;
	};
	virtual void MacAddrPrint(u8 *macAddr, int doPrintNextLine = 0) //6 byte hex
	{
		printf("%02X %02X %02X %02X %02X %02X",
		       macAddr[0],
		       macAddr[1],
		       macAddr[2],
		       macAddr[3],
		       macAddr[4],
		       macAddr[5]);
		if (doPrintNextLine)
			printf("\n");
	}
	virtual int MacAddrIsTheSame(u8 *macAddr0, u8 *macAddr1) //6 byte hex
	{
		if (memcmp(macAddr0, macAddr1, 6) == 0)
			return 1;
		return 0;
	}
	virtual void MacAddrCopy(u8 *to, u8 *from) //6 byte hex
	{
		memcpy(to, from, 6);
	}
};

template <typename REQ, typename RES>
class NL60211_IF_Addr_Id : public NL60211_User_Command<REQ, RES> {
public:
	struct nl60211_addmpath_req *templateReq;
	virtual void SendReq_Verbose()
	{
		this->PrintClassName();
		printf(" addr : (HEX) ");
		this->MacAddrPrint(this->pReq->da);
		printf(" , iface_id = %d\n", this->pReq->iface_id);
	};
	virtual s32 RunTest_AddrId(u8 *ethDA, u16 iface_id)
	{
		templateReq = (struct nl60211_addmpath_req *)(this->pReq);
		templateReq->iface_id = iface_id;
		memcpy(templateReq->da, ethDA, 6);
		return NL60211_User_Command<REQ, RES>::RunTest();
	};
	virtual s32 RunFailTest_AddrId(u8 *ethDA, u16 iface_id)
	{
		templateReq = (struct nl60211_addmpath_req *)(this->pReq);
		templateReq->iface_id = iface_id;
		memcpy(templateReq->da, ethDA, 6);
		return NL60211_User_Command<REQ, RES>::RunFailTest();
	};
};

class NL60211_Control : public NL60211_User_Command<struct nl60211_ctrl_req, struct nl60211_ctrl_res> {
public:
	NL60211_Control() { cmdType = NL60211_CTRL;};
	virtual void CheckResponseReturnCode()
	{
		NL60211_User_Command::CheckResponseReturnCode();
		if (pReq->ctrl_code != pRes->ctrl_code) {
			PrintClassName();
			printf(" Error, ctrl_code not match!(Req:%d, Res:%d)\n", pReq->ctrl_code, pRes->ctrl_code);
			exit(-1);
		}
	}
};

class NL60211_GetVersion : public NL60211_Control {
public:
	NL60211_GetVersion() { pReq->ctrl_code = NL60211_CTRL_GET_VERSION; };

	virtual void CheckResponse()
	{
		PrintClassName();
		printf("local  data struct ver = 0x%04X\n", NL60211_DATA_STRUCT_VER);
		PrintClassName();
		printf("local  sub ver         = 0x%04X\n", NL60211_SUB_VER);
		PrintClassName();
		printf("module data struct ver = 0x%04X\n", pRes->u.verNum >> 16);
		PrintClassName();
		printf("module sub ver         = 0x%04X\n", pRes->u.verNum & 0xFFFF);
		
		if (NL60211_DATA_STRUCT_VER != (pRes->u.verNum >> 16)) {
			PrintClassName();
			printf("Wrong data struct ver\n");
			exit(-1);
		}
		if (NL60211_SUB_VER != (pRes->u.verNum & 0xFFFF)) {
			PrintClassName();
			printf("Wrong sub ver\n");
			exit(-1);
		}

		NL60211_User_Command::CheckResponse();
	};
};

class NL60211_GetRPD : public NL60211_Control {
public:
	NL60211_GetRPD() { pReq->ctrl_code = NL60211_CTRL_GET_RECV_PORT_DETECT; };
	virtual s32 Get(u8 *pRecvPortDetect)
	{
		s32 ret = NL60211_Control::RunTest();
		*pRecvPortDetect = pRes->u.recvPortDetect;
		return ret;
	};
};

class NL60211_SetRPD : public NL60211_Control {
public:
	NL60211_SetRPD() { pReq->ctrl_code = NL60211_CTRL_SET_RECV_PORT_DETECT; };
	virtual s32 RunTest(u8 recvPortDetect)
	{
		pReq->u.recvPortDetect = recvPortDetect;
		return NL60211_Control::RunTest();
	};
	virtual s32 Set(u8 recvPortDetect)
	{
		return RunTest(recvPortDetect);
	};
};

class NL60211_GetMeshId : public NL60211_User_Command<struct nl60211_getmeshid_req, struct nl60211_getmeshid_res> {
public:
	NL60211_GetMeshId() { cmdType = NL60211_GETMESHID; };
	virtual void RecvRes_CopyAddition(u8 *buf)
	{
		struct nl60211_getmeshid_res *resBuf = (struct nl60211_getmeshid_res *)buf;
		if (resAddiBuf)
			free(resAddiBuf);
		resAddiBuf = (u8 *)malloc(resBuf->id_len);
		memcpy(resAddiBuf, resBuf->id, resBuf->id_len);
		resAddiBuf[resBuf->id_len] = 0; //end of c string
	};
	virtual void RecvRes_Verbose()
	{
		PrintClassName();
		printf(" get id = %s\n", resAddiBuf);
	};
	virtual s32 RunTest(char *outStr)
	{
		s32 ret = NL60211_User_Command::RunTest();
		strcpy(outStr, (const char *)resAddiBuf);
		return ret;
	}
};

class NL60211_SetMeshId : public NL60211_User_Command<struct nl60211_setmeshid_req, struct nl60211_setmeshid_res> {
public:
	NL60211_SetMeshId() { cmdType = NL60211_SETMESHID; };
	void SetParam(char *idStr)
	{
		if (idStr == NULL)
			return;
		if (reqAddiBuf)
			free(reqAddiBuf);
		reqAddiBufLen = strlen(idStr);
		reqAddiBuf = (u8 *)malloc(reqAddiBufLen+1);
		memcpy(reqAddiBuf, idStr, reqAddiBufLen);
		pReq->id_len = reqAddiBufLen;
		reqAddiBuf[reqAddiBufLen] = 0;
	};
	virtual void SendReq()
	{
		if (reqAddiBuf) {
			NL60211_User_Command::SendReq();
		} else {
			PrintClassName();
			printf(" Error, mesh id is empty to set...\n");
		}
	};
	virtual void SendReq_Verbose()
	{
		PrintClassName();
		if (reqAddiBuf) {
			printf(" set id : %s\n", reqAddiBuf);
		} else {
			printf(" Error, mesh id is empty to set...\n");
		}
	};
	virtual s32 RunTest(char *idStr = NULL)
	{
		SetParam(idStr);
		return NL60211_User_Command::RunTest();
	}
};

class NL60211_GetSa : public NL60211_User_Command<struct nl60211_getsa_req, struct nl60211_getsa_res> {
public:
	NL60211_GetSa() { cmdType = NL60211_GETSA; };
	virtual void RecvRes_CopyAddition(u8 *buf)
	{
		struct nl60211_getsa_res *resBuf = (struct nl60211_getsa_res *)buf;
		if (resAddiBuf)
			free(resAddiBuf);
		resAddiBuf = (u8 *)malloc(resBuf->sa_len);
		memcpy(resAddiBuf, resBuf->sa, resBuf->sa_len);
	};
	virtual void RecvRes_Verbose()
	{
		u32 i;

		PrintClassName();
		printf(" get sa = (HEX) ");
		for (i=0; i<pRes->sa_len; i++) {
			printf("%02X ", resAddiBuf[i]);
		}
		printf("\n");
	};
};

class NL60211_AddMpath : public NL60211_IF_Addr_Id<struct nl60211_addmpath_req, struct nl60211_addmpath_res> {
public:
	NL60211_AddMpath() { cmdType = NL60211_ADD_MPATH; };
};

class NL60211_DelMpath : public NL60211_IF_Addr_Id<struct nl60211_delmpath_req, struct nl60211_delmpath_res> {
public:
	NL60211_DelMpath() { cmdType = NL60211_DEL_MPATH; };
};

class NL60211_GetMpath : public NL60211_IF_Addr_Id<struct nl60211_getmpath_req, struct nl60211_getmpath_res> {
public:
	NL60211_GetMpath() { cmdType = NL60211_GET_MPATH; };
};

class NL60211_DumpMpath : public NL60211_User_Command<struct nl60211_dumpmpath_req, struct nl60211_dumpmpath_res> {
public:
	u32 mpathNum;
	struct nl60211_dumpmpath_res mpathTbl[32];

	NL60211_DumpMpath() { cmdType = NL60211_DUMP_MPATH; mpathNum = 0; };
	void FillMpathTable(int verbos = 1)
	{
		u32 i;
		s32 *res_return_code;

		mpathNum = 0;
		SendReq();
		for(i = 0; i < 33; i++) {
			RecvRes_SyncMode();
			CheckResponseHeader();
			res_return_code = (s32 *)pRes;
			if (*res_return_code) {
				break;
			} else {
				if(i == 32) {
					PrintClassName();
					printf(" Error, mpath is more than 32.\n");
					exit(-1);
				}
				memcpy(&mpathTbl[mpathNum], pRes, sizeof(struct nl60211_dumpmpath_res));
				if(verbos) {
					printf("MPATH(%d) DA:(HEX)", mpathNum);
					MacAddrPrint(pRes->da);
					printf(", if:%u, metric:%u\n", pRes->iface_id, pRes->metric);
				}
				mpathNum++;
			}
		}
	};
	// Return true if found
	int FindMpath(u8 *da, u16 if_id, u32 *outFoundIndex = NULL)
	{
		u32 i;
		for(i = 0; i < mpathNum; i++) {
			if (MacAddrIsTheSame(da, mpathTbl[i].da) && (if_id == mpathTbl[i].iface_id)) {
				if (outFoundIndex != NULL)
					*outFoundIndex = i;
				return 1;
			}
		}
		return 0;
	}
};

class NL60211_PlcGetMetric : public NL60211_User_Command<struct nl60211_plcgetmetric_req, struct nl60211_plcgetmetric_res> {
public:
	NL60211_PlcGetMetric() { cmdType = NL60211_PLC_GET_METRIC; };
	virtual s32 RunTest(u8 *da)
	{
		MacAddrCopy(pReq->da, da);
		return NL60211_User_Command::RunTest();
	};
	virtual void RecvRes_Verbose()
	{
		PrintClassName();
		printf("MPATH: DA:(HEX)");
		MacAddrPrint(pReq->da);
		printf(", metric:%u\n", pRes->metric);
	};
};

class NL60211_PlcSetMetric : public NL60211_User_Command<struct nl60211_plcsetmetric_req, struct nl60211_plcsetmetric_res> {
public:
	NL60211_PlcSetMetric() { cmdType = NL60211_PLC_SET_METRIC; };
	virtual s32 RunTest(u8 *da, u32 metric)
	{
		MacAddrCopy(pReq->da, da);
		pReq->metric = metric;
		return NL60211_User_Command::RunTest();
	};
};

class NL60211_PlcDumpSta : public NL60211_User_Command<struct nl60211_plcdumpsta_req, struct nl60211_plcdumpsta_res> {
public:
	u32 staNum;
	struct nl60211_plcdumpsta_res staTbl[32];

	NL60211_PlcDumpSta() { cmdType = NL60211_PLC_DUMP_STA; staNum = 0; };
	void FillStaTable(int verbos = 1)
	{
		u32 i;
		s32 *res_return_code;

		staNum = 0;
		SendReq();
		for(i = 0; i < 33; i++) {
			RecvRes_SyncMode();
			CheckResponseHeader();
			res_return_code = (s32 *)pRes;
			if (*res_return_code) {
				break;
			} else {
				if(i == 32) {
					PrintClassName();
					printf(" Error, mpath is more than 32.\n");
					exit(-1);
				}
				memcpy(&staTbl[staNum], pRes, sizeof(struct nl60211_plcdumpsta_res));
				if(verbos) {
					printf("STA(%d) DA:(HEX)", staNum);
					MacAddrPrint(pRes->addr);
					printf("\n");
				}
				staNum++;
			}
		}
	};
	// Return true if found
	int FindSta(u8 *da, u32 *outFoundIndex = NULL)
	{
		u32 i;
		for(i = 0; i < staNum; i++) {
			if (MacAddrIsTheSame(da, staTbl[i].addr)) {
				if (outFoundIndex != NULL)
					*outFoundIndex = i;
				return 1;
			}
		}
		return 0;
	}
};

/*
class NL60211_DumpMpath2 : public NL60211_User_Command<struct nl60211_addmpath_req, struct nl60211_addmpath_res> {
public:
	NL60211_DumpMpath2() { cmdType = NL60211_DUMP_MPATH2; };
};
*/

class NL60211_Recv : public NL60211_User_Command<struct nl60211_recv_req, struct nl60211_recv_res> {
public:
	//u8 *recvBuf;
	NL60211_Recv()
	{
		cmdType = NL60211_RECV;
		pReq->ether_type[0] = 0xAA;
		pReq->ether_type[1] = 0x66;
	};
	//virtual ~NL60211_Recv() {free(recvBuf);};
	/*
	virtual void RecvRes_CopyAddition(u8 *buf)
	{
		struct nl60211_recv_res *res = (struct nl60211_recv_res *)buf;
		memcpy(recvBuf, res->recv_buf, pRes->recv_len);
	};
	*/
	virtual void RecvRes_CopyAddition_Parsing(u8 *buf, u32 *pOutRecvLen, u8 **pOutRecvBuf)
	{
		struct nl60211_recv_res *res = (struct nl60211_recv_res *)buf;
		*pOutRecvBuf = res->recv_buf;
		*pOutRecvLen = res->recv_len;
	};
	virtual void CheckResponseHeader()
	{
		/*
		if (res_nl_msghdr.nlmsg_type != cmdType) {
			PrintClassName();
			printf("Error, nlmsg_type in response! res_nl_msghdr.nlmsg_type=0x%X, cmdType=0x%0X\n",
				res_nl_msghdr.nlmsg_type,
				cmdType);
			exit(-1);
		}
		*/
		if (res_if_idx != if_idx) {
			PrintClassName();
			printf("Error, if_index in response! res_if_idx=%d, if_idx=%d\n",
				res_if_idx,
				if_idx);
			exit(-1);
		}
	};
};

struct nl60211_8023_hdr {
	u8     da[6];
	u8     sa[6];
	u8     ether_type[2];
};

enum nl60211_echo_type {
	NL60211_ECHO_TERMINATE = 0x1313,
	NL60211_ECHO_SAME_DATA,
};

struct nl60211_echo_req {
	u16    echo_type;
	u16    echo_data_len;
	void   *padding;
	u8     echo_data[];
};

struct nl60211_echo_res {
	s32    peer_return_code;
	u16    peer_recv_cmd_type;
	u16    echo_type;
	u16    echo_data_len;
	void   *padding;
	u8     echo_data[];
};

class NL60211_Recv_EchoReq : public NL60211_Recv {
public:
	struct nl60211_8023_hdr *pEchoReqHdr;
	struct nl60211_echo_req *pEchoReq;
	u8 *pEchoReqData;
	virtual void RecvRes_SyncMode()
	{
		u8 *ptr;
		NL60211_Recv::RecvRes_SyncMode();
		ptr = (u8 *)GetResAddiBuf_Safely();
		pEchoReqHdr = (struct nl60211_8023_hdr *)ptr;

		//ptr += sizeof(struct nl60211_8023_hdr);
		ptr += sizeof(struct nl60211_sendplc_req) - sizeof(nl60211_sendplc_req::total_len); //padding compensation!!!!
		//DND(sizeof(struct nl60211_sendplc_req) - sizeof(nl60211_sendplc_req::total_len));
		pEchoReq = (struct nl60211_echo_req *)ptr;

		ptr += sizeof(struct nl60211_echo_req);
		pEchoReqData = ptr;
	};
};

class NL60211_Recv_EchoRes : public NL60211_Recv {
public:
	struct nl60211_8023_hdr *pEchoReqHdr;
	struct nl60211_echo_res *pEchoRes;
	u8 *pEchoResData;
	virtual void RecvRes_SyncMode()
	{
		u8 *ptr;
		NL60211_Recv::RecvRes_SyncMode();
		ptr = (u8 *)GetResAddiBuf_Safely();
		pEchoReqHdr = (struct nl60211_8023_hdr *)ptr;

		//ptr += sizeof(struct nl60211_8023_hdr);
		ptr += sizeof(struct nl60211_sendplc_req) - sizeof(nl60211_sendplc_req::total_len); //padding compensation!!!!
		//DND(sizeof(struct nl60211_sendplc_req) - sizeof(nl60211_sendplc_req::total_len));
		pEchoRes = (struct nl60211_echo_res *)ptr;

		ptr += sizeof(struct nl60211_echo_res);
		pEchoResData = ptr;
	};
};


template <typename REQ, typename RES>
class NL60211_SendCommon : public NL60211_User_Command<REQ, RES> {
public:
	NL60211_SendCommon() { this->reqAddiBuf = (u8 *)malloc(2048); };
	void RevertCopyDaSa(u8 *from, int doCopyEthType = 1)
	{
		struct nl60211_sendplc_req *to = (struct nl60211_sendplc_req *)this->pReq; //template structure
		memcpy(to->da, &(from[6]), 6);
		memcpy(to->sa, &(from[0]), 6);
		if (doCopyEthType) {
			to->ether_type[0] = from[12];
			to->ether_type[1] = from[13];
		}
	};
	void CopyDaSaType(u8 *da, u8 *sa, u16 bigEndType = 0xAA66)
	{
		memcpy(this->pReq->da, da, 6);
		memcpy(this->pReq->sa, sa, 6);
		this->MacAddrPrint(this->pReq->da, 1);
		this->MacAddrPrint(this->pReq->sa, 1);
		this->pReq->ether_type[0] = (u8)(bigEndType >> 8);
		this->pReq->ether_type[1] = (u8)(bigEndType);
	}
	void CopyDaSaFromGlobal()
	{
		CopyDaSaType(g_peer_mac, g_sa);
	}
};

class NL60211_SendBest : public NL60211_SendCommon<struct nl60211_sendbest_req, struct nl60211_sendbest_res> {
public:
	NL60211_SendBest() { cmdType = NL60211_SEND_BEST; };
};

class NL60211_SendPlc : public NL60211_SendCommon<struct nl60211_sendplc_req, struct nl60211_sendplc_res> {
public:
	NL60211_SendPlc() { cmdType = NL60211_SEND_PLC; };
};

class NL60211_SendWifi : public NL60211_SendCommon<struct nl60211_sendwifi_req, struct nl60211_sendwifi_res> {
public:
	NL60211_SendWifi() { cmdType = NL60211_SEND_WIFI; };
};

class NL60211_SendFlood : public NL60211_SendCommon<struct nl60211_sendflood_req, struct nl60211_sendflood_res> {
public:
	NL60211_SendFlood() { cmdType = NL60211_SEND_FLOOD; };
};

class NL60211_Mgr_MeshIdTest : public MyBasics {
public:
	class NL60211_SetMeshId setMeshId;
	class NL60211_GetMeshId getMeshId;
	char old_mesh_id[33];
	char old_mesh_id2[33];
	char new_mesh_id[33];

	NL60211_Mgr_MeshIdTest(){strcpy(new_mesh_id, "mesh996633");};
	void RunTest()
	{
		s32 ret;

		getMeshId.RunTest(old_mesh_id);
		ret = setMeshId.RunTest(new_mesh_id);
		if (ret == 0) {
			getMeshId.RunTest(old_mesh_id2);
			if (strcmp(old_mesh_id2, new_mesh_id) == 0) {
				PrintClassName();
				printf("new mesh id set OK ...\n");
				setMeshId.RunTest(old_mesh_id);
			} else {
				PrintClassName();
				printf("new mesh id set FAILED ...\n");
				exit(-1);
			}
		}
	}
};

class NL60211_Mgr_MpathTest : public MyBasics {
public:
	u8 newMpath[6];
	u8 newMpath2[6];
	u16 newIfId;
	u16 newIfId2;
	
	class NL60211_AddMpath addMpath;
	class NL60211_GetMpath getMpath;
	class NL60211_DelMpath delMpath;
	class NL60211_DumpMpath dumpMpath;

	NL60211_Mgr_MpathTest(){
		u8 addr0[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
		u8 addr1[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
		memcpy(newMpath, addr0, 6);
		memcpy(newMpath2, addr1, 6);
		newIfId = 1;
		newIfId2 = 2;
	};
	void AddInvalidAddrTest()
	{
		u8 invalidAddr[] = {0xFF, 0x11, 0x22, 0x33, 0x44, 0x55};
		PrintClassName();
		printf("Add invalid addr test:\n");
		addMpath.RunFailTest_AddrId(invalidAddr, 1);
	};
	void GetUnknownAddrTest()
	{
		u8 unknownAddr[] = {0x00, 0x11, 0x22, 0x33, 0xF3, 0x4F};
		PrintClassName();
		printf("Get unknown addr test:\n");
		getMpath.RunFailTest_AddrId(unknownAddr, 1);
	};
	void DelUnknownAddrTest()
	{
		u8 unknownAddr[] = {0x00, 0x11, 0x22, 0x33, 0xF3, 0x4F};
		PrintClassName();
		printf("Del unknown addr test:\n");
		delMpath.RunFailTest_AddrId(unknownAddr, 1);
	};
	void RunTest()
	{
		PrintClassName();
		printf(" start ...\n");

		AddInvalidAddrTest();
		GetUnknownAddrTest();
		DelUnknownAddrTest();

		//add mpath 1
		addMpath.RunTest_AddrId(newMpath, newIfId);
		getMpath.RunTest_AddrId(newMpath, newIfId);
		//add mpath 2
		addMpath.RunTest_AddrId(newMpath2, newIfId2);
		getMpath.RunTest_AddrId(newMpath2, newIfId2);

		//dump test, check mpath 1 2 exist
		printf("Dump Mpath test:\n");
		dumpMpath.FillMpathTable();
		if (dumpMpath.FindMpath(newMpath, newIfId) == 0) {
			PrintClassName();
			printf(" Error, dump mpath misses the mpath w/ DA:(HEX)");
			dumpMpath.MacAddrPrint(newMpath, 1);
			exit(-1);
		}
		if (dumpMpath.FindMpath(newMpath2, newIfId2) == 0) {
			PrintClassName();
			printf(" Error, dump mpath misses the mpath w/ DA:(HEX)");
			dumpMpath.MacAddrPrint(newMpath, 1);
			exit(-1);
		}

		//delete test
		delMpath.RunTest_AddrId(newMpath, newIfId);
		getMpath.RunFailTest_AddrId(newMpath, newIfId); //make sure it's deleted
		delMpath.RunTest_AddrId(newMpath2, newIfId2);
		getMpath.RunFailTest_AddrId(newMpath2, newIfId2); //make sure it's deleted

		PrintClassName();
		printf(" end ...\n");
	}
};

static void Self_Test_Util_PingPeer()
{
	u32 i;
	class NL60211_DumpMpath dumpMpath;
	char pingCmd[50];
	sprintf(pingCmd, "ping %d.%d.%d.%d -c 3",
		g_peer_ip[0],
		g_peer_ip[1],
		g_peer_ip[2],
		g_peer_ip[3]);
	system(pingCmd);
	for (i = 0; i < 16; i++) {
		tpr(" : establish mpath of peer node ... (%d)\n", i);
		usleep(500000);
		dumpMpath.FillMpathTable();
		if (dumpMpath.FindMpath(g_peer_mac, 1) == 0)
			continue;
		if (dumpMpath.FindMpath(g_peer_mac, 2) == 0)
			continue;
		return;
	}
	tpr(" : ERROR, establish mpath of peer node ... FAILED\n");
	exit(-1);
}

/*
ECHO REQ:
	send: [da] [sa] [type] AA66 [echo_type] [echo_data_len] [echo_data ...]
	recv:
		nl60211_recv_res
			s32    return_code;
			u32    recv_len;
			u8     recv_buf[];
		resAddiBuf
			[da] [sa] [type] AA66 [echo_type] [echo_data_len] [echo_data ...]

*/
static void Self_Test_Util_Echo_Res_Mode()
{
	class NL60211_Recv_EchoReq recvEcho;
	//class NL60211_Recv recv;
	class NL60211_SendPlc sendPlc;
	//struct nl60211_sendplc_req *cmnSendHdr;
	//struct nl60211_echo_req *pEchoReq;
	struct nl60211_echo_res *pEchoRes;

	pEchoRes = (struct nl60211_echo_res *)sendPlc.reqAddiBuf;

	tpr(": ECHO MODE start!!\n");

	recvEcho.SendReq();

	while (1) {
		tpr(": receive & wait ...\n");
		recvEcho.RecvRes_SyncMode();
		recvEcho.CheckResponseHeader();
		//recv.CheckResponseReturnCode();
		recvEcho.GetResAddiBuf_Safely();
		/*
		printf("RX packet = %X %X %X %X %X %X ...\n",
			recvEcho.resAddiBuf[0],
			recvEcho.resAddiBuf[1],
			recvEcho.resAddiBuf[2],
			recvEcho.resAddiBuf[3],
			recvEcho.resAddiBuf[4],
			recvEcho.resAddiBuf[5]);
		printf("LLC data  = %X %X %X %X %X %X ...\n",
			recvEcho.resAddiBuf[14],
			recvEcho.resAddiBuf[15],
			recvEcho.resAddiBuf[16],
			recvEcho.resAddiBuf[17],
			recvEcho.resAddiBuf[18],
			recvEcho.resAddiBuf[19]);
		*/

		//cmnSendHdr = (struct nl60211_sendplc_req *)recv.GetResAddiBuf_Safely();
		//pEchoReq = (struct nl60211_echo_req *)&(recv.resAddiBuf[sizeof(struct nl60211_sendplc_req)]);//offset

		pEchoRes->peer_return_code = recvEcho.pRes->return_code;
		pEchoRes->peer_recv_cmd_type = recvEcho.res_nl_msghdr.nlmsg_type;
		pEchoRes->echo_type = recvEcho.pEchoReq->echo_type;
		pEchoRes->echo_data_len = 0;
		
		switch (recvEcho.pEchoReq->echo_type) {
		case NL60211_ECHO_TERMINATE:
			tpr(": NL60211_ECHO_TERMINATE !!\n");
			return;
		case NL60211_ECHO_SAME_DATA:
			tpr(": NL60211_ECHO_SAME_DATA !!\n");
			printf("echo data len = %d\n", recvEcho.pEchoReq->echo_data_len);
			printf("(HEX)%02X %02X %02X ...\n",
			       recvEcho.pEchoReq->echo_data[0],
			       recvEcho.pEchoReq->echo_data[1],
			       recvEcho.pEchoReq->echo_data[2]);
			switch (pEchoRes->peer_recv_cmd_type) {
			case NL60211_RECV_PLC:
				printf("rx from plc ...\n");
				break;
			case NL60211_RECV_WIFI:
				printf("rx from wifi ...\n");
				break;
			}
			sendPlc.RevertCopyDaSa(recvEcho.resAddiBuf);
			sendPlc.pReq->total_len = 
				sizeof(struct nl60211_sendplc_req) -
				sizeof(nl60211_sendplc_req::total_len) +
				sizeof(struct nl60211_echo_res) +
				recvEcho.pEchoReq->echo_data_len;
			pEchoRes->echo_data_len = recvEcho.pEchoReq->echo_data_len;
			memcpy(pEchoRes->echo_data, recvEcho.pEchoReq->echo_data, recvEcho.pEchoReq->echo_data_len);
			sendPlc.reqAddiBufLen = sizeof(struct nl60211_echo_res) + recvEcho.pEchoReq->echo_data_len;
			sendPlc.SendReq();
			sendPlc.RecvRes_SyncMode();
			sendPlc.CheckResponseHeader();
			sendPlc.CheckResponseReturnCode();
			break;
		default:
			tpr(": Unknown echo_typ = 0x%X !!!\n", recvEcho.pEchoReq->echo_type);
			break;
		}
	}
}

/*
ECHO REQ:
	send: [da] [sa] [type] AA66 [echo_type] [echo_data_len] [echo_data ...]
	recv:
		nl60211_recv_res
			s32    return_code;
			u32    recv_len;
			u8     recv_buf[];
		resAddiBuf
			[da] [sa] [type] AA66 [echo_type] [echo_data_len] [echo_data ...]

*/
static void Self_Test_Util_Echo_Req_SendPlc()
{
	u8 testData[] = {0x33, 0x34, 0x35};
	class NL60211_SendPlc sender;
	struct nl60211_echo_req *pEchoReq;
	u8 *pEchoData;

	tpr(" : START ... \n");
	sender.CopyDaSaFromGlobal();

	pEchoReq = (struct nl60211_echo_req *)sender.GetReqAddiBuf_Safely();
	pEchoReq->echo_type = NL60211_ECHO_SAME_DATA;
	pEchoReq->echo_data_len = sizeof(testData);
	pEchoData = (u8 *)pEchoReq;
	pEchoData += sizeof(struct nl60211_echo_req); //offset
	memcpy(pEchoData, testData, sizeof(testData));

	sender.pReq->total_len = 
		sizeof(struct nl60211_sendplc_req) +
		sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;
	sender.reqAddiBufLen = sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;

	sender.Run();
	tpr("receiving echo res ...\n");
	{
		u16 i;
		class NL60211_Recv_EchoRes recvEchoRes;

		recvEchoRes.Run();
		printf("peer_return_code   = %d\n", recvEchoRes.pEchoRes->peer_return_code);
		printf("peer_recv_cmd_type = 0x%04X\n", recvEchoRes.pEchoRes->peer_recv_cmd_type);
		printf("echo_type          = 0x%X\n", recvEchoRes.pEchoRes->echo_type);
		printf("echo_data_len      = 0x%X\n", recvEchoRes.pEchoRes->echo_data_len);
		if (recvEchoRes.pEchoRes->echo_type == NL60211_ECHO_SAME_DATA) {
			printf("echo_data =(HEX)\n");
			for (i = 0; i < recvEchoRes.pEchoRes->echo_data_len; i++) {
				printf("%02X ", recvEchoRes.pEchoResData[i]);
			}
			printf("\n");
		}
		if (recvEchoRes.pEchoRes->peer_recv_cmd_type != NL60211_RECV_PLC) {
			tpr(" : Error, peer_recv_cmd_type should be %d (%d)\n", NL60211_RECV_PLC, recvEchoRes.pEchoRes->peer_recv_cmd_type);
			exit(-1);
		}
		if (recvEchoRes.pEchoRes->echo_data_len != sizeof(testData)) {
			tpr(" : Error, echo_data_len error! (%d, %lu)\n", recvEchoRes.pEchoRes->echo_data_len, sizeof(testData));
			exit(-1);
		}
		if (memcmp(testData, recvEchoRes.pEchoResData, sizeof(testData)) != 0) {
			tpr(" : Error, pEchoResData mismatch!\n");
			exit(-1);
		}
	}
	tpr(" : END ... \n");
}

static void Self_Test_Util_Echo_Req_SendWifi()
{
	u8 testData[] = {0x44, 0x45, 0x46, 0x47};
	class NL60211_SendWifi sender;
	struct nl60211_echo_req *pEchoReq;
	u8 *pEchoData;

	tpr(" : START ... \n");
	sender.CopyDaSaFromGlobal();

	pEchoReq = (struct nl60211_echo_req *)sender.GetReqAddiBuf_Safely();
	pEchoReq->echo_type = NL60211_ECHO_SAME_DATA;
	pEchoReq->echo_data_len = sizeof(testData);
	pEchoData = (u8 *)pEchoReq;
	pEchoData += sizeof(struct nl60211_echo_req); //offset
	memcpy(pEchoData, testData, sizeof(testData));

	sender.pReq->total_len = 
		sizeof(struct nl60211_sendwifi_req) +
		sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;
	sender.reqAddiBufLen = sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;

	sender.Run();
	tpr("receiving echo res ...\n");
	{
		u16 i;
		class NL60211_Recv_EchoRes recvEchoRes;

		recvEchoRes.Run();
		printf("peer_return_code   = %d\n", recvEchoRes.pEchoRes->peer_return_code);
		printf("peer_recv_cmd_type = 0x%04X\n", recvEchoRes.pEchoRes->peer_recv_cmd_type);
		printf("echo_type          = 0x%X\n", recvEchoRes.pEchoRes->echo_type);
		printf("echo_data_len      = 0x%X\n", recvEchoRes.pEchoRes->echo_data_len);
		if (recvEchoRes.pEchoRes->echo_type == NL60211_ECHO_SAME_DATA) {
			printf("echo_data =(HEX)\n");
			for (i = 0; i < recvEchoRes.pEchoRes->echo_data_len; i++) {
				printf("%02X ", recvEchoRes.pEchoResData[i]);
			}
			printf("\n");
		}
		if (recvEchoRes.pEchoRes->peer_recv_cmd_type != NL60211_RECV_WIFI) {
			tpr(" : Error, peer_recv_cmd_type should be %d (%d)\n", NL60211_RECV_WIFI, recvEchoRes.pEchoRes->peer_recv_cmd_type);
			exit(-1);
		}
		if (recvEchoRes.pEchoRes->echo_data_len != sizeof(testData)) {
			tpr(" : Error, echo_data_len error! (%d, %lu)\n", recvEchoRes.pEchoRes->echo_data_len, sizeof(testData));
			exit(-1);
		}
		if (memcmp(testData, recvEchoRes.pEchoResData, sizeof(testData)) != 0) {
			tpr(" : Error, pEchoResData mismatch!\n");
			exit(-1);
		}
	}
	tpr(" : END ... \n");
}

static void Self_Test_Util_Echo_Req_SendBest()
{
	u8 testData[] = {0x55, 0x56, 0x57, 0x58};
	class NL60211_SendBest sender;
	struct nl60211_echo_req *pEchoReq;
	u8 *pEchoData;

	tpr(" : START ... \n");
	sender.CopyDaSaFromGlobal();

	pEchoReq = (struct nl60211_echo_req *)sender.GetReqAddiBuf_Safely();
	pEchoReq->echo_type = NL60211_ECHO_SAME_DATA;
	pEchoReq->echo_data_len = sizeof(testData);
	pEchoData = (u8 *)pEchoReq;
	pEchoData += sizeof(struct nl60211_echo_req); //offset
	memcpy(pEchoData, testData, sizeof(testData));

	sender.pReq->total_len = 
		sizeof(struct nl60211_sendbest_req) +
		sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;
	sender.reqAddiBufLen = sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;

	sender.Run();
	tpr("receiving echo res ...\n");
	{
		u16 i;
		class NL60211_Recv_EchoRes recvEchoRes;

		recvEchoRes.Run();
		printf("peer_return_code   = %d\n", recvEchoRes.pEchoRes->peer_return_code);
		printf("peer_recv_cmd_type = 0x%04X\n", recvEchoRes.pEchoRes->peer_recv_cmd_type);
		printf("echo_type          = 0x%X\n", recvEchoRes.pEchoRes->echo_type);
		printf("echo_data_len      = 0x%X\n", recvEchoRes.pEchoRes->echo_data_len);
		if (recvEchoRes.pEchoRes->echo_type == NL60211_ECHO_SAME_DATA) {
			printf("echo_data =(HEX)\n");
			for (i = 0; i < recvEchoRes.pEchoRes->echo_data_len; i++) {
				printf("%02X ", recvEchoRes.pEchoResData[i]);
			}
			printf("\n");
		}
		//if (recvEchoRes.pEchoRes->peer_recv_cmd_type != NL60211_RECV) {
		//	tpr(" : Error, peer_recv_cmd_type should be %d (%d)\n", NL60211_RECV, recvEchoRes.pEchoRes->peer_recv_cmd_type);
		//	exit(-1);
		//}
		if (recvEchoRes.pEchoRes->echo_data_len != sizeof(testData)) {
			tpr(" : Error, echo_data_len error! (%d, %lu)\n", recvEchoRes.pEchoRes->echo_data_len, sizeof(testData));
			exit(-1);
		}
		if (memcmp(testData, recvEchoRes.pEchoResData, sizeof(testData)) != 0) {
			tpr(" : Error, pEchoResData mismatch!\n");
			exit(-1);
		}
	}
	tpr(" : END ... \n");
}
/*
static void Self_Test_Util_Echo_Req_SendFlood()
{
	u8 testData[] = {0x66, 0x67, 0x68, 0x69};
	class NL60211_SendFlood sender;
	struct nl60211_echo_req *pEchoReq;
	class NL60211_Recv_EchoRes recvEchoRes;
	u8 *pEchoData;

	tpr(" : START ... \n");
	sender.CopyDaSaFromGlobal();

	pEchoReq = (struct nl60211_echo_req *)sender.GetReqAddiBuf_Safely();
	pEchoReq->echo_type = NL60211_ECHO_SAME_DATA;
	pEchoReq->echo_data_len = sizeof(testData);
	pEchoData = (u8 *)pEchoReq;
	pEchoData += sizeof(struct nl60211_echo_req); //offset
	memcpy(pEchoData, testData, sizeof(testData));

	sender.pReq->total_len = 
		sizeof(struct nl60211_sendflood_req) +
		sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;
	sender.reqAddiBufLen = sizeof(struct nl60211_echo_req) +
		pEchoReq->echo_data_len;

	sender.Run();
	tpr("receiving echo res  1111 ...\n");
	{
		u16 i;

		recvEchoRes.Run();
		printf("peer_return_code   = %d\n", recvEchoRes.pEchoRes->peer_return_code);
		printf("peer_recv_cmd_type = 0x%04X\n", recvEchoRes.pEchoRes->peer_recv_cmd_type);
		printf("echo_type          = 0x%X\n", recvEchoRes.pEchoRes->echo_type);
		printf("echo_data_len      = 0x%X\n", recvEchoRes.pEchoRes->echo_data_len);
		if (recvEchoRes.pEchoRes->echo_type == NL60211_ECHO_SAME_DATA) {
			printf("echo_data =(HEX)\n");
			for (i = 0; i < recvEchoRes.pEchoRes->echo_data_len; i++) {
				printf("%02X ", recvEchoRes.pEchoResData[i]);
			}
			printf("\n");
		}
		//if (recvEchoRes.pEchoRes->peer_recv_cmd_type != NL60211_RECV) {
		//	tpr(" : Error, peer_recv_cmd_type should be %d (%d)\n", NL60211_RECV, recvEchoRes.pEchoRes->peer_recv_cmd_type);
		//	exit(-1);
		//}
		if (recvEchoRes.pEchoRes->echo_data_len != sizeof(testData)) {
			tpr(" : Error, echo_data_len error! (%d, %lu)\n", recvEchoRes.pEchoRes->echo_data_len, sizeof(testData));
			exit(-1);
		}
		if (memcmp(testData, recvEchoRes.pEchoResData, sizeof(testData)) != 0) {
			tpr(" : Error, pEchoResData mismatch!\n");
			exit(-1);
		}
	}
	tpr("receiving echo res  2222 ...\n");
	{
		u16 i;

		recvEchoRes.RecvRes_SyncMode();
		recvEchoRes.CheckResponseHeader();
		recvEchoRes.CheckResponseReturnCode();
		printf("peer_return_code   = %d\n", recvEchoRes.pEchoRes->peer_return_code);
		printf("peer_recv_cmd_type = 0x%04X\n", recvEchoRes.pEchoRes->peer_recv_cmd_type);
		printf("echo_type          = 0x%X\n", recvEchoRes.pEchoRes->echo_type);
		printf("echo_data_len      = 0x%X\n", recvEchoRes.pEchoRes->echo_data_len);
		if (recvEchoRes.pEchoRes->echo_type == NL60211_ECHO_SAME_DATA) {
			printf("echo_data =(HEX)\n");
			for (i = 0; i < recvEchoRes.pEchoRes->echo_data_len; i++) {
				printf("%02X ", recvEchoRes.pEchoResData[i]);
			}
			printf("\n");
		}
		//if (recvEchoRes.pEchoRes->peer_recv_cmd_type != NL60211_RECV) {
		//	tpr(" : Error, peer_recv_cmd_type should be %d (%d)\n", NL60211_RECV, recvEchoRes.pEchoRes->peer_recv_cmd_type);
		//	exit(-1);
		//}
		if (recvEchoRes.pEchoRes->echo_data_len != sizeof(testData)) {
			tpr(" : Error, echo_data_len error! (%d, %lu)\n", recvEchoRes.pEchoRes->echo_data_len, sizeof(testData));
			exit(-1);
		}
		if (memcmp(testData, recvEchoRes.pEchoResData, sizeof(testData)) != 0) {
			tpr(" : Error, pEchoResData mismatch!\n");
			exit(-1);
		}
	}
	tpr(" : END ... \n");
}
*/
static void Self_Test_Util_Read_SA()
{
	class NL60211_GetSa getSa;

	getSa.Run();
	getSa.RecvRes_Verbose();
	memcpy(g_sa, getSa.resAddiBuf, 6);
}

static void Self_Test_Util_Read_Peer_Info()
{
#define PEER_INFO_FILE "peer_info.txt"
#define PEER_MAC_STR "peer_mac(hex):"
#define PEER_IP_STR "peer_ip:"

	u32 i;
	FILE *fp;
	char scanStr[100];
	u32 tempU32;

	tpr(": local test ... ((( START )))\n");

	fp = fopen(PEER_INFO_FILE, "r+b"); 

	if (fp == NULL) { 
		tpr(" Error. Cannot open: %s.  Exit Now!\n", PEER_INFO_FILE);
		exit(-1);
	}

	if (fscanf(fp, "%s", scanStr) == 0) {
		printf(" Error, peer_mac name scan error!\n");
		exit(-1);
	}

	if (strcmp(scanStr, PEER_MAC_STR) != 0) {
		printf(" Error, peer_mac name string not match!\n");
		exit(-1);
	}
	printf("%s =\n", PEER_MAC_STR);
	for (i = 0; i < 6; i++) {
		if (fscanf(fp, "%x", &tempU32) == 0) {
			printf(" Error, peer_mac scan error in %d bytes!\n", i);
			exit(-1);
		}
		g_peer_mac[i] = (u8)tempU32;
		printf("%X ", g_peer_mac[i]);
		if (i==5)
			printf("\n");
	}

	if (fscanf(fp, "%s", scanStr) == 0) {
		printf(" Error, peer_ip name scan error!\n");
		exit(-1);
	}

	if (strcmp(scanStr, PEER_IP_STR) != 0) {
		printf(" Error, peer_ip name string not match!\n");
		exit(-1);
	}
	printf("%s =\n", PEER_IP_STR);
	for (i = 0; i < 4; i++) {
		if (fscanf(fp, "%u", &tempU32) == 0) {
			printf(" Error, peer_ip scan error in %d bytes!\n", i);
			exit(-1);
		}
		g_peer_ip[i] = (u8)tempU32;
		printf("%d ", g_peer_ip[i]);
		if (i==3)
			printf("\n");
	}
	fclose(fp);
}

static void Self_Test_001()
{
	class NL60211_Mgr_MeshIdTest meshIdTest;
	class NL60211_GetVersion getVersion;
	class NL60211_GetSa getSa;
	class NL60211_Mgr_MpathTest mpathTest;

	tpr(": local test ... ((( START )))\n");

	getVersion.RunTest();

	meshIdTest.RunTest();

	getSa.RunTest();

	mpathTest.RunTest();

	tpr(": local test ... ((( ALL PASS )))\n");
}

static void Self_Test_002()
{
	class NL60211_SetRPD setRPD;
	class NL60211_GetRPD getRPD;
	u8 recvPortDetect = 0;
	setRPD.Set(1);
	getRPD.Get(&recvPortDetect);
	if (recvPortDetect != 1) {
		//PrintClassName();
		printf(" Error, recvPortDetect set error, should be 1. (%d)\n", recvPortDetect);
		exit(-1);
	}
	Self_Test_Util_Echo_Res_Mode();
}

static void Self_Test_003()
{
	class NL60211_PlcSetMetric plcSetMetric;
	class NL60211_PlcGetMetric plcGetMetric;
	Self_Test_Util_Read_SA();
	Self_Test_Util_Read_Peer_Info();
	{
		u32 i;
		class NL60211_PlcDumpSta plcDumpSta;
		for (i = 0; i < 16; i++) {
			tpr(" : NL60211_PlcDumpSta ... (%d)\n", i);
			usleep(500000);
			plcDumpSta.FillStaTable();
			if (plcDumpSta.staNum != 0) {
				if (plcDumpSta.FindSta(g_peer_mac))
					break;
			}
		}
		if (i == 16) {
			tpr(" : Error, can't find plc sta ...\n");
			exit(-1);
		}
	}
	Self_Test_Util_PingPeer();
	Self_Test_Util_Echo_Req_SendPlc();
	Self_Test_Util_Echo_Req_SendWifi();
	Self_Test_Util_Echo_Req_SendBest();
	//Self_Test_Util_Echo_Req_SendFlood();
	plcSetMetric.RunTest(g_peer_mac, 20000);
	plcGetMetric.RunTest(g_peer_mac);
	Self_Test_Util_Echo_Req_SendBest();
}


void self_test_proc(u32 ctrl_code, unsigned int if_idx)
{
	g_if_idx_from_shell_input = if_idx;
	switch(ctrl_code)
	{
		case NL60211_CTRL_SELF_TEST_001:
			Self_Test_001();
			break;
		case NL60211_CTRL_SELF_TEST_002:
			Self_Test_002();
			break;
		case NL60211_CTRL_SELF_TEST_003:
			Self_Test_003();
			break;
		case NL60211_CTRL_SELF_TEST_004:
			break;
		default:
			break;
	}
}

