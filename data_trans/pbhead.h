#ifndef _PBHEAD_H_
#define _PBHEAD_H_

struct PBCmdHeader_
{
	unsigned int m_cmdNum;
	unsigned int m_cmdSeq;
	unsigned int m_reserve;
};

struct PBReqHeader_ 
{
	struct PBCmdHeader_ m_header;
	unsigned int m_srcId;
	unsigned int m_session;
};



#endif
