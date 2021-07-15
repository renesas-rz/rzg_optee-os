/*
 * Copyright (c) 2021, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RPC_FOR_QSPI_H_
#define RPC_FOR_QSPI_H_

#define RPC_BASE	(0xEE200000U)
//RPC register offset
#define RPC_CMNCR	(0x0000U)
#define RPC_SSLDR	(0x0004U)
#define RPC_DRCR	(0x000CU)
#define RPC_DRCMR	(0x0010U)
#define RPC_DREAR	(0x0014U)
#define RPC_DRENR	(0x001CU)
#define RPC_SMCR	(0x0020U)
#define RPC_SMCMR	(0x0024U)
#define RPC_SMADR	(0x0028U)
#define RPC_SMENR	(0x0030U)
#define RPC_SMRDR0	(0x0038U)
#define RPC_SMWDR0	(0x0040U)
#define RPC_CMNSR	(0x0048U)
#define RPC_DRDMCR	(0x0058U)
#define RPC_DRDRENR	(0x005CU)
#define RPC_SMDMCR	(0x0060U)
#define RPC_SMDRENR	(0x0064U)
#define RPC_PHYCNT	(0x007CU)
#define RPC_PHYINT	(0x0088U)
#define RPC_WRBUF	(0x8000U)

#define	CPG_BASE    (0xE6150000U)
#define CPG_CPGWPR	(0x0900U)
#define CPG_RPCCKCR (0x0238U)

//MSTPRST register offset
#define	CPG_SRCR9	(0x0924U)
#define	CPG_SRSTCLR9    (0x0964U)
#define	CPG_MSTPSR9 (0x09A4U)
#define CPG_SMSTPCR9    (0x0994U)


#define	PRR				    (0xFFF00044U)	// R	32	Product Register
#define PRR_PRODUCT_MASK    (0x00007F00U)
#define PRR_CUT_MASK		(0x000000FFU)
#define PRR_PRODUCT_G2H		(0x00004F00U)	/* RZ/G2H	*/
#define PRR_PRODUCT_G2M		(0x00005200U)	/* RZ/G2M 	*/
#define PRR_PRODUCT_G2N		(0x00005500U)	/* RZ/G2N 	*/
#define PRR_PRODUCT_G2E		(0x00005700U)	/* RZ/G2E	*/

#define PRR_CUT_10  (0x00U)		/* Ver.1.0	*/
#define PRR_CUT_11	(0x01U)		/* Ver.1.1	*/
#define PRR_CUT_20	(0x10U)		/* Ver.2.0	*/
#define PRR_CUT_30	(0x20U)		/* Ver.3.0	*/

#define	RZG2M_CUT_11    (0x10)		/* Ver.1.1/1.2	*/

#define		BIT0	0x00000001
#define		BIT1	0x00000002
#define		BIT2	0x00000004
#define		BIT3	0x00000008
#define		BIT4	0x00000010
#define		BIT5	0x00000020
#define		BIT6	0x00000040
#define		BIT7	0x00000080
#define		BIT8	0x00000100
#define		BIT9	0x00000200
#define		BIT10	0x00000400
#define		BIT11	0x00000800
#define		BIT12	0x00001000
#define		BIT13	0x00002000
#define		BIT14	0x00004000
#define		BIT15	0x00008000
#define		BIT16	0x00010000
#define		BIT17	0x00020000
#define		BIT18	0x00040000
#define		BIT19	0x00080000
#define		BIT20	0x00100000
#define		BIT21	0x00200000
#define		BIT22	0x00400000
#define		BIT23	0x00800000
#define		BIT24	0x01000000
#define		BIT25	0x02000000
#define		BIT26	0x04000000
#define		BIT27	0x08000000
#define		BIT28	0x10000000
#define		BIT29	0x20000000
#define		BIT30	0x40000000
#define		BIT31	0x80000000

void rzg_rpc_manual_mode_init(void);
void rzg_rpc_read_ext_mode_init(void);
void rzg_rpc_reset(void);
void rzg_rpc_erase_sector(uint32_t sector_addr);
void rzg_rpc_write_buff(uint32_t addr, uint64_t source_addr);
void rzg_rpc_read_status(uint32_t *readData);
void rzg_rpc_write_cmd(uint32_t command);
void rzg_rpc_power_on(void);
void rzg_rpc_power_off(void);

#endif /* RPC_FOR_QSPI_H_ */
