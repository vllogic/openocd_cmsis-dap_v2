

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <helper/binarybuffer.h>
#include <helper/bits.h>
#include <helper/time_support.h>
#include <target/algorithm.h>
#include <target/armv7m.h>
#include <target/image.h>
#include "at32qspi.h"
#include "sfdp.h"

/* deprecated */
#define CMD_W0_OFFSET                     0x00
#define CMD_W1_OFFSET                     0x04
#define CMD_W2_OFFSET                     0x08
#define CMD_W3_OFFSET                     0x0C
#define CTRL_OFFSET                           0x10
#define FIFOSTS_OFFSET                     0x18
#define CTRL2_OFFSET                         0x20
#define CMDSTS_OFFSET                      0x24
#define RSTS_OFFSET                           0x28
#define FSIZE_OFFSET                         0x2C
#define XIP_CMD_W0_OFFSET             0x30
#define XIP_CMD_W1_OFFSET             0x34
#define XIP_CMD_W2_OFFSET             0x38
#define XIP_CMD_W3_OFFSET             0x3C
#define CTRL3_OFFSET                        0x40
#define REV_OFFSET                            0x50
#define DT_OFFSET                              0x100

#define AT32_QSPI_REG(offset)          ((at32_qspi_info->base_addr+offset))

#define AT32_QSPI1_BASE_ADDR      0xA0001000
#define AT32_QSPI2_BASE_ADDR      0xA0002000

#define QSPI_OPERATE_TIMEOUT       0x100
#define QSPI_WAIT_TIMEOUT          0x100
#define QSPI_TXFIFORDY_TIMEOUT     0x100
#define QSPI_RXFIFORDY_TIMEOUT     0x100
#define QSPI_SEND_DATA_TIMEOUT     0x100
#define QSPI_ERASE_SECTOR_TIMEOUT  0x1000
#define QSPI_ERASE_BLOCK_TIMEOUT   0x10000
#define QSPI_ERASE_CHIP_TIMEOUT    0x800000

#define  QSPI_SECTOR_SIZE   0x1000
#define  QSPI_PAGE_SIZE       0x100
#define  QSPI_BLOCK_SIZE    0x10000




typedef enum
{
  QSPI_CMD_INSLEN_0_BYTE                 = 0x00, /*!< qspi no instruction code */
  QSPI_CMD_INSLEN_1_BYTE                 = 0x01, /*!< qspi instruction code 1 byte */
  QSPI_CMD_INSLEN_2_BYTE                 = 0x02  /*!< qspi instruction code 2 byte(repeat) */
} qspi_cmd_inslen_type;

/**
  * @brief qspi command port address length type
  */
typedef enum
{
  QSPI_CMD_ADRLEN_0_BYTE                 = 0x00, /*!< qspi  no address */
  QSPI_CMD_ADRLEN_1_BYTE                 = 0x01, /*!< qspi  address length 1 byte */
  QSPI_CMD_ADRLEN_2_BYTE                 = 0x02, /*!< qspi  address length 2 byte */
  QSPI_CMD_ADRLEN_3_BYTE                 = 0x03, /*!< qspi  address length 3 byte */
  QSPI_CMD_ADRLEN_4_BYTE                 = 0x04  /*!< qspi  address length 4 byte */
} qspi_cmd_adrlen_type;

/**
  * @brief qspi operate mode type
  */
typedef enum
{
  QSPI_OPERATE_MODE_111                  = 0x00, /*!< qspi serial mode */
  QSPI_OPERATE_MODE_112                  = 0x01, /*!< qspi dual mode */
  QSPI_OPERATE_MODE_114                  = 0x02, /*!< qspi quad mode */
  QSPI_OPERATE_MODE_122                  = 0x03, /*!< qspi dual i/o mode */
  QSPI_OPERATE_MODE_144                  = 0x04, /*!< qspi quad i/o mode */
  QSPI_OPERATE_MODE_222                  = 0x05, /*!< qspi instruction 2-bit mode */
  QSPI_OPERATE_MODE_444                  = 0x06  /*!< qspi instruction 4-bit mode(qpi) */
} qspi_operate_mode_type;

/**
  * @brief qspi read status configure type
  */
typedef enum
{
  QSPI_RSTSC_HW_AUTO                     = 0x00, /*!< qspi read status by hardware */
  QSPI_RSTSC_SW_ONCE                     = 0x01  /*!< qspi read status by software */
} qspi_read_status_conf_type;

/**
  * @brief qspi cmd type
  */
typedef struct
{
  uint8_t                                pe_mode_enable;          /*!< performance enhance mode enable */
  uint8_t                                pe_mode_operate_code;    /*!< performance enhance mode operate code */
  uint8_t                                instruction_code;        /*!< instruction code */
  qspi_cmd_inslen_type           instruction_length;      /*!< instruction code length */
  uint32_t                               address_code;            /*!< address code */
  qspi_cmd_adrlen_type           address_length;          /*!< address legnth */
  uint32_t                               data_counter;            /*!< read/write data counter */
  uint8_t                                second_dummy_cycle_num;  /*!< number of second dummy state cycle 0~32 */
  qspi_operate_mode_type                 operation_mode;          /*!< operation mode */
  qspi_read_status_conf_type             read_status_config;      /*!< config to read status */
  uint8_t                          read_status_enable;      /*!< config to read status */
  uint8_t                          write_data_enable;       /*!< enable to write data */
} at32_qspi_cmd_type;


/**
  * @brief qspi xip r/w address length type
  */
typedef enum
{
  QSPI_XIP_ADDRLEN_3_BYTE                = 0x00, /*!< qspi xip address length 3 byte */
  QSPI_XIP_ADDRLEN_4_BYTE                = 0x01  /*!< qspi xip address length 4 byte */
} qspi_xip_addrlen_type;


/**
  * @brief qspi xip write access mode type
  */
typedef enum
{
  QSPI_XIPW_SEL_MODED                    = 0x00, /*!< qspi xip write select mode d */
  QSPI_XIPW_SEL_MODET                    = 0x01  /*!< qspi xip write select mode t */
} qspi_xip_write_sel_type;

/**
  * @brief qspi xip read access mode type
  */
typedef enum
{
  QSPI_XIPR_SEL_MODED                    = 0x00, /*!< qspi xip read select mode d */
  QSPI_XIPR_SEL_MODET                    = 0x01  /*!< qspi xip read select mode t */
} qspi_xip_read_sel_type;

/**
  * @brief qspi xip type
  */
typedef struct
{
  uint8_t                                read_instruction_code;         /*!< read instruction code */
  qspi_xip_addrlen_type                  read_address_length;           /*!< read address legnth */
  qspi_operate_mode_type                 read_operation_mode;           /*!< read operation mode */
  uint8_t                                read_second_dummy_cycle_num;   /*!< read number of second dummy state cycle 0~32 */
  uint8_t                                write_instruction_code;        /*!< write instruction code */
  qspi_xip_addrlen_type                  write_address_length;          /*!< write address legnth */
  qspi_operate_mode_type                 write_operation_mode;          /*!< write operation mode */
  uint8_t                                write_second_dummy_cycle_num;  /*!< write number of second dummy state cycle 0~32 */
  qspi_xip_write_sel_type                write_select_mode;             /*!< write mode d or mode t selection */
  uint8_t                                write_time_counter;            /*!< write count for mode t */
  uint8_t                                write_data_counter;            /*!< write count for mode d */
  qspi_xip_read_sel_type                 read_select_mode;              /*!< read mode d or mode t selection */
  uint8_t                                read_time_counter;             /*!< read count for mode t */
  uint8_t                                read_data_counter;             /*!< read count for mode d */
} at32_qspi_xip_type;

#if 1
/* cmd read parameters, the address_code and data_counter need to be set in application */
static  at32_qspi_cmd_type qspi_read_para = {
0,0,0xEB,QSPI_CMD_INSLEN_1_BYTE,0,QSPI_CMD_ADRLEN_3_BYTE,0,6,QSPI_OPERATE_MODE_144,QSPI_RSTSC_HW_AUTO,0,0};

/* cmd write parameters, the address_code and data_counter need to be set in application */
static  at32_qspi_cmd_type qspi_write_para = {
0,0,0x32,QSPI_CMD_INSLEN_1_BYTE,0,QSPI_CMD_ADRLEN_3_BYTE,0,0,QSPI_OPERATE_MODE_114,QSPI_RSTSC_HW_AUTO,0,1};
#endif
/*  cmd sector erase parameters, the address_code need to be set in application */
static  at32_qspi_cmd_type qspi_erase_para = {
0,0,0x20,QSPI_CMD_INSLEN_1_BYTE,0,QSPI_CMD_ADRLEN_3_BYTE,0,0,QSPI_OPERATE_MODE_111,QSPI_RSTSC_HW_AUTO,0,1};

#if 1
/*  cmd wren parameters */
static  at32_qspi_cmd_type qspi_wren_para = {
0,0,SPIFLASH_WRITE_ENABLE,QSPI_CMD_INSLEN_1_BYTE,0,QSPI_CMD_ADRLEN_0_BYTE,0,0,QSPI_OPERATE_MODE_111,QSPI_RSTSC_HW_AUTO,0,1};

/*  cmd rdsr parameters */
static  at32_qspi_cmd_type qspi_rdsr_para = {
0,0,SPIFLASH_READ_STATUS,QSPI_CMD_INSLEN_1_BYTE,0,QSPI_CMD_ADRLEN_0_BYTE,0,0,QSPI_OPERATE_MODE_111,QSPI_RSTSC_HW_AUTO,1,0};
#endif

/*  cmd mass erase parameters, the address_code need to be set in application */
static  at32_qspi_cmd_type qspi_mass_erase_para = {
0,0,SPIFLASH_MASS_ERASE,QSPI_CMD_INSLEN_1_BYTE,0,QSPI_CMD_ADRLEN_0_BYTE,0,0,QSPI_OPERATE_MODE_111,QSPI_RSTSC_HW_AUTO,0,1};

/*  xip parameters */
static  at32_qspi_xip_type qspi_xip_para = {
0x6B, 
QSPI_XIP_ADDRLEN_3_BYTE ,
QSPI_OPERATE_MODE_114, 
8, 
0x32, 
QSPI_XIP_ADDRLEN_3_BYTE,
QSPI_XIP_ADDRLEN_3_BYTE, 
0, 
QSPI_XIPW_SEL_MODED, 
0x7F, 
0x1F, 
QSPI_XIPR_SEL_MODED, 
0x7F, 
0x1F};
 
#undef SPIFLASH_READ
#undef SPIFLASH_PAGE_PROGRAM

#define SPI_ADSIZE (((at32_qspi_info->saved_ccr >> SPI_ADSIZE_POS) & 0x3) + 1)

#define OPI_CMD(cmd) ((OPI_MODE ? ((((uint16_t)(cmd)) << 8) | (~(cmd) & 0xFFU)) : (cmd)))

/* convert uint32_t into 4 uint8_t in little endian byte order */
static inline uint32_t h_to_le_32(uint32_t val)
{
	uint32_t result;

	h_u32_to_le((uint8_t *)&result, val);
	return result;
}

/* Timeout in ms */
#define SPI_CMD_TIMEOUT			(100)
#define SPI_PROBE_TIMEOUT		(100)
#define SPI_MAX_TIMEOUT			(2000)
#define SPI_MASS_ERASE_TIMEOUT	(400000)

struct sector_info {
	uint32_t offset;
	uint32_t size;
	uint32_t result;
};

struct at32_qspi_flash_bank {
	bool probed;
	char devname[32];
	bool octo;
	struct flash_device dev;
	uint32_t base_addr;
	uint32_t flash_addr;
	uint32_t saved_cr;	/* in particular FSEL, DFM bit mask in QUADSPI_CR *AND* OCTOSPI_CR */
	uint32_t saved_ccr; /* different meaning for QUADSPI and OCTOSPI */
	uint32_t saved_tcr;	/* only for OCTOSPI */
	uint32_t saved_ir;	/* only for OCTOSPI */
	unsigned int sfdp_dummy1;	/* number of dummy bytes for SFDP read for flash1 and octo */
	unsigned int sfdp_dummy2;	/* number of dummy bytes for SFDP read for flash2 */
	uint32_t qspi_en;
	uint32_t flash_id;
	uint32_t sector_size;
	uint32_t p_page_size;

	at32_qspi_xip_type xip_struct;
	at32_qspi_cmd_type cmd_struct;
	
};



FLASH_BANK_COMMAND_HANDLER(at32qspi_flash_bank_command)
{
	struct at32_qspi_flash_bank *at32_qspi_info;
	uint32_t base_addr;
	uint8_t qspi_cmd;

	LOG_DEBUG("%s", __func__);

	if (CMD_ARGC < 7)
		return ERROR_COMMAND_SYNTAX_ERROR;

	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[6], base_addr);
	LOG_INFO("CMD_ARGC %d, base_addr = 0x%x", CMD_ARGC, base_addr);
#if 1
	if (CMD_ARGC > 7)
	{
		COMMAND_PARSE_NUMBER(u8, CMD_ARGV[7], qspi_cmd);
		/* Read command */
		qspi_read_para.instruction_code = qspi_cmd;
		LOG_INFO("READ command 0x%x", qspi_cmd);
		
	}

	if (CMD_ARGC > 8)
	{
		COMMAND_PARSE_NUMBER(u8, CMD_ARGV[8], qspi_cmd);
		/* Read command */
		qspi_write_para.instruction_code = qspi_cmd;
		LOG_INFO("Write command 0x%x", qspi_cmd);
		
	}

	if (CMD_ARGC > 9)
	{
		COMMAND_PARSE_NUMBER(u8, CMD_ARGV[9], qspi_cmd);
		/* Read command */
		qspi_erase_para.instruction_code = qspi_cmd;
		LOG_INFO("Erase command 0x%x", qspi_cmd);
		
	}

	if (CMD_ARGC > 10)
	{
		COMMAND_PARSE_NUMBER(u8, CMD_ARGV[10], qspi_cmd);
		/* Read command */
		qspi_wren_para.instruction_code = qspi_cmd;
		LOG_INFO("wen command 0x%x", qspi_cmd);
		
	}
#endif
	at32_qspi_info = malloc(sizeof(struct at32_qspi_flash_bank));
	if (!at32_qspi_info) {
		LOG_ERROR("not enough memory");
		return ERROR_FAIL;
	}

	bank->driver_priv = at32_qspi_info;
	at32_qspi_info->sfdp_dummy1 = 0;
	at32_qspi_info->sfdp_dummy2 = 0;
	at32_qspi_info->probed = false;
	at32_qspi_info->base_addr = base_addr;
	at32_qspi_info->qspi_en = 0;

	return ERROR_OK;
}


#if 0
static int at32_register_debug(struct target *target, target_addr_t address)
{
	int retval;
	uint32_t data = 0;
	retval = target_read_u32(target, address,  (uint32_t *)&data);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("read qspi 0x%x error",(uint32_t)address);
		return retval;
	}
	LOG_INFO("read address = 0x%x, read reg = 0x%x", (uint32_t)address, data);
	return ERROR_OK;

}
#endif
static int at32_qspi_wait_status(struct target *target, target_addr_t address, uint32_t bit_offset,  uint8_t set)
{
	int retval;
	uint32_t data = 0, timeout = 0;
	timeout = 10000000;
	while ((timeout --) > 0)
	{
		retval = target_read_u32(target,address,(uint32_t *) &data);
		if(retval != ERROR_OK)
		{
			return retval;
		}
		if((uint32_t)(data & (1 << bit_offset)) == (uint32_t)(set << bit_offset))
		{
			break;
		}
	}
	if(timeout == 0)
	{
		LOG_INFO("wait staus error: %u. address = 0x%x, read reg = 0x%x", timeout, (uint32_t)address, data);
		return ERROR_FAIL;
	}
	return ERROR_OK;

}

static int at32_qspi_set_reg(struct target *target, target_addr_t address, uint32_t value)
{
	int retval;
	uint32_t data = 0;
	retval = target_read_u32(target, address,  (uint32_t *)&data);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	data = data | value;
	
	retval = target_write_u32(target,address, data);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	retval = target_read_u32(target, address,  (uint32_t *)&data);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	return ERROR_OK;
}

static int at32_qspi_clear_reg(struct target *target, target_addr_t address, uint32_t value)
{
	int retval;
	uint32_t data = 0;
	retval = target_read_u32(target, address,  (uint32_t *)&data);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	data = data & (~value);
	retval = target_write_u32(target,address, data);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	return ERROR_OK;
}

static int custom_qspi_cmd_send(struct flash_bank *bank, at32_qspi_cmd_type * cmd, uint8_t wait_state)
{
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	int retval;

	uint32_t w0, w1, w2, w3;
	
	w0 = cmd->address_code;
	
	w1 = (uint32_t)cmd->address_length;
       w1 |= (uint32_t)(cmd->second_dummy_cycle_num << 16);
       w1 |= (uint32_t)(cmd->instruction_length << 24);
       w1 |= (uint32_t)(cmd->pe_mode_enable << 28);

	w2 = (uint32_t)cmd->data_counter;

	w3 = (uint32_t)(cmd->write_data_enable << 1);
       w3 |= (uint32_t)(cmd->read_status_enable << 2);
       w3 |= (uint32_t)(cmd->read_status_config << 3);
       w3 |= (uint32_t)(cmd->operation_mode << 5);
       w3 |= (uint32_t)(cmd->pe_mode_operate_code << 16);
       w3 |= (uint32_t)(cmd->instruction_code << 24);

//	LOG_INFO("Start Write w0 0x%x = 0x%x",  AT32_QSPI_REG(CMD_W0_OFFSET), w0);
	retval = target_write_u32(target, AT32_QSPI_REG(CMD_W0_OFFSET), w0);
	if(retval != ERROR_OK)
	{
		return retval;
	}

//	LOG_INFO("Start Write w1 0x%x = 0x%x",  AT32_QSPI_REG(CMD_W1_OFFSET), w1);
	retval = target_write_u32(target, AT32_QSPI_REG(CMD_W1_OFFSET), w1);
	if(retval != ERROR_OK)
	{
		return retval;
	}

//	LOG_INFO("Start Write w2 0x%x = 0x%x",  AT32_QSPI_REG(CMD_W2_OFFSET), w2);
	retval = target_write_u32(target, AT32_QSPI_REG(CMD_W2_OFFSET), w2);
	if(retval != ERROR_OK)
	{
		return retval;
	}

//	LOG_INFO("Start Write w3 0x%x = 0x%x",  AT32_QSPI_REG(CMD_W3_OFFSET), w3);
	retval = target_write_u32(target, AT32_QSPI_REG(CMD_W3_OFFSET), w3);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	
	if(wait_state == 1)
	{
		retval = at32_qspi_wait_status(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0, 1);
		if(retval != ERROR_OK)
		{
			return retval;
		}
//		at32_register_debug(target, AT32_QSPI_REG(CMDSTS_OFFSET));
		retval = at32_qspi_set_reg(target, AT32_QSPI_REG(CMDSTS_OFFSET), 1);
		if(retval != ERROR_OK)
		{
			return retval;
		}
//		at32_register_debug(target, AT32_QSPI_REG(CMDSTS_OFFSET));
	}
	return ERROR_OK;

}


static int custom_qspi_xip_send(struct flash_bank *bank, at32_qspi_xip_type * cmd, uint8_t wait_state)
{
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	int retval;

	uint32_t w0, w1, w2;
	
	w0 = (uint32_t)cmd->read_second_dummy_cycle_num;
  	w0 |= (uint32_t)(cmd->read_operation_mode << 8);
  	w0 |= (uint32_t)(cmd->read_address_length << 11);
 	w0 |= (uint32_t)(cmd->read_instruction_code << 12);
	
	w1 = (uint32_t)cmd->write_second_dummy_cycle_num;
  	w1 |= (uint32_t)(cmd->write_operation_mode << 8);
  	w1 |= (uint32_t)(cmd->write_address_length << 11);
  	w1 |= (uint32_t)(cmd->write_instruction_code << 12);

	w2 = (uint32_t)cmd->read_data_counter;
 	w2 |= (uint32_t)(cmd->read_time_counter << 8);
 	w2 |= (uint32_t)(cmd->read_select_mode << 15);
 	w2 |= (uint32_t)(cmd->write_data_counter << 16);
       w2 |= (uint32_t)(cmd->write_time_counter << 24);
  	w2 |= (uint32_t)(cmd->write_select_mode << 31);
	

//	LOG_INFO("Start Write w0 0x%x = 0x%x",  AT32_QSPI_REG(XIP_CMD_W0_OFFSET), w0);

	retval = target_write_u32(target, AT32_QSPI_REG(XIP_CMD_W0_OFFSET), w0);
	if(retval != ERROR_OK)
	{
		return retval;
	}

	retval = target_write_u32(target, AT32_QSPI_REG(XIP_CMD_W1_OFFSET), w1);
	if(retval != ERROR_OK)
	{
		return retval;
	}

	retval = target_write_u32(target, AT32_QSPI_REG(XIP_CMD_W2_OFFSET), w2);
	if(retval != ERROR_OK)
	{
		return retval;
	}
#if 0
	LOG_INFO("Start Write w3 0x%x = 0x%x",  AT32_QSPI_REG(XIP_CMD_W3_OFFSET), w3);
	retval = target_write_u32(target, AT32_QSPI_REG(XIP_CMD_W3_OFFSET), w3);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("write qspi 0x%x error", AT32_QSPI_REG(XIP_CMD_W3_OFFSET));
		return retval;
	}
#endif
	if(wait_state == 1)
	{
		retval = at32_qspi_wait_status(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0, 1);
		if(retval != ERROR_OK)
		{
			return retval;
		}

		retval = at32_qspi_set_reg(target, AT32_QSPI_REG(CMDSTS_OFFSET), 1);
		if(retval != ERROR_OK)
		{
			return retval;
		}
	}
	return ERROR_OK;

}

static int custom_qspi_write_enable(struct flash_bank *bank)
{
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	at32_qspi_info->cmd_struct = qspi_wren_para;
	return custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 1);

}

static int custom_qspi_sector_erase(struct flash_bank *bank, uint32_t address)
{
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	
	at32_qspi_info->cmd_struct = qspi_erase_para;
	at32_qspi_info->cmd_struct.address_code = address;
	return custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 1);

}
static int custom_qspi_busy_check(struct flash_bank *bank)
{
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	
	at32_qspi_info->cmd_struct = qspi_rdsr_para;
	return custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 1);
}

static int custom_qspi_xip_enable(struct flash_bank *bank, bool flag)
{
#if 1
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	int retval;
	uint32_t data;
	retval = target_read_u32(target, AT32_QSPI_REG(CTRL_OFFSET),  (uint32_t *)&data);
	if(retval != ERROR_OK)
	{
		return retval;
	}

	if((data & 0x100000) == flag)
		return ERROR_OK;

	retval = at32_qspi_wait_status(target,AT32_QSPI_REG(FIFOSTS_OFFSET) ,0, 1);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	if(flag == true)
		retval = at32_qspi_set_reg(target, AT32_QSPI_REG(CTRL_OFFSET), (1 << 20));
	else
		retval = at32_qspi_clear_reg(target, AT32_QSPI_REG(CTRL_OFFSET), (1 << 20));
	if(retval != ERROR_OK)
	{
		return retval;
	}

	retval = at32_qspi_wait_status(target, AT32_QSPI_REG(CTRL_OFFSET), 8, 0);
	if(retval != ERROR_OK)
	{
		return retval;
	}
	if(flag == true)
	{
		retval = at32_qspi_wait_status(target, AT32_QSPI_REG(XIP_CMD_W3_OFFSET), 3, 0);
		if(retval != ERROR_OK)
		{
			return retval;
		}
		at32_qspi_info->xip_struct = qspi_xip_para;
		custom_qspi_xip_send(bank, &at32_qspi_info->xip_struct, 0);
	}
	return ERROR_OK;
#endif
}

static int qspi_cmd_init(struct flash_bank *bank)
{
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	int retval;
       at32_qspi_set_reg(target, 0x40023838, 0x402);
	   	
	custom_qspi_xip_enable(bank, false);

	retval = at32_qspi_clear_reg(target, AT32_QSPI_REG(CTRL_OFFSET), ((1 << 4) | (3 << 16) | 3 | (1 << 20)));
	if(retval != ERROR_OK)
	{
		LOG_ERROR("Clear Register Error");
		return retval;
	}

	retval = at32_qspi_set_reg(target, AT32_QSPI_REG(CTRL3_OFFSET), ((1 << 8) | 50));
	if(retval != ERROR_OK)
	{
		LOG_ERROR("Set QSPI Register Error");
		return retval;
	}
	alive_sleep(1);
	return ERROR_OK;
	
}

static int at32qspi_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	unsigned int sector;
	uint32_t address;
	int retval = ERROR_OK;
	custom_qspi_xip_enable(bank, false);
	LOG_INFO("%s: from sector %u to sector %u", __func__, first, last);
	
	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if ((last < first) || (last >= bank->num_sectors)) {
		LOG_ERROR("Flash sector invalid");
		return ERROR_FLASH_SECTOR_INVALID;
	}
	
	for (sector = first; sector <= last; sector++) {
		custom_qspi_write_enable(bank);
		address = sector * (at32_qspi_info->sector_size);
//		LOG_INFO("erase sector %d, address = 0x%x", sector, address);
		retval = custom_qspi_sector_erase(bank, address);
		if (retval != ERROR_OK)
			break;
		retval = custom_qspi_busy_check(bank);
		if (retval != ERROR_OK)
			break;
//		alive_sleep(10);
//		keep_alive();
	}
	LOG_INFO("Erase Success");
	if (retval != ERROR_OK)
		LOG_ERROR("Flash sector_erase failed on sector %u", sector);
	custom_qspi_xip_enable(bank,true);
	return retval;
}

static int at32qspi_protect(struct flash_bank *bank, int set,
	unsigned int first, unsigned int last)
{
	unsigned int sector;

	for (sector = first; sector <= last; sector++)
		bank->sectors[sector].is_protected = set;

	if (set)
		LOG_WARNING("setting soft protection only, not related to flash's hardware write protection");

	return ERROR_OK;
}

static int at32qspi_write(struct flash_bank *bank, const uint8_t *buffer,
	uint32_t offset, uint32_t count)
{
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	unsigned int  idx, w_len = count;
	int retval;

	LOG_INFO("%s: offset=0x%08" PRIx32 " count=0x%08" PRIx32,
		__func__, offset, count);
	custom_qspi_xip_enable(bank,false);
	
	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (!(at32_qspi_info->probed)) {
		LOG_ERROR("Flash bank not probed");
		return ERROR_FLASH_BANK_NOT_PROBED;
	}

	if (offset + count > bank->size) {
		LOG_WARNING("Write beyond end of flash. Extra data discarded.");
		count = bank->size - offset;
	}
#if 0		
	/* Check sector protection */
	for (sector = 0; sector < bank->num_sectors; sector++) {
		/* Start offset in or before this sector? */
		/* End offset in or behind this sector? */
		if ((offset < (bank->sectors[sector].offset + bank->sectors[sector].size)) &&
			((offset + count - 1) >= bank->sectors[sector].offset) &&
			bank->sectors[sector].is_protected) {
			LOG_ERROR("Flash sector %u protected", sector);
			return ERROR_FLASH_PROTECTED;
		}
	}
#endif
	
	do
	{
	      custom_qspi_write_enable(bank);
		w_len = (offset /at32_qspi_info->dev.pagesize + 1) * at32_qspi_info->dev.pagesize - offset;
//		LOG_INFO("Write offset = 0x%x, length = 0x%x", offset, w_len);
		if(count < w_len)
		{
			w_len = count;
		}
		at32_qspi_info->cmd_struct = qspi_write_para;
		at32_qspi_info->cmd_struct.address_code = offset;
		at32_qspi_info->cmd_struct.data_counter = w_len;
		custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 0);

		for(idx = 0; idx < w_len  / 4; idx ++)
		{
			retval = at32_qspi_wait_status(target, AT32_QSPI_REG(FIFOSTS_OFFSET), 0, 1);
			if(retval != ERROR_OK)
			{
				LOG_ERROR("Wait QSPI W FIFOSTS_OFFSET Error");
				return retval;
			}
			retval = target_write_u32(target, AT32_QSPI_REG(DT_OFFSET), *((uint32_t *)buffer + idx));
			if(retval != ERROR_OK)
			{
				LOG_ERROR("Write QSPI DT_OFFSET Error");
				return retval;
			}
		}
		if((w_len % 4) != 0)
		{
			for(idx = 0; idx < w_len % 4; idx ++)
			{
				retval = at32_qspi_wait_status(target, AT32_QSPI_REG(FIFOSTS_OFFSET), 0, 1);
				if(retval != ERROR_OK)
				{
					LOG_ERROR("Wait QSPI W FIFOSTS_OFFSET Error");
					return retval;
				}
				retval = target_write_u8(target, AT32_QSPI_REG(DT_OFFSET), *(buffer  + w_len - (w_len % 4 - idx)));
				if(retval != ERROR_OK)
				{
					LOG_ERROR("Write QSPI DT_OFFSET Error");
					return retval;
				}
			}
		}

		count -= w_len;
		offset += w_len;
		buffer += w_len;

		retval = at32_qspi_wait_status(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0, 1);
		if(retval != ERROR_OK)
		{
			LOG_ERROR("Wait QSPI CMDSTS_OFFSET FLAG  Error");
			return retval;
		}

		retval = target_write_u32(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0x1);
		if(retval != ERROR_OK)
		{
			LOG_ERROR("Read QSPI CMDSTS_OFFSET Error");
			return retval;
		}
		custom_qspi_busy_check(bank);
	
	}while(count);
	custom_qspi_xip_enable(bank,true);
	LOG_INFO("Write Success");
	return ERROR_OK;
}


static int at32qspi_read(struct flash_bank *bank, uint8_t *buffer,
	uint32_t offset, uint32_t count)
{
LOG_INFO("%s: offset=0x%08" PRIx32 " count=0x%08" PRIx32,
		__func__, offset, count);
#if 1
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	unsigned int idx, r_len = count;
	int retval;
	

	LOG_INFO("%s: offset=0x%08" PRIx32 " count=0x%08" PRIx32,
		__func__, offset, count);
	at32_qspi_info->cmd_struct = qspi_read_para;
	at32_qspi_info->cmd_struct.address_code = offset;
	at32_qspi_info->cmd_struct.data_counter = count;
	custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 0);

	do
	{
		if(count >= 128)
		{
			r_len = 128;
		}
		else
		{
			r_len = count;
		}
		retval = at32_qspi_wait_status(target, AT32_QSPI_REG(FIFOSTS_OFFSET), 1, 1);
		if(retval != ERROR_OK)
		{
			LOG_ERROR("Read QSPI R FIFO Status Error");
			return retval;
		}
		for(idx = 0; idx < r_len; idx ++)
		{
			retval = target_read_u8(target, AT32_QSPI_REG(DT_OFFSET), buffer);
			if(retval != ERROR_OK)
			{
				LOG_ERROR("Read QSPI Data Error");
				return retval;
			}
			buffer ++;
		}
		count -= r_len;

	}while(count);
#endif
	retval = at32_qspi_wait_status(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0, 1);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("Wait QSPI CMDSTS_OFFSET FLAG  Error");
		return retval;
	}

	retval = target_write_u32(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0x1);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("Read QSPI CMDSTS_OFFSET Error");
		return retval;
	}
	return ERROR_OK;
}

#if 1
static int at32_qspi_read_flash_id(struct flash_bank *bank, uint32_t *flash_id)
{
	struct target *target = bank->target;
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	int retval;
	uint8_t id[3];
	at32_qspi_info->cmd_struct = qspi_read_para;
       at32_qspi_info->cmd_struct.instruction_code = SPIFLASH_READ_ID;
	at32_qspi_info->cmd_struct.address_length = QSPI_CMD_ADRLEN_0_BYTE;
	at32_qspi_info->cmd_struct.address_code = 0;
	at32_qspi_info->cmd_struct.operation_mode = QSPI_OPERATE_MODE_111;
	at32_qspi_info->cmd_struct.second_dummy_cycle_num= 0;
	at32_qspi_info->cmd_struct.data_counter = 3;
	custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 0);

	retval = at32_qspi_wait_status(target, AT32_QSPI_REG(FIFOSTS_OFFSET), 1, 1);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("read qspi DT_OFFSET error");
		return retval;
	}
	for(uint8_t i = 0; i < 3; i ++)
	{
		retval = target_read_u8(target, AT32_QSPI_REG(DT_OFFSET), &id[i]);
		if(retval != ERROR_OK)
		{
			LOG_ERROR("read qspi  xip_cmd_w3 error");
			return retval;
		}
	}

#if 1
	retval = at32_qspi_wait_status(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0, 1);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("read qspi DT_OFFSET error");
		return retval;
	}

	retval = target_write_u32(target, AT32_QSPI_REG(CMDSTS_OFFSET), 0x1);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("read qspi DT_OFFSET error");
		return retval;
	}
#endif
      *flash_id = id[0] | (id[1] << 8) | (id[2] << 16);
	LOG_INFO("Read Flash id = 0x%x", *flash_id);
	return ERROR_OK;
}
#endif
static int at32qspi_probe(struct flash_bank *bank)
{
	struct at32_qspi_flash_bank *at32_qspi_info = bank->driver_priv;
	const struct flash_device *p;
	uint32_t data;
	int retval;
	uint32_t flash_id;

#if 0
     struct target *target = bank->target;
	at32_register_debug(target, 0x40023838);
	at32_register_debug(target, 0x400238A0);
       at32_register_debug(target, 0x40023C60);
	at32_register_debug(target, 0x40023C00);
	at32_register_debug(target, 0x40020400);
	at32_register_debug(target, 0x40020408);
	at32_register_debug(target, 0x40020420);
	at32_register_debug(target, 0x40020424);
	at32_register_debug(target, 0x40020800);
	at32_register_debug(target, 0x40020808);
	at32_register_debug(target, 0x40020820);
	at32_register_debug(target, 0x40020824);
#endif
	/* calculate numbers of pages */
	int num_pages = 4096;

	/* check that calculation result makes sense */
	assert(num_pages > 0);

	if (bank->sectors) {
		free(bank->sectors);
		bank->sectors = NULL;
	}

	if (bank->prot_blocks) {
		free(bank->prot_blocks);
		bank->prot_blocks = NULL;
	}
	bank->size = 1024 * 1024 * 16;
	bank->num_sectors = num_pages;
	
	bank->sectors = alloc_block_array(0, QSPI_SECTOR_SIZE, num_pages);
	if (!bank->sectors)
		return ERROR_FAIL;

	/* calculate number of write protection blocks */
	int num_prot_blocks = num_pages / 2;
	if (num_prot_blocks > 32)
		num_prot_blocks = 32;

	bank->num_prot_blocks = num_prot_blocks;
	bank->prot_blocks = alloc_block_array(0, 2 * QSPI_SECTOR_SIZE, num_prot_blocks);
	if (!bank->prot_blocks)
		return ERROR_FAIL;

	if (num_prot_blocks == 32)
		bank->prot_blocks[31].size = (num_pages - (31 * 2)) * QSPI_SECTOR_SIZE;

	at32_qspi_info->probed = 1;
#if 1
	retval = target_read_u32(bank->target, 0x40023838, (uint32_t *) &data);
	if(retval != ERROR_OK)
	{
		LOG_ERROR("read qspi clock error");
	}
#endif
	if(AT32_QSPI1_BASE_ADDR == at32_qspi_info->base_addr)
	{
		if((data & 0x00000002) == 0x00)
			return ERROR_OK;
	}
	else if(AT32_QSPI2_BASE_ADDR == at32_qspi_info->base_addr)
	{
		if((data & 0x00000400) == 0x00)
			return ERROR_OK;
	}
#if 1
	else
	{
		return ERROR_OK;
	}
#endif
	at32_qspi_info->dev.sectorsize = QSPI_SECTOR_SIZE;
	at32_qspi_info->dev.pagesize = QSPI_PAGE_SIZE;
	at32_qspi_info->p_page_size = QSPI_PAGE_SIZE;

	qspi_cmd_init(bank);
	at32_qspi_info->flash_id = 0;
	at32_qspi_info->sector_size = QSPI_SECTOR_SIZE;
	if(at32_qspi_read_flash_id(bank, &flash_id) == ERROR_OK)
	{
		for (p = flash_devices; flash_id && p->name ; p++) {
			if (p->device_id == flash_id) {
				memcpy(&at32_qspi_info->dev, p, sizeof(at32_qspi_info->dev));
				if (p->size_in_bytes / 4096)
					LOG_INFO("QSPI flash \'%s\' id = 0x%06" PRIx32 " size = %" PRIu32
						"kbytes", p->name, flash_id, p->size_in_bytes / 1024);
				else
					LOG_INFO("QSPI flash \'%s\' id = 0x%06" PRIx32 " size = %" PRIu32
						"bytes", p->name, flash_id, p->size_in_bytes);
				bank->size = p->size_in_bytes;
				bank->num_sectors = p->size_in_bytes /QSPI_SECTOR_SIZE;
#if 0
				at32_qspi_info->flash_id = flash_id;
				bank->size = p->size_in_bytes;
				bank->num_sectors = p->size_in_bytes / p->sectorsize;
				bank->sectors = alloc_block_array(0, p->sectorsize, bank->num_sectors );
				if (!bank->sectors)
					return ERROR_FAIL;

				num_prot_blocks = bank->num_sectors / 2;
				if (num_prot_blocks > 32)
					num_prot_blocks = 32;
				
				bank->num_prot_blocks = num_prot_blocks;
				bank->prot_blocks = alloc_block_array(0, 2 *  p->sectorsize, num_prot_blocks);
				if (!bank->prot_blocks)
					return ERROR_FAIL;
				if (num_prot_blocks == 32)
					bank->prot_blocks[31].size = (num_pages - (31 * 2)) * p->sectorsize;
#endif				
				break;
			}
		}

		
		
	}
	else
	{
		LOG_INFO("AT32 QSPI Read Flash ID ERROR");
	}
	return ERROR_OK;
	
}

static int at32qspi_auto_probe(struct flash_bank *bank)
{
	return at32qspi_probe(bank);
}

static int get_at32qspi_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	LOG_INFO("Get AT32 QSPI infomation ");
	return ERROR_OK;
}
static int at32qspi_blank_check(struct flash_bank *bank)
{
	LOG_INFO("AT32 QSPI Blank Check");
	return ERROR_OK;
}
static int at32qspi_protect_check(struct flash_bank *bank)
{
	LOG_INFO("AT32 QSPI Protect Check");
	return ERROR_OK;
}
static int at32qspi_verify(struct flash_bank *bank, const uint8_t *buffer,
	uint32_t offset, uint32_t count)
{
	LOG_INFO("AT32 QSPI Verify ");
	return ERROR_OK;
}

COMMAND_HANDLER(at32qspi_handle_mass_erase_command)
{
	struct at32_qspi_flash_bank *at32_qspi_info;
	

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;
	
	at32_qspi_info = bank->driver_priv;

	if(at32_qspi_info->base_addr != AT32_QSPI1_BASE_ADDR && at32_qspi_info->base_addr != AT32_QSPI2_BASE_ADDR)
	{
		LOG_INFO("Error Canmand qspi mass erase");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}
	custom_qspi_xip_enable(bank,false);
	
	
#if 0
	if(at32_qspi_info->flash_id != 0)
	{
		at32_qspi_info->cmd_struct.instruction_code = at32_qspi_info->dev.chip_erase_cmd;
	}
#endif
	LOG_INFO("start at32 qspi mass erase wait....");
	custom_qspi_write_enable(bank);
	at32_qspi_info->cmd_struct = qspi_mass_erase_para;
	at32_qspi_info->cmd_struct.address_code = 0;
	retval = custom_qspi_cmd_send(bank, &at32_qspi_info->cmd_struct, 1);
	retval = custom_qspi_busy_check(bank);
	custom_qspi_xip_enable(bank,true);
	LOG_INFO("at32 qspi mass erase complete");
	return retval;
}

static const struct command_registration at32qspi_exec_command_handlers[] = {
	{
		.name = "qspi_mass_erase",
		.handler = at32qspi_handle_mass_erase_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "mass erase qspi flash device.",
	},
	COMMAND_REGISTRATION_DONE
};


static const struct command_registration at32qspi_command_handlers[] = {
	{
		.name = "at32qspi",
		.mode = COMMAND_ANY,
		.help = "at32qspi flash command group",
		.usage = "",
		.chain = at32qspi_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver at32qspi_flash = {
	.name = "at32qspi",
	.commands = at32qspi_command_handlers,
	.flash_bank_command = at32qspi_flash_bank_command,
	.erase = at32qspi_erase,
	.protect = at32qspi_protect,
	.write = at32qspi_write,
	.read = at32qspi_read,\
	.verify = at32qspi_verify,
	.probe = at32qspi_probe,
	.auto_probe = at32qspi_auto_probe,
	.erase_check = at32qspi_blank_check,
	.protect_check = at32qspi_protect_check,
	.info = get_at32qspi_info,
	.free_driver_priv = default_flash_free_driver_priv,
};
