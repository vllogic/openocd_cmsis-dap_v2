/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2008 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 *                                                                         *
 *   Copyright (C) 2011 by Andreas Fritiofson                              *
 *   andreas.fritiofson@gmail.com                                          *
 *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/cortex_m.h>
#include "at32xx.h"

/* at32xx flash description */
#define MCU_HELP                          "at32xx flash command group"

/* flash unlock keys */
#define KEY1			                  0x45670123
#define KEY2			                  0xCDEF89AB

/* flash erase timeout values */
#define FLASH_WRITE_TIMEOUT               100
#define FLASH_SECTOR_ERASE_TIMEOUT        1000
#define FLASH_MASS_ERASE_TIMEOUT          120000

#define BANK1_BASE_ADDR                   0x08000000
#define BANK2_BASE_ADDR                   0x08080000
#define BANK2_BASE_ADDR_4M             0x08200000
#define SPIM_BASE_ADDR                      0x08400000

/* sector size */
#define SECTOR_SIZE_0_5K                  0x200
#define SECTOR_SIZE_1K                    0x400
#define SECTOR_SIZE_2K                    0x800
#define SECTOR_SIZE_4K                    0x1000

#define AT32_FLASH_PSR_OFFSET             0x00
#define AT32_FLASH_UNLOCK_OFFSET          0x04
#define AT32_FLASH_USD_UNLOCK_OFFSET      0x08
#define AT32_FLASH_STS_OFFSET             0x0C
#define AT32_FLASH_CTRL_OFFSET            0x10
#define AT32_FLASH_ADDR_OFFSET            0x14
#define AT32_FLASH_USD_OFFSET             0x1C
#define AT32_FLASH_EPPS_OFFSET            0x20
#define AT32_FLASH_EPPS1_OFFSET           0x2C

/* flash ctrl register bits */
#define FLASH_FPRGM			              (1 << 0)
#define FLASH_SECERS				      (1 << 1)
#define FLASH_BANKERS			          (1 << 2)
#define FLASH_USDPRGM			          (1 << 4)
#define FLASH_USDERS			          (1 << 5)
#define FLASH_ERSTR			              (1 << 6)
#define FLASH_OPLK			              (1 << 7)
#define FLASH_USDULKS		              (1 << 9)

/* flash sts register bits */
#define FLASH_OBF		                  (1 << 0)
#define FLASH_PRGMERR		              (1 << 2)
#define FLASH_EPPERR	                  (1 << 4)
#define FLASH_ODF		                  (1 << 5)

/* flash usd bits */
#define FLASH_USDERR		              0
#define FLASH_FAP		                  1
#define FLASH_WDT_ATO_EN		          2
#define FLASH_DEPSLP_RST	              3
#define FLASH_STDBY_RST	                  4

/*at32 user system data*/
struct at32x_usd_data {
	uint8_t fap;
	uint8_t ssb;
	uint16_t data;
	uint32_t protection;
};

/* at32 mcu type*/
struct at32_spim_info
{
	uint32_t is_support_spim;
	uint32_t io_mux;
	uint32_t flash_type;
	uint32_t flash_size;
	uint32_t sector_size;
};

struct at32_flash_info
{
	uint8_t         project_id;
	uint32_t        pid;
	uint32_t        flash_size;
	uint16_t        sector_size;
	uint32_t        bank_addr;
	uint32_t        bank_size;
	uint32_t        cur_reg_base;
	uint32_t        sector_num;
	uint8_t         probed;
	uint8_t         type_id;
       uint32_t       usd_addr;
	mcu_type_info   *type;
	struct at32x_usd_data usd_data;
	struct at32_spim_info spim_info;
	
};


#define AT32_PROJECT_ID_ADDR              0x1FFFF7F3
#define AT32_FLASH_SIZE_ADDR              0x1FFFF7E0
#define AT32_PRODUCT_ID_ADDR              0xE0042000
#define AT32_BANK1_BASE_ADDR              0x40022000
#define AT32_BANK2_BASE_ADDR              0x40022040
#define AT32_SPIM_BASE_ADDR              0x40022080
#define AT32_USD_BASE_ADDR                0x1FFFF800
#define AT32_USD_LENGTH                    48


static int at32x_mass_erase(struct flash_bank *bank);
static int at32x_get_product_id(struct flash_bank *bank, uint32_t *product_id);
static int at32x_write_block(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t address, uint32_t count);
static int at32x_get_project_id(struct flash_bank *bank, uint8_t *project_id);
static inline void at32x_set_base_reg(struct flash_bank *bank, uint32_t bank_reg);

static int at32x_get_project_id(struct flash_bank *bank, uint8_t *project_id)
{
	struct target *target = bank->target;
	int retval = target_read_u8(target, AT32_PROJECT_ID_ADDR, project_id);
	if (retval != ERROR_OK)
		return retval;
	return ERROR_OK;
}

static int at32x_get_product_id(struct flash_bank *bank, uint32_t *product_id)
{
	int retval;
	struct target *target = bank->target;
	retval = target_read_u32(target, AT32_PRODUCT_ID_ADDR, product_id);
	if (retval != ERROR_OK)
		return retval;

	return retval;
}

static int at32x_get_flash_size(struct flash_bank *bank, uint16_t *flash_size_in_kb)
{
	struct target *target = bank->target;
	int retval;
	retval = target_read_u16(target, AT32_FLASH_SIZE_ADDR, flash_size_in_kb);
	if (retval != ERROR_OK)
		return retval;
	return retval;
}


static int at32_get_device_info(struct flash_bank *bank)
{
	int retval, sector;
	uint8_t index;
	struct at32_flash_info *at32x_info = bank->driver_priv;

	retval = at32x_get_project_id(bank, &(at32x_info->project_id));
	if (retval != ERROR_OK)
		return retval;

	for(index = 0; index < NUM_OF_MCU_TYPE; index ++)
	{
		if(at32x_info->project_id == at32_mcu_type[index].project_id)
		{
			at32x_info->type_id = index;
			break;
		}
	}

	if(index == NUM_OF_MCU_TYPE)
	{
		/*if chip is access protect, use algorithm name compare*/
		for(index = 0; index < NUM_OF_MCU_TYPE; index ++)
		{
			if(strncmp(bank->driver->name, at32_mcu_type[index].name, strlen(bank->driver->name)) == 0)
			{
				at32x_info->type_id = index;
				at32x_info->project_id = at32_mcu_type[index].project_id;
				LOG_WARNING("**************************************************************************************************");
				LOG_WARNING("* maybe the target mcu access protection is activated, please try disable access protection.*");
				LOG_WARNING("**************************************************************************************************");
				break;
			}
		}
		if(index == NUM_OF_MCU_TYPE)
		{
			if(at32x_info->cur_reg_base != 0)
			{
				at32x_info->type_id = index - 1;
			}
			else
			{
				LOG_ERROR("please select the matching algorithm");
				return ERROR_FAIL;
			}
		}
	}
	LOG_INFO("This is target %s algorithm", at32_mcu_type[at32x_info->type_id].name);
	
		
	retval = at32x_get_product_id(bank, &(at32x_info->pid));
	if (retval != ERROR_OK)
		return retval;
	
	if(at32x_info->spim_info.is_support_spim == true)
	{
		uint32_t read_val;
		at32x_info->cur_reg_base = AT32_SPIM_BASE_ADDR;
		at32x_info->spim_info.sector_size = SECTOR_SIZE_4K;
		at32x_info->sector_size = at32x_info->spim_info.sector_size;
		at32x_info->flash_size = at32x_info->spim_info.flash_size;
		at32x_info->bank_size = at32x_info->spim_info.flash_size;
		at32x_info->sector_num = at32x_info->bank_size / at32x_info->sector_size;
		
		/*enable gpio clock*/
		retval = target_write_u32(bank->target, 0x40021018, 0xD);
		if (retval != ERROR_OK)
			return retval;

		/*read gpioa pa8 config*/
		retval = target_read_u32(bank->target, 0x40010804, &read_val);
		if (retval != ERROR_OK)
			return retval;
		read_val 	&= ~(0xf);
		read_val |= 0x9;
		
		retval = target_write_u32(bank->target, 0x40010804, read_val);
		if (retval != ERROR_OK)
			return retval;

		/*read gpiob pb1, pb6, pb7  config*/
		retval = target_read_u32(bank->target, 0x40010c00, &read_val);
		if (retval != ERROR_OK)
			return retval;
		read_val 	&= ~(0xff0000f0);
		read_val |= 0x99000090;
		
		retval = target_write_u32(bank->target, 0x40010c00, read_val);
		if (retval != ERROR_OK)
			return retval;
		if(at32x_info->spim_info.io_mux == true)
		{

			/*read gpiob pb10, pb11  config*/
			retval = target_read_u32(bank->target, 0x40010c04, &read_val);
			if (retval != ERROR_OK)
				return retval;
			read_val 	&= ~(0x0000ff00);
			read_val |= 0x00009900;
		
			retval = target_write_u32(bank->target, 0x40010c04, read_val);
			if (retval != ERROR_OK)
				return retval;
		}
		else
		{
			/*read gpiob pa11, pa12  config*/
			retval = target_read_u32(bank->target, 0x40010804, &read_val);
			if (retval != ERROR_OK)
				return retval;
			read_val 	&= ~(0x000ff000);
			read_val |= 0x00099000;
		
			retval = target_write_u32(bank->target, 0x40010804, read_val);
			if (retval != ERROR_OK)
				return retval;
		}
		/*enable spif*/

		if(at32x_info->project_id == AT32F403XX_ID)
		{
			retval = target_write_u32(bank->target, 0x4001001c, 1 << 21);
			if (retval != ERROR_OK)
				return retval;

		}
		else
		{
			retval = target_write_u32(bank->target, 0x40010030, 0x00000009);
			if (retval != ERROR_OK)
				return retval;
		}
			
		/*flash type select*/
		retval = target_write_u32(bank->target, 0x40022088, at32x_info->spim_info.flash_type);
		if (retval != ERROR_OK)
			return retval;

		at32x_info->probed = 1;
		LOG_INFO("spim flash size: 0x%" PRIx32 ", sector num:  0x%x, sector size: 0x%x", 
				(at32x_info->flash_size ),  at32x_info->sector_num,  at32x_info->sector_size);
		
	}
	else
	{
		retval = at32x_get_flash_size(bank, (uint16_t *)&(at32x_info->flash_size));
		if (retval != ERROR_OK || at32x_info->flash_size == 0 || at32x_info->flash_size == 0xFFFF)
		{
			LOG_WARNING("read at32 flash size failed, %"PRIu32"k flash",at32x_info->flash_size);
		}

		at32x_info->flash_size &= 0xFFFF;
	
		sector = (0x00007000 & at32x_info->pid) >> 12;
		switch(sector)
		{
			case 1:
				at32x_info->sector_size = SECTOR_SIZE_0_5K;
				break;
			case 2:
				at32x_info->sector_size = SECTOR_SIZE_1K;
				break;
			case 3:
				at32x_info->sector_size = SECTOR_SIZE_2K;
				break;
			case 4:
				at32x_info->sector_size = SECTOR_SIZE_4K;
				break;
			default:
				if(at32x_info->flash_size >= 256)
					at32x_info->sector_size = SECTOR_SIZE_2K;
				else
					at32x_info->sector_size = SECTOR_SIZE_1K;
				break;
				
		}

		if(at32x_info->usd_addr == 0)
		{
			at32x_info->usd_addr = at32_mcu_type[at32x_info->type_id].usd_addr;
		}
		if(at32x_info->bank_addr == BANK1_BASE_ADDR)
		{
		       if(at32x_info->cur_reg_base == 0)	
				at32x_info->cur_reg_base = at32_mcu_type[at32x_info->type_id].flash_bank1_reg;
		}
		else if((at32x_info->bank_addr == BANK2_BASE_ADDR || 
		    at32x_info->bank_addr == BANK2_BASE_ADDR_4M) && 
		   at32x_info->flash_size > 512)
		{
		      if(at32x_info->cur_reg_base == 0)
				at32x_info->cur_reg_base = at32_mcu_type[at32x_info->type_id].flash_bank2_reg;
		}
		else
		{
			LOG_WARNING("not have this flash bank address:0x %" PRIx32 "", at32x_info->bank_addr);
		}

		if(at32x_info->flash_size > 512)
		{
			/*two bank: each bank 512kb*/
			if(at32x_info->flash_size > 1024)
			{
				if(at32x_info->bank_addr == BANK1_BASE_ADDR)
				{
					at32x_info->bank_size = 0x200000;  //2048 Kb
					at32x_info->sector_num = at32x_info->bank_size / at32x_info->sector_size;
				}
				else
				{
					at32x_info->bank_size = (at32x_info->flash_size << 10) - 0x200000;
					at32x_info->sector_num = at32x_info->bank_size / at32x_info->sector_size;
				}
			
			}
			else
			{
				if(at32x_info->bank_addr == BANK1_BASE_ADDR)
				{
					at32x_info->bank_size = 0x80000;  //512 Kb
					at32x_info->sector_num = at32x_info->bank_size / at32x_info->sector_size;
				}
				else
				{
					at32x_info->bank_size = (at32x_info->flash_size << 10) - 0x80000;
					at32x_info->sector_num = at32x_info->bank_size / at32x_info->sector_size;
				}
			}
		}
		else
		{
			at32x_info->sector_num = (at32x_info->flash_size << 10) / at32x_info->sector_size;
			at32x_info->bank_size = at32x_info->flash_size << 10;		
		}
		at32x_info->probed = 1;
		LOG_INFO("main flash size: 0x%" PRIx32 ", sector num:  0x%" PRIx32 ", sector size: 0x%" PRIx32 ",  bank size: 0x%" PRIx32 "", 
				 (at32x_info->flash_size << 10),  at32x_info->sector_num,  at32x_info->sector_size, at32x_info->bank_size);
	}

	return ERROR_OK;

}

/* flash bank at32x <base> <size> 0 0 <target#>
 */
FLASH_BANK_COMMAND_HANDLER(at32x_flash_bank_command)
{
	struct at32_flash_info *at32x_info;
	
	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;
	at32x_info = malloc(sizeof(struct at32_flash_info));
	at32x_info->spim_info.is_support_spim = false;
	if( bank->base == SPIM_BASE_ADDR)
	{
		uint32_t io_mux, type, size;
		
		if(CMD_ARGC < 9)
			return ERROR_COMMAND_SYNTAX_ERROR;
		
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[6], io_mux);
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], type);
		COMMAND_PARSE_NUMBER(u32, CMD_ARGV[8], size);
		at32x_info->spim_info.is_support_spim = true;
		at32x_info->spim_info.io_mux = io_mux;
		at32x_info->spim_info.flash_type = type;
		at32x_info->spim_info.flash_size = size;

		LOG_INFO("spim flash io_mux: 0x%" PRIx32 ", type: 0x%" PRIx32 ", size: 0x%" PRIx32 "", io_mux, type, size);
      }
	else
	{
		if(CMD_ARGC >= 7)
		{
			COMMAND_PARSE_NUMBER(u32, CMD_ARGV[6], at32x_info->cur_reg_base);
		}
		else
		{
			at32x_info->cur_reg_base = 0;
		}

		if(CMD_ARGC >= 8)
		{
			 COMMAND_PARSE_NUMBER(u32, CMD_ARGV[7], at32x_info->usd_addr);
		}
		else
		{
			at32x_info->usd_addr = 0;
		}
		LOG_INFO("flash reg address: 0x%" PRIx32 ", usd addr:  0x%x", 
				(at32x_info->cur_reg_base ),  at32x_info->usd_addr);
	}
	bank->driver_priv = at32x_info;
	at32x_info->bank_addr = bank->base;
	at32x_info->probed = 0;
	return ERROR_OK;
}

static inline void at32x_set_base_reg(struct flash_bank *bank, uint32_t bank_reg)
{
    struct at32_flash_info *at32x_info = bank->driver_priv;
	at32x_info->cur_reg_base = bank_reg;
}
static inline int at32x_get_flash_reg(struct flash_bank *bank, uint32_t reg)
{
   
	struct at32_flash_info *at32x_info = bank->driver_priv;
	return (reg + at32x_info->cur_reg_base);
}

static inline int at32x_get_flash_status(struct flash_bank *bank, uint32_t *status)
{
	struct target *target = bank->target;
	return target_read_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_STS_OFFSET), status);
}

static int at32x_wait_status_busy(struct flash_bank *bank, int timeout)
{
	struct target *target = bank->target;
	struct at32_flash_info *at32x_info = bank->driver_priv;
	uint32_t status;
	int retval = ERROR_OK;
	/* wait for busy to clear */
	for (;;) 
	{
		retval = at32x_get_flash_status(bank, &status);
		if (retval != ERROR_OK)
			return retval;
		LOG_DEBUG(">status: 0x%" PRIx32 "", status);
		if ((status & FLASH_OBF) == 0)
			break;
		if (timeout-- <= 0) {
			LOG_ERROR("timed out waiting for flash");
			return ERROR_FAIL;
		}
		alive_sleep(1);
	}
	if (status & FLASH_PRGMERR) {
		LOG_ERROR("%s device programming failed", at32_mcu_type[at32x_info->type_id].name);
		retval = ERROR_FAIL;
	}

	/* clear errors */
	if (status & (FLASH_EPPERR | FLASH_PRGMERR)) {
		target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_STS_OFFSET),
				FLASH_EPPERR | FLASH_PRGMERR);
	}
	return retval;
}

static int at32x_read_usd_data(struct flash_bank *bank)
{
	struct at32_flash_info *at32x_info = bank->driver_priv;
	struct target *target = bank->target;
	uint32_t usd_data;
	int retval;
      
	/* read user and read protection option bytes */
//	retval = target_read_u32(target, AT32_USD_BASE_ADDR, &usd_data);
	retval = target_read_u32(target, at32x_info->usd_addr, &usd_data);
	if (retval != ERROR_OK)
		return retval;

	at32x_info->usd_data.fap = usd_data & 0xFF;
	at32x_info->usd_data.ssb = (usd_data >> 16) & 0xFF;

	/* read user data option bytes */
	retval = target_read_u32(target, at32x_info->usd_addr+4, &usd_data);
	if (retval != ERROR_OK)
		return retval;

	at32x_info->usd_data.data = ((usd_data >> 8) & 0xFF00) | (usd_data & 0xFF);

	/* read write protection option bytes */
	retval = target_read_u32(target, at32x_info->usd_addr+8, &usd_data);
	if (retval != ERROR_OK)
		return retval;

	at32x_info->usd_data.protection = ((usd_data >> 8) & 0xFF00) | (usd_data & 0xFF);

	retval = target_read_u32(target, at32x_info->usd_addr+0xc, &usd_data);
	if (retval != ERROR_OK)
		return retval;

	at32x_info->usd_data.protection |= (((usd_data >> 8) & 0xFF00) | (usd_data & 0xFF)) << 16;

	return ERROR_OK;
}

static int at32x_erase_usd_data(struct flash_bank *bank)
{
	struct target *target = bank->target;

//	at32x_set_base_reg(bank, AT32_BANK1_BASE_ADDR);

	/* read user system data */
	at32x_read_usd_data(bank);

	/* unlock flash registers */
	int retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		return retval;

	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		return retval;

	/* unlock user system data flash registers */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_USD_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_USD_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		return retval;

	/* erase user system data */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), 
							  FLASH_USDERS | FLASH_USDULKS);
	if (retval != ERROR_OK)
		return retval;
	
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET),
							FLASH_USDERS | FLASH_ERSTR | FLASH_USDULKS);
	if (retval != ERROR_OK)
		return retval;

	retval = at32x_wait_status_busy(bank, FLASH_SECTOR_ERASE_TIMEOUT);
	if (retval != ERROR_OK)
		return retval;
	
	return ERROR_OK;
}

static int at32x_write_usd_data(struct flash_bank *bank)
{
	struct at32_flash_info *at32x_info = bank->driver_priv;
	struct target *target = bank->target;

//	at32x_set_base_reg(bank, AT32_BANK1_BASE_ADDR);

	/* unlock flash registers */
	int retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		return retval;

	/* unlock option flash registers */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_USD_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_USD_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		return retval;

	/* program option bytes */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), 
							FLASH_USDPRGM | FLASH_USDULKS);
	if (retval != ERROR_OK)
		return retval;

	uint8_t usd_data[16];

	target_buffer_set_u16(target, usd_data, at32x_info->usd_data.fap);
	target_buffer_set_u16(target, usd_data + 2, at32x_info->usd_data.ssb);
	target_buffer_set_u16(target, usd_data + 4, at32x_info->usd_data.data & 0xff);
	target_buffer_set_u16(target, usd_data + 6, (at32x_info->usd_data.data >> 8) & 0xff);
	target_buffer_set_u16(target, usd_data + 8, at32x_info->usd_data.protection & 0xff);
	target_buffer_set_u16(target, usd_data + 10, (at32x_info->usd_data.protection >> 8) & 0xff);
	target_buffer_set_u16(target, usd_data + 12, (at32x_info->usd_data.protection >> 16) & 0xff);
	target_buffer_set_u16(target, usd_data + 14, (at32x_info->usd_data.protection >> 24) & 0xff);

	retval = at32x_write_block(bank, usd_data, at32x_info->usd_addr, sizeof(usd_data) / 2);
	if (retval != ERROR_OK) {
		if (retval == ERROR_TARGET_RESOURCE_NOT_AVAILABLE)
			LOG_ERROR("working area required to erase options bytes");
		return retval;
	}

	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_OPLK);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}

static int at32x_protect_check(struct flash_bank *bank)
{
	struct target *target = bank->target;
	uint32_t protection;
	int retval;
	LOG_INFO("protect check");
	retval = target_read_u32(target, at32x_get_flash_reg(bank,AT32_FLASH_EPPS_OFFSET), &protection);
	if (retval != ERROR_OK)
		return retval;

	for (unsigned int i = 0; i < bank->num_prot_blocks; i++)
		bank->prot_blocks[i].is_protected = (protection & (1 << i)) ? 0 : 1;

	return ERROR_OK;
}

static int at32x_erase(struct flash_bank *bank, unsigned int first, unsigned int last)
{
	struct target *target = bank->target;

	int retval;
	unsigned int i;

	LOG_INFO("Earse first sector = 0x%" PRIx32 ", last sector = 0x%" PRIx32 " ", first, last);

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if ((first == 0) && (last == (bank->num_sectors - 1)))
		return at32x_mass_erase(bank);

	/* unlock flash registers */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		return retval;
	for (i = first; i <= last; i++) {
		retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_SECERS);
		if (retval != ERROR_OK)
			return retval;
		retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_ADDR_OFFSET),
				bank->base + bank->sectors[i].offset);
		if (retval != ERROR_OK)
			return retval;
		retval = target_write_u32(target,
				at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_SECERS | FLASH_ERSTR);
		if (retval != ERROR_OK)
			return retval;

		retval = at32x_wait_status_busy(bank, FLASH_SECTOR_ERASE_TIMEOUT);
		if (retval != ERROR_OK)
			return retval;

		bank->sectors[i].is_erased = 1;
	}

	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_OPLK);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}

static int at32x_protect(struct flash_bank *bank, int set, unsigned int first, unsigned int last)
{
	struct target *target = bank->target;
	struct at32_flash_info *at32x_info = bank->driver_priv;
	int retval;
	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = at32x_erase_usd_data(bank);
	if (retval != ERROR_OK) {
		LOG_ERROR("%s failed to erase options", at32_mcu_type[at32x_info->type_id].name);
		return retval;
	}

	for (unsigned int i = first; i <= last; i++) {
		if (set)
			at32x_info->usd_data.protection &= ~(1 << i);
		else
			at32x_info->usd_data.protection |= (1 << i);
	}

	return at32x_write_usd_data(bank);
}

static int at32x_write_block(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t address, uint32_t count)
{
	struct at32_flash_info *at32x_info = bank->driver_priv;
	struct target *target = bank->target;
	uint32_t buffer_size = 16384;
	struct working_area *write_algorithm;
	struct working_area *source;
	struct reg_param reg_params[5];
	struct armv7m_algorithm armv7m_info;
	int retval = ERROR_OK;

	static const uint8_t at32x_flash_write_code[] = {
			0x16,0x68,0x00,0x2e,0x18,0xd0,0x55,0x68,
		    0xb5,0x42,0xf9,0xd0,0x2e,0x88,0x26,0x80,
		    0x02,0x35,0x02,0x34,0xc6,0x68,0x01,0x27,
		    0x3e,0x42,0xfb,0xd1,0x14,0x27,0x3e,0x42,
		    0x08,0xd1,0x9d,0x42,0x01,0xd3,0x15,0x46,
		    0x08,0x35,0x55,0x60,0x01,0x39,0x00,0x29,
		    0x02,0xd0,0xe5,0xe7,0x00,0x20,0x50,0x60,
		    0x30,0x46,0x00,0xbe
	};

	/* flash write code */
	if (target_alloc_working_area(target, sizeof(at32x_flash_write_code),
			&write_algorithm) != ERROR_OK) {
		LOG_WARNING("no working area available, can't do block memory writes");
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	retval = target_write_buffer(target, write_algorithm->address,
			sizeof(at32x_flash_write_code), at32x_flash_write_code);
	if (retval != ERROR_OK) {
		target_free_working_area(target, write_algorithm);
		return retval;
	}

	/* memory buffer */
	while (target_alloc_working_area_try(target, buffer_size, &source) != ERROR_OK) {
		buffer_size /= 2;
		buffer_size &= ~3UL; /* Make sure it's 4 byte aligned */
		if (buffer_size <= 256) {
			/* we already allocated the writing code, but failed to get a
			 * buffer, free the algorithm */
			target_free_working_area(target, write_algorithm);

			LOG_WARNING("no large enough working area available, can't do block memory writes");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);	/* flash base (in), status (out) */
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);	/* count (halfword-16bit) */
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);	/* buffer start */
	init_reg_param(&reg_params[3], "r3", 32, PARAM_OUT);	/* buffer end */
	init_reg_param(&reg_params[4], "r4", 32, PARAM_IN_OUT);	/* target address */

	buf_set_u32(reg_params[0].value, 0, 32, at32x_info->cur_reg_base);
	buf_set_u32(reg_params[1].value, 0, 32, count);
	buf_set_u32(reg_params[2].value, 0, 32, source->address);
	buf_set_u32(reg_params[3].value, 0, 32, source->address + source->size);
	buf_set_u32(reg_params[4].value, 0, 32, address);

	armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	armv7m_info.core_mode = ARM_MODE_THREAD;

	retval = target_run_flash_async_algorithm(target, buffer, count, 2,
			0, NULL,
			5, reg_params,
			source->address, source->size,
			write_algorithm->address, 0,
			&armv7m_info);

	if (retval == ERROR_FLASH_OPERATION_FAILED) {
		LOG_ERROR("flash write failed at address 0x%"PRIx32,
				buf_get_u32(reg_params[4].value, 0, 32));

		if (buf_get_u32(reg_params[0].value, 0, 32) & FLASH_PRGMERR) {
			LOG_ERROR("flash memory not erased before writing");
			/* Clear but report errors */
			target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_STS_OFFSET), FLASH_PRGMERR);
		}

		if (buf_get_u32(reg_params[0].value, 0, 32) & FLASH_EPPERR) {
			LOG_ERROR("flash memory write protected");
			/* Clear but report errors */
			target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_STS_OFFSET), FLASH_EPPERR);
		}
	}

	target_free_working_area(target, source);
	target_free_working_area(target, write_algorithm);

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);
	destroy_reg_param(&reg_params[4]);

	return retval;
}

static int at32x_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct target *target = bank->target;
	uint8_t *new_buffer = NULL;

	LOG_INFO("Write address = 0x%" PRIx32 ", count: 0x%" PRIx32 "", (uint32_t)bank->base + offset,  count);
	
	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (offset & 0x1) {
		LOG_ERROR("offset 0x%" PRIx32 " breaks required 2-byte alignment", offset);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	/* If there's an odd number of bytes, the data has to be padded. Duplicate
	 * the buffer and use the normal code path with a single block write since
	 * it's probably cheaper than to special case the last odd write using
	 * discrete accesses. */
	if (count & 1) {
		new_buffer = malloc(count + 1);
		if (new_buffer == NULL) {
			LOG_ERROR("odd number of bytes to write and no memory for padding buffer");
			return ERROR_FAIL;
		}
		LOG_INFO("odd number of bytes to write, padding with 0xff");
		buffer = memcpy(new_buffer, buffer, count);
		new_buffer[count++] = 0xff;
	}

	uint32_t words_remaining = count / 2;
	int retval, retval2;

	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		goto cleanup;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		goto cleanup;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_FPRGM);
	if (retval != ERROR_OK)
		goto cleanup;

	/* try using a block write */
	retval = at32x_write_block(bank, buffer, bank->base + offset, words_remaining);

	if (retval == ERROR_TARGET_RESOURCE_NOT_AVAILABLE) {
		/* if block write failed (no sufficient working area),
		 * we use normal (slow) single halfword accesses */
		LOG_WARNING("couldn't use block writes, falling back to single memory accesses");

		while (words_remaining > 0) {
			uint16_t value;
			memcpy(&value, buffer, sizeof(uint16_t));

			retval = target_write_u16(target, bank->base + offset, value);
			if (retval != ERROR_OK)
				goto reset_pg_and_lock;
#if 0
			retval = at32x_wait_status_busy(bank, 5);
			if (retval != ERROR_OK)
				goto reset_pg_and_lock;
#endif
			words_remaining--;
			buffer += 2;
			offset += 2;
		}
	}

reset_pg_and_lock:
	retval2 = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_OPLK);
	if (retval == ERROR_OK)
		retval = retval2;

cleanup:
	if (new_buffer)
		free(new_buffer);

	return retval;
}


static int at32x_probe(struct flash_bank *bank)
{
	struct at32_flash_info *at32x_info = bank->driver_priv;
	int retval;

	retval = at32_get_device_info(bank);
	if (retval != ERROR_OK)
		return retval;

	/* calculate numbers of pages */
	int num_pages = at32x_info->sector_num;

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
	bank->size = at32x_info->bank_size;
	bank->num_sectors = num_pages;
	
	bank->sectors = alloc_block_array(0, at32x_info->sector_size, num_pages);
	if (!bank->sectors)
		return ERROR_FAIL;

	/* calculate number of write protection blocks */
	int num_prot_blocks = num_pages / 2;
	if (num_prot_blocks > 32)
		num_prot_blocks = 32;

	bank->num_prot_blocks = num_prot_blocks;
	bank->prot_blocks = alloc_block_array(0, 2 * at32x_info->sector_size, num_prot_blocks);
	if (!bank->prot_blocks)
		return ERROR_FAIL;

	if (num_prot_blocks == 32)
		bank->prot_blocks[31].size = (num_pages - (31 * 2)) * at32x_info->sector_size;

	at32x_info->probed = 1;

	return ERROR_OK;
}

static int at32x_auto_probe(struct flash_bank *bank)
{
	return at32x_probe(bank);
}

static int get_at32fx_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	at32_get_device_info(bank);
	return ERROR_OK;
}

static int at32x_mass_erase(struct flash_bank *bank)
{
	struct target *target = bank->target;
    int retval;

	LOG_INFO("flash bank 0x%" PRIx32 " mass erase", (uint32_t)bank->base);
	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* unlock flash registers */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_UNLOCK_OFFSET), KEY2);
	if (retval != ERROR_OK)
		return retval;

	/* mass erase flash memory */
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_BANKERS);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET),
			FLASH_BANKERS | FLASH_ERSTR);
	if (retval != ERROR_OK)
		return retval;

	retval = at32x_wait_status_busy(bank, FLASH_MASS_ERASE_TIMEOUT);
	if (retval != ERROR_OK)
		return retval;

	retval = target_write_u32(target, at32x_get_flash_reg(bank, AT32_FLASH_CTRL_OFFSET), FLASH_OPLK);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}


COMMAND_HANDLER(at32x_handle_mass_erase_command)
{
	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	retval = at32x_mass_erase(bank);
	if (retval == ERROR_OK)
		LOG_INFO("at32x mass erase complete");
	else
		LOG_INFO( "at32x mass erase failed");

	return retval;
}

COMMAND_HANDLER(at32x_handle_disable_access_protection_command)
{
	struct target *target = NULL;
	struct at32_flash_info *at32x_info = NULL;

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	at32x_info = bank->driver_priv;
	target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}
/*
	if(at32x_info->cur_reg_base != at32_mcu_type[at32x_info->type_id].flash_bank1_reg)
	{
		return ERROR_FLASH_OPERATION_FAILED;
	}
*/
	if (at32x_erase_usd_data(bank) != ERROR_OK) {
		LOG_INFO("at32x failed to erase usd");
		return ERROR_OK;
	}
	at32x_info->usd_data.fap = 0xA5;
	if (at32x_write_usd_data(bank) != ERROR_OK) {
		LOG_INFO("at32x failed to write usd");
		return ERROR_OK;
	}

	LOG_INFO("AT32x disable access protection complete");

	return ERROR_OK;
}

static const struct command_registration at32f4xx_exec_command_handlers[] = {
	{
		.name = "mass_erase",
		.handler = at32x_handle_mass_erase_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Erase entire flash device.",
	},
	{
		.name = "disable_access_protection",
		.handler = at32x_handle_disable_access_protection_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "if access protection enabled, can not write data to flash",
	},
	COMMAND_REGISTRATION_DONE
};


static const struct command_registration at32f4xx_command_handlers[] = {
	{
		.name = "at32f4xx",
		.mode = COMMAND_ANY,
		.help = "at32f4xx flash command group",
		.usage = "",
		.chain = at32f4xx_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver at32f403xx_flash = {
	.name = "at32f403xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32f413xx_flash = {
	.name = "at32f413xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32f415xx_flash = {
	.name = "at32f415xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};


const struct flash_driver at32f403axx_flash = {
	.name = "at32f403axx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};


const struct flash_driver at32f407xx_flash = {
	.name = "at32f407xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32wb415xx_flash = {
	.name = "at32wb415xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32f421xx_flash = {
	.name = "at32f421xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};



const struct flash_driver at32f425xx_flash = {
	.name = "at32f425xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32f435xx_flash = {
	.name = "at32f435xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32f437xx_flash = {
	.name = "at32f437xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};


const struct flash_driver at32f423xx_flash = {
	.name = "at32f423xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};

const struct flash_driver at32f4xx_flash = {
	.name = "at32f4xx",
	.commands = at32f4xx_command_handlers,
	.flash_bank_command = at32x_flash_bank_command,
	.erase = at32x_erase,
	.protect = at32x_protect,
	.write = at32x_write,
	.read = default_flash_read,
	.probe = at32x_probe,
	.auto_probe = at32x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = at32x_protect_check,
	.info = get_at32fx_info,
	.free_driver_priv = default_flash_free_driver_priv,
};




