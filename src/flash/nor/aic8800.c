/***************************************************************************
 *   Copyright (C) 2022 by Talpa Chen                                      *
 *   talpachen@gmail.com                                               *
 *                                                                         *
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

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/armv7m.h>

#ifndef dimof
#   define dimof(arr)                       (sizeof(arr) / sizeof((arr)[0]))
#endif

/*
	struct aic8800_rom_falsh_api_t {
		void (*undefined_api_0)(void);
		void (*undefined_api_1)(void);
		uint32_t (*ChipSizeGet)(void);
		void (*ChipErase)(void);
		int32_t (*Erase)(uint32_t addr_4k, uint32_t len);
		int32_t (*Write)(uint32_t addr_256, uint32_t len, uint32_t buf);
		int32_t (*Read)(uint32_t addr_256, uint32_t len, uint32_t buf);
		void (*CacheInvalidAll)(void);
		void (*CacheInvalidRange)(uint32_t addr, uint32_t len);
	} aic8800_rom_falsh_api @ 0x00000180UL;
*/
#define AIC8800_ROM_APITBL_BASE		(0x00000180UL)

#define AIC8800_FLASH_BASE			0x08000000
#define AIC8800_FLASH_SECSIZE		0x1000
#define AIC8800_FLASH_PAGESIZE		0x100

#define STACK_DEFAULT				512
#define TIMEROUT_DEFAULT			1000
#define TIMEROUT_ERASE_4K			100
#define TIMEROUT_WRITE_4K			20

struct aic8800_rom_api_call_code_t {
	uint16_t ldrn_r3;	// 0x4b01
	uint16_t blx_r3;	// 0x4798
	uint16_t nop[2];	// 0xbf00, 0xbf00
	uint32_t api_addr;	// api addr
};

struct aic8800_rom_api_call_code_t aic8800_rom_api_call_code_example = {
	.ldrn_r3 = 0x4b01,			/* LDR.N R3, [PC, #0x4]*/
	.blx_r3 = 0x4798,			/* BLX R3 */
	.nop = {0xbf00, 0xbf00},	/* NOP & NOP */
	.api_addr = 0x12345678,
};

struct aic8800_flash_bank {
	bool probed;

	struct aic8800_rom_api_call_code_t rom_api_call_code[9];
	struct armv7m_algorithm armv7m_info;
};

static int romapi_ChipSizeGet(struct flash_bank *bank, uint32_t *chip_size)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	struct reg_param reg_params[2];

	retval = target_alloc_working_area(target, sizeof(struct aic8800_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800_rom_api_call_code_t),
									(const uint8_t *)&aic8800_bank->rom_api_call_code[2]);

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN);
	init_reg_param(&reg_params[1], "sp", 32, PARAM_OUT);
	//buf_set_u32(reg_params[0].value, 0, 32, 0);
	buf_set_u32(reg_params[1].value, 0, 32, algorithm->address + algorithm->size);

	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, algorithm->address + sizeof(struct aic8800_rom_api_call_code_t) - 6,
									TIMEROUT_DEFAULT, &aic8800_bank->armv7m_info);
	if (retval == ERROR_OK) {
		*chip_size = buf_get_u32(reg_params[0].value, 0, 32);
	}

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);

	return retval;
}

static int romapi_ChipErase(struct flash_bank *bank)
{
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	int retval;
	uint32_t timeout = (bank->size / 4096) * TIMEROUT_ERASE_4K;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct reg_param reg_params[1];

	retval = target_alloc_working_area(target, sizeof(struct aic8800_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800_rom_api_call_code_t),
									(const uint8_t *)&aic8800_bank->rom_api_call_code[3]);

	init_reg_param(&reg_params[0], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, algorithm->address + algorithm->size);

	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, algorithm->address + sizeof(struct aic8800_rom_api_call_code_t) - 6,
									timeout, &aic8800_bank->armv7m_info);
	if (retval == ERROR_OK) {
	}

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);

	return retval;
}

static uint32_t romapi_Erase(struct flash_bank *bank, uint32_t addr_4k, uint32_t len)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	struct reg_param reg_params[3];

	retval = target_alloc_working_area(target, sizeof(struct aic8800_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800_rom_api_call_code_t),
									(const uint8_t *)&aic8800_bank->rom_api_call_code[4]);

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, addr_4k);
	buf_set_u32(reg_params[1].value, 0, 32, len);
	buf_set_u32(reg_params[2].value, 0, 32, algorithm->address + algorithm->size);

	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, algorithm->address + sizeof(struct aic8800_rom_api_call_code_t) - 6,
									TIMEROUT_ERASE_4K * ((len + 4095) / 4096), &aic8800_bank->armv7m_info);
	if (retval == ERROR_OK) {
	}

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	return len;
}

static int romapi_Write(struct flash_bank *bank, uint32_t addr_256, uint32_t len, const uint8_t *buf)
{
	int retval;
	struct working_area *algorithm;
	struct working_area *fifo;
	struct target *target = bank->target;
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	struct reg_param reg_params[4];

	retval = target_alloc_working_area(target, sizeof(struct aic8800_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	retval = target_alloc_working_area(target, 4096, &fifo);

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800_rom_api_call_code_t),
									(const uint8_t *)&aic8800_bank->rom_api_call_code[5]);


	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[1], "r2", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "sp", 32, PARAM_OUT);

	while (len) {
		uint32_t block;
		if (len <= 4096) {
			block = len;
		} else {
			block = 4096;
		}




		len -= block;
	}


	//buf_set_u32(reg_params[0].value, 0, 32, addr_4k);
	//buf_set_u32(reg_params[1].value, 0, 32, len);
	//buf_set_u32(reg_params[2].value, 0, 32, len);
	buf_set_u32(reg_params[2].value, 0, 32, algorithm->address + algorithm->size);

	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, algorithm->address + sizeof(struct aic8800_rom_api_call_code_t) - 6,
									TIMEROUT_ERASE_4K * ((len + 4095) / 4096), &aic8800_bank->armv7m_info);
	if (retval == ERROR_OK) {
	}

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	return retval;
}

static int romapi_CacheInvalidAll(struct flash_bank *bank)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	struct reg_param reg_params[1];

	retval = target_alloc_working_area(target, sizeof(struct aic8800_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800_rom_api_call_code_t),
									(const uint8_t *)&aic8800_bank->rom_api_call_code[7]);

	init_reg_param(&reg_params[0], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, algorithm->address + algorithm->size);

	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, algorithm->address + sizeof(struct aic8800_rom_api_call_code_t) - 6,
									TIMEROUT_DEFAULT, &aic8800_bank->armv7m_info);
	if (retval == ERROR_OK) {
	}

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);

	return retval;
}

static int romapi_CacheInvalidRange(struct flash_bank *bank, uint32_t addr, uint32_t len)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	struct reg_param reg_params[8];

	retval = target_alloc_working_area(target, sizeof(struct aic8800_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800_rom_api_call_code_t),
									(const uint8_t *)&aic8800_bank->rom_api_call_code[4]);

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, addr);
	buf_set_u32(reg_params[1].value, 0, 32, len);
	buf_set_u32(reg_params[2].value, 0, 32, algorithm->address + algorithm->size);

	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, algorithm->address + sizeof(struct aic8800_rom_api_call_code_t) - 6,
									TIMEROUT_DEFAULT, &aic8800_bank->armv7m_info);
	if (retval == ERROR_OK) {
	}

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	return retval;
}

FLASH_BANK_COMMAND_HANDLER(aic8800_flash_bank_command)
{
	struct aic8800_flash_bank *aic8800_bank;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	aic8800_bank = malloc(sizeof(struct aic8800_flash_bank));

	bank->driver_priv = aic8800_bank;
	aic8800_bank->probed = false;

	return ERROR_OK;
}

static int aic8800_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	int retval;
	uint32_t addr_4k, len;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}
	
	if ((last > (bank->size / AIC8800_FLASH_SECSIZE)) || (first > last)) {
		LOG_ERROR("invalid first and last param");
		return ERROR_FAIL;
	}

	addr_4k = AIC8800_FLASH_BASE + first * AIC8800_FLASH_SECSIZE;
	len = AIC8800_FLASH_SECSIZE * (last - first + 1);

	if (len == bank->size) {
		retval = romapi_ChipErase(bank);
		if (retval == ERROR_OK) {
			retval = romapi_CacheInvalidAll(bank);
		}
	} else {
		retval = romapi_Erase(bank, addr_4k, len);
		if (retval == ERROR_OK) {
			retval = romapi_CacheInvalidRange(bank, addr_4k, len);
		}
	}

	return retval;
}

static int aic8800_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	int retval;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if ((offset % AIC8800_FLASH_PAGESIZE) != 0) {
		LOG_WARNING("offset 0x%" PRIx32 " breaks required %d-byte alignment",
			offset, AIC8800_FLASH_PAGESIZE);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	if ((count % AIC8800_FLASH_PAGESIZE) != 0) {
		LOG_WARNING("count 0x%" PRIx32 " breaks required %d-byte alignment",
			offset, AIC8800_FLASH_PAGESIZE);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	retval = romapi_Write(bank, offset, count, buffer);
	if (retval == ERROR_OK) {
		retval = romapi_CacheInvalidRange(bank, offset, count);
	}

	return retval;
}

static void init_rom_api_call_code(struct aic8800_rom_api_call_code_t *call_code, uint32_t api_addr)
{
	memcpy(call_code, &aic8800_rom_api_call_code_example, sizeof(struct aic8800_rom_api_call_code_t));
	call_code->api_addr = api_addr;
}

static int aic8800_probe(struct flash_bank *bank)
{
	int retval;
	uint32_t size;
	struct target *target = bank->target;
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;
	uint32_t rom_api_table[dimof(aic8800_bank->rom_api_call_code)];

	retval = target_read_buffer(target, AIC8800_ROM_APITBL_BASE, sizeof(rom_api_table), (uint8_t *)rom_api_table);
	if (retval != ERROR_OK)
		return retval;

	aic8800_bank->probed = false;

	// read flash size
	retval = romapi_ChipSizeGet(bank, &size);
	if (retval != ERROR_OK)
		return retval;
	LOG_INFO("Flash Size = %" PRIu32 "kbytes", size / 1024);

	bank->base = AIC8800_FLASH_BASE;
	bank->size = size;
	bank->num_sectors = size / AIC8800_FLASH_SECSIZE;
	bank->write_start_alignment = AIC8800_FLASH_PAGESIZE;
	bank->write_end_alignment = AIC8800_FLASH_PAGESIZE;
	bank->sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);

	for (unsigned int i = 0; i < bank->num_sectors; i++) {
		bank->sectors[i].offset = i * AIC8800_FLASH_SECSIZE;
		bank->sectors[i].size = AIC8800_FLASH_SECSIZE;
		bank->sectors[i].is_erased = -1;
		bank->sectors[i].is_protected = 0;
	}

	for (unsigned int i = 0; i < dimof(aic8800_bank->rom_api_call_code); i++) {
		struct aic8800_rom_api_call_code_t *call_code = &aic8800_bank->rom_api_call_code[i];
		init_rom_api_call_code(call_code, rom_api_table[i]);
	}
	
	aic8800_bank->armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	aic8800_bank->armv7m_info.core_mode = ARM_MODE_THREAD;

	aic8800_bank->probed = true;

	return ERROR_OK;
}

static int aic8800_auto_probe(struct flash_bank *bank)
{
	struct aic8800_flash_bank *aic8800_bank = bank->driver_priv;

	if (aic8800_bank->probed)
		return ERROR_OK;
	return aic8800_probe(bank);
}

static int get_aic8800_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	int retval;
	uint32_t size;
	retval = romapi_ChipSizeGet(bank, &size);
	if (retval != ERROR_OK)
		return retval;
	command_print_sameline(cmd, "AIC8800 Flash Size = %" PRIu32 "kbytes", size / 1024);
	return ERROR_OK;
}

const struct flash_driver aic8800_flash = {
	.name = "aic8800",
	.flash_bank_command = aic8800_flash_bank_command,
	.erase = aic8800_erase,
	.write = aic8800_write,
	.read = default_flash_read,
	.probe = aic8800_probe,
	.auto_probe = aic8800_auto_probe,
	.erase_check = default_flash_blank_check,
	.info = get_aic8800_info,
	.free_driver_priv = default_flash_free_driver_priv,
};
