// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2022 by Talpa Chen                                      *
 *   talpachen@gmail.com                                                   *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/armv7m.h>

#ifndef dimof
#	define dimof(arr)				(sizeof(arr) / sizeof((arr)[0]))
#endif

/*
struct aic8800m40_rom_falsh_api_t {
	void (*undefined_api_0)(void);
	void (*undefined_api_1)(void);
	void (*undefined_api_2)(void);
	void (*undefined_api_3)(void);
	void (*undefined_api_4)(void);
	void (*undefined_api_6)(void);
	void (*undefined_api_7)(void);
	void (*undefined_api_8)(void);
	void (*undefined_api_9)(void);
	void (*undefined_api_10)(void);
	void (*undefined_api_11)(void);
	uint32_t (*ChipSizeGet)(void);
	void (*ChipErase)(void);
	int32_t (*Erase)(uint32_t addr_4k, uint32_t len);
	int32_t (*Write)(uint32_t addr_256, uint32_t len, uint32_t buf);
	int32_t (*Read)(uint32_t addr_256, uint32_t len, uint32_t buf);
	void (*CacheInvalidAll)(void);
	void (*CacheInvalidRange)(uint32_t addr, uint32_t len);
} aic8800m40_rom_falsh_api @ 0x00000198UL;
*/
#define AIC8800M40_ROM_APITBL_BASE	(0x00000198UL)

#define AIC8800M40_FLASH_BASE			0x08000000
#define AIC8800M40_FLASH_SECSIZE			0x1000
#define AIC8800M40_FLASH_PAGESIZE		0x100

#define STACK_DEFAULT				512
#define TIMEROUT_DEFAULT			1000
#define TIMEROUT_ERASE_4K			100
#define TIMEROUT_WRITE_4K			50

struct aic8800m40_rom_api_call_code_t {
	uint16_t ldrn_r3;	// 0x4b01
	uint16_t blx_r3;	// 0x4798
	uint16_t bkpt;	    // 0xbe00
	uint16_t nop;	    // 0xbf00
	uint32_t api_addr;	// api addr
};

struct aic8800m40_rom_api_call_code_t aic8800m40_rom_api_call_code_example = {
	.ldrn_r3 = 0x4b01,			/* LDR.N R3, [PC, #0x4]*/
	.blx_r3 = 0x4798,			/* BLX R3 */
	.bkpt = 0xbe00,				/* bkpt */
	.nop = 0xbf00,				/* NOP */
	.api_addr = 0x12345678,
};
#define CALL_CODE_BKPT_ADDR(enter_addr)		((enter_addr) + 4)

struct aic8800m40_flash_bank {
	bool probed;

	struct aic8800m40_rom_api_call_code_t rom_api_call_code[19];
	struct armv7m_algorithm armv7m_info;
};

static int romapi_chip_size_get(struct flash_bank *bank, uint32_t *chip_size)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	struct reg_param reg_params[2];

	retval = target_alloc_working_area(target, sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT);
		return retval;
	}
	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800m40_rom_api_call_code_t),
									(const uint8_t *)&aic8800m40_bank->rom_api_call_code[12]);
	if (retval != ERROR_OK) {
		target_free_working_area(target, algorithm);
		return retval;
	}

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN);
	init_reg_param(&reg_params[1], "sp", 32, PARAM_OUT);
	//buf_set_u32(reg_params[0].value, 0, 32, 0);
	buf_set_u32(reg_params[1].value, 0, 32, algorithm->address + algorithm->size);

	LOG_DEBUG("Running AIC8800M40 ChipSizeGet algorithm");
	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, CALL_CODE_BKPT_ADDR(algorithm->address),
									TIMEROUT_DEFAULT, &aic8800m40_bank->armv7m_info);
	if (retval != ERROR_OK)
		LOG_ERROR("Error executing ChipSizeGet algorithm");
	else
		*chip_size = buf_get_u32(reg_params[0].value, 0, 32);

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);

	return retval;
}

static int romapi_chip_erase(struct flash_bank *bank)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	struct reg_param reg_params[1];
	uint32_t timeout = (bank->size / 4096) * TIMEROUT_ERASE_4K;

	retval = target_alloc_working_area(target, sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT);
		return retval;
	}
	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800m40_rom_api_call_code_t),
									(const uint8_t *)&aic8800m40_bank->rom_api_call_code[13]);
	if (retval != ERROR_OK) {
		target_free_working_area(target, algorithm);
		return retval;
	}

	init_reg_param(&reg_params[0], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, algorithm->address + algorithm->size);

	LOG_DEBUG("Running AIC8800M40 ChipErase algorithm");
	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, CALL_CODE_BKPT_ADDR(algorithm->address),
									timeout, &aic8800m40_bank->armv7m_info);
	if (retval != ERROR_OK)
		LOG_ERROR("Error executing ChipErase algorithm");

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);

	return retval;
}

static uint32_t romapi_erase(struct flash_bank *bank, uint32_t addr, uint32_t len)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	struct reg_param reg_params[3];

	retval = target_alloc_working_area(target, sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT);
		return retval;
	}
	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800m40_rom_api_call_code_t),
									(const uint8_t *)&aic8800m40_bank->rom_api_call_code[14]);
	if (retval != ERROR_OK) {
		target_free_working_area(target, algorithm);
		return retval;
	}

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, addr);
	buf_set_u32(reg_params[1].value, 0, 32, len);
	buf_set_u32(reg_params[2].value, 0, 32, algorithm->address + algorithm->size);

	LOG_DEBUG("Running AIC8800M40 Erase algorithm");
	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, CALL_CODE_BKPT_ADDR(algorithm->address),
									TIMEROUT_ERASE_4K * (len / 4096), &aic8800m40_bank->armv7m_info);
	if (retval != ERROR_OK)
		LOG_ERROR("Error executing Erase algorithm");

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	return retval;
}

static int romapi_write(struct flash_bank *bank, uint32_t addr, uint32_t len, const uint8_t *buf)
{
	int retval;
	struct working_area *fifo;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	struct reg_param reg_params[4];

	retval = target_alloc_working_area(target, sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT);
		return retval;
	}
	retval = target_alloc_working_area(target, 4096, &fifo);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT + 4096);
		target_free_working_area(target, algorithm);
		return retval;
	}

	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800m40_rom_api_call_code_t),
									(const uint8_t *)&aic8800m40_bank->rom_api_call_code[15]);
	if (retval != ERROR_OK) {
		target_free_working_area(target, algorithm);
		target_free_working_area(target, fifo);
		return retval;
	}

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);
	init_reg_param(&reg_params[3], "sp", 32, PARAM_OUT);

	buf_set_u32(reg_params[2].value, 0, 32, fifo->address);
	buf_set_u32(reg_params[3].value, 0, 32, algorithm->address + algorithm->size);

	while (len) {
		uint32_t block;
		if (len <= 4096)
			block = len;
		else
			block = 4096;

		buf_set_u32(reg_params[0].value, 0, 32, addr);
		buf_set_u32(reg_params[1].value, 0, 32, block);
		buf_set_u32(reg_params[2].value, 0, 32, fifo->address);
		buf_set_u32(reg_params[3].value, 0, 32, algorithm->address + algorithm->size);

		retval = target_write_buffer(target, fifo->address, block, buf);
		if (retval != ERROR_OK)
			return retval;

		LOG_DEBUG("Running AIC8800M40 Write algorithm");
		retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
										algorithm->address, CALL_CODE_BKPT_ADDR(algorithm->address),
										TIMEROUT_WRITE_4K, &aic8800m40_bank->armv7m_info);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error executing Write algorithm");
			break;
		}

		addr += block;
		len -= block;
		buf += block;
	}

	target_free_working_area(target, fifo);
	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);

	return retval;
}

static int romapi_cache_invalid_all(struct flash_bank *bank)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	struct reg_param reg_params[1];

	retval = target_alloc_working_area(target, sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT);
		return retval;
	}
	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800m40_rom_api_call_code_t),
									(const uint8_t *)&aic8800m40_bank->rom_api_call_code[17]);
	if (retval != ERROR_OK) {
		target_free_working_area(target, algorithm);
		return retval;
	}

	init_reg_param(&reg_params[0], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, algorithm->address + algorithm->size);

	LOG_DEBUG("Running AIC8800M40 CacheInvalidAll algorithm");
	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, CALL_CODE_BKPT_ADDR(algorithm->address),
									TIMEROUT_DEFAULT, &aic8800m40_bank->armv7m_info);
	if (retval != ERROR_OK)
		LOG_ERROR("Error executing CacheInvalidAll algorithm");

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);

	return retval;
}

static int romapi_cache_invalid_range(struct flash_bank *bank, uint32_t addr, uint32_t len)
{
	int retval;
	struct working_area *algorithm;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	struct reg_param reg_params[3];

	retval = target_alloc_working_area(target, sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT, &algorithm);
	if (retval != ERROR_OK) {
		LOG_ERROR("Insufficient working area to initialize. You must allocate at least %zdB of working "
			"area in order to use this driver.", sizeof(struct aic8800m40_rom_api_call_code_t) + STACK_DEFAULT);
		return retval;
	}
	retval = target_write_buffer(target, algorithm->address, sizeof(struct aic8800m40_rom_api_call_code_t),
									(const uint8_t *)&aic8800m40_bank->rom_api_call_code[18]);
	if (retval != ERROR_OK) {
		target_free_working_area(target, algorithm);
		return retval;
	}

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);
	init_reg_param(&reg_params[2], "sp", 32, PARAM_OUT);
	buf_set_u32(reg_params[0].value, 0, 32, addr);
	buf_set_u32(reg_params[1].value, 0, 32, len);
	buf_set_u32(reg_params[2].value, 0, 32, algorithm->address + algorithm->size);

	LOG_DEBUG("Running AIC8800M40 CacheInvalidRange algorithm");
	retval = target_run_algorithm(target, 0, NULL, dimof(reg_params), reg_params,
									algorithm->address, CALL_CODE_BKPT_ADDR(algorithm->address),
									TIMEROUT_DEFAULT, &aic8800m40_bank->armv7m_info);
	if (retval != ERROR_OK)
		LOG_ERROR("Error executing CacheInvalidRange algorithm");

	target_free_working_area(target, algorithm);
	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);

	return retval;
}

FLASH_BANK_COMMAND_HANDLER(aic8800m40_flash_bank_command)
{
	struct aic8800m40_flash_bank *aic8800m40_bank;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	aic8800m40_bank = malloc(sizeof(struct aic8800m40_flash_bank));

	bank->driver_priv = aic8800m40_bank;
	aic8800m40_bank->probed = false;

	return ERROR_OK;
}

static int aic8800m40_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	int retval;
	uint32_t addr, len;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (last > (bank->size / AIC8800M40_FLASH_SECSIZE)) {
		LOG_ERROR("invalid first and last param");
		return ERROR_FAIL;
	}

	addr = AIC8800M40_FLASH_BASE + first * AIC8800M40_FLASH_SECSIZE;
	len = AIC8800M40_FLASH_SECSIZE * (last - first + 1);

	if (len == bank->size) {
		retval = romapi_chip_erase(bank);
		if (retval == ERROR_OK)
			retval = romapi_cache_invalid_all(bank);
	} else {
		retval = romapi_erase(bank, addr, len);
		if (retval == ERROR_OK)
			retval = romapi_cache_invalid_range(bank, addr, len);
	}

	return retval;
}

static int aic8800m40_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	int retval;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if ((offset % AIC8800M40_FLASH_PAGESIZE) != 0) {
		LOG_WARNING("offset 0x%" PRIx32 " breaks required %d-byte alignment",
			offset, AIC8800M40_FLASH_PAGESIZE);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	if ((count % AIC8800M40_FLASH_PAGESIZE) != 0) {
		LOG_WARNING("count 0x%" PRIx32 " breaks required %d-byte alignment",
			offset, AIC8800M40_FLASH_PAGESIZE);
		return ERROR_FLASH_DST_BREAKS_ALIGNMENT;
	}

	retval = romapi_write(bank, bank->base + offset, count, buffer);
	if (retval == ERROR_OK)
		retval = romapi_cache_invalid_range(bank, bank->base + offset, count);

	return retval;
}

static void init_rom_api_call_code(struct aic8800m40_rom_api_call_code_t *call_code, uint32_t api_addr)
{
	memcpy(call_code, &aic8800m40_rom_api_call_code_example, sizeof(struct aic8800m40_rom_api_call_code_t));
	call_code->api_addr = api_addr;
}

static int aic8800m40_probe(struct flash_bank *bank)
{
	int retval;
	uint32_t size;
	struct target *target = bank->target;
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;
	uint32_t rom_api_table[dimof(aic8800m40_bank->rom_api_call_code)];

	aic8800m40_bank->probed = false;

	aic8800m40_bank->armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	aic8800m40_bank->armv7m_info.core_mode = ARM_MODE_THREAD;

	retval = target_read_buffer(target, AIC8800M40_ROM_APITBL_BASE, sizeof(rom_api_table), (uint8_t *)rom_api_table);
	if (retval != ERROR_OK)
		return retval;

	for (unsigned int i = 0; i < dimof(aic8800m40_bank->rom_api_call_code); i++)
		init_rom_api_call_code(&aic8800m40_bank->rom_api_call_code[i], rom_api_table[i]);

	retval = romapi_chip_size_get(bank, &size);
	if (retval != ERROR_OK)
		return retval;
	LOG_INFO("Flash Size = %" PRIu32 "kbytes", size / 1024);

	bank->base = AIC8800M40_FLASH_BASE;
	bank->size = size;
	bank->num_sectors = size / AIC8800M40_FLASH_SECSIZE;
	bank->write_start_alignment = AIC8800M40_FLASH_PAGESIZE;
	bank->write_end_alignment = AIC8800M40_FLASH_PAGESIZE;
	bank->sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);

	for (unsigned int i = 0; i < bank->num_sectors; i++) {
		bank->sectors[i].offset = i * AIC8800M40_FLASH_SECSIZE;
		bank->sectors[i].size = AIC8800M40_FLASH_SECSIZE;
		bank->sectors[i].is_erased = -1;
		bank->sectors[i].is_protected = 0;
	}


	aic8800m40_bank->probed = true;

	return ERROR_OK;
}

static int aic8800m40_auto_probe(struct flash_bank *bank)
{
	struct aic8800m40_flash_bank *aic8800m40_bank = bank->driver_priv;

	if (aic8800m40_bank->probed)
		return ERROR_OK;
	return aic8800m40_probe(bank);
}

static int aic8800m40_get_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	int retval;
	uint32_t size;
	retval = romapi_chip_size_get(bank, &size);
	if (retval != ERROR_OK)
		return retval;
	command_print_sameline(cmd, "AIC8800M40 Flash Size = %" PRIu32 "kbytes", size / 1024);
	return ERROR_OK;
}

const struct flash_driver aic8800m40_flash = {
	.name = "aic8800m40",
	.flash_bank_command = aic8800m40_flash_bank_command,
	.erase = aic8800m40_erase,
	.write = aic8800m40_write,
	.read = default_flash_read,
	.probe = aic8800m40_probe,
	.auto_probe = aic8800m40_auto_probe,
	.erase_check = default_flash_blank_check,
	.info = aic8800m40_get_info,
	.free_driver_priv = default_flash_free_driver_priv,
};