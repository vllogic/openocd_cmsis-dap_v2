// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2008 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 *                                                                         *
 *   Copyright (C) 2011 by Andreas Fritiofson                              *
 *   andreas.fritiofson@gmail.com                                          *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "imp.h"
#include "helper/binarybuffer.h"
#include "target/algorithm.h"
#include "target/cortex_m.h"

/* puyaf0x register locations */

#define PUYA_PAGE_SIZE 128

#define FLASH_REG_BASE_B0 0x40022000
#define FLASH_REG_BASE_B1 0x40022040

#define STM32_FLASH_OBR     0x1C // nope

#define PUYA_FLASH_ACR     0x00
#define PUYA_FLASH_KEYR    0x08 // key
#define PUYA_FLASH_OPTKEYR 0x0C // options key
#define PUYA_FLASH_SR      0x10 // status
#define PUYA_FLASH_CR      0x14 // command
#define PUYA_FLASH_WRPR    0x2C

/* TODO: Check if code using these really should be hard coded to bank 0.
 * There are valid cases, on dual flash devices the protection of the
 * second bank is done on the bank0 reg's. */
#define PUYA_FLASH_KEYR_B0    0x40022004
#define PUYA_FLASH_OPTKEYR_B0 0x40022008
#define PUYA_FLASH_SR_B0      0x4002200C
#define PUYA_FLASH_CR_B0      0x40022010
#define STM32_FLASH_AR_B0      0x40022014
#define STM32_FLASH_OBR_B0     0x4002201C
#define PUYA_FLASH_WRPR_B0    0x40022020

/* option byte location */

#define STM32_OB_RDP		0x1FFFF800

/* FLASH_CR register bits */

#define FLASH_PG			(1 << 0) //ver
#define FLASH_PER			(1 << 1) //ver
#define FLASH_MER			(1 << 2) //ver
#define FLASH_SER           (1 << 11) //puya, sector erase
#define FLASH_OPTSTRT		(1 << 17) // puya
#define FLASH_PGSTRT        (1 << 19) // puya
#define FLASH_EOPIE         (1 << 24) // puya
#define FLASH_ERRIE         (1 << 25) // puya
#define FLASH_OBL_LAUNCH	(1 << 27) // ver
#define FLASH_OPTLOCK       (1 << 30) // puya
#define FLASH_LOCK			(1 << 31) // ver

#define FLASH_STRT	        (0) // nope!
#define FLASH_OPTWRE	    (0) // nope!
#define FLASH_OPTPG			(0) //nope!
#define FLASH_OPTER			(0) // nope!

/* FLASH_SR register bits */

#define FLASH_BSY		(1 << 16) //ver
#define FLASH_WRPRTERR	(1 << 4) // ver - WRP_ERR?
#define FLASH_EOP		(1 << 0) //ver
#define FLASH_OPTVERR   (1 << 15)
#define FLASH_PGERR		(1 << 2) // nope

/* STM32_FLASH_OBR bit definitions (reading) */

// no obr reg...
#define OPT_ERROR		0
#define OPT_READOUT		1
#define OPT_RDWDGSW		2
#define OPT_RDRSTSTOP	3
#define OPT_RDRSTSTDBY	4
#define OPT_BFB2		5	/* dual flash bank only */

/* register unlock keys */

#define KEY1			0x45670123
#define KEY2			0xCDEF89AB

/* timeout values */

#define FLASH_PRE_TIMEOUT 100
#define FLASH_WRITE_TIMEOUT 10
#define FLASH_ERASE_TIMEOUT 100

struct puyaf0x_options {
	uint8_t rdp;
	uint8_t user;
	uint16_t data;
	uint32_t protection;
};

struct puyaf0x_flash_bank {
	struct puyaf0x_options option_bytes;
	int ppage_size;
	bool probed;

	bool has_dual_banks;
	/* used to access dual flash bank puyaf0xl */
	bool can_load_options;
	uint32_t register_base;
	uint8_t default_rdp;
	int user_data_offset;
	int option_offset;
	uint32_t user_bank_size;
};

static int puyaf0x_mass_erase(struct flash_bank *bank);
static int puyaf0x_write_sector(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t address, uint32_t words_count);

/* flash bank puyaf0x <base> <size> 0 0 <target#>
 */
FLASH_BANK_COMMAND_HANDLER(puyaf0x_flash_bank_command)
{
	struct puyaf0x_flash_bank *puyaf0x_info;

	if (CMD_ARGC < 6)
		return ERROR_COMMAND_SYNTAX_ERROR;

	puyaf0x_info = malloc(sizeof(struct puyaf0x_flash_bank));

	bank->driver_priv = puyaf0x_info;
	puyaf0x_info->probed = false;
	puyaf0x_info->has_dual_banks = false;
	puyaf0x_info->can_load_options = false;
	puyaf0x_info->register_base = FLASH_REG_BASE_B0;
	puyaf0x_info->user_bank_size = bank->size;

	/* The flash write must be aligned to a page boundary */
	bank->write_start_alignment = bank->write_end_alignment = PUYA_PAGE_SIZE;

	return ERROR_OK;
}

static inline int puyaf0x_get_flash_reg(struct flash_bank *bank, uint32_t reg)
{
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;
	return reg + puyaf0x_info->register_base;
}

static inline int puyaf0x_get_flash_status(struct flash_bank *bank, uint32_t *status)
{
	struct target *target = bank->target;
	return target_read_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_SR), status);
}

static int puyaf0x_wait_status_busy(struct flash_bank *bank, int timeout, bool expect_eop)
{
	struct target *target = bank->target;
	uint32_t status;
	int retval = ERROR_OK;

	/* wait for busy to clear */
	for (;;) {
		retval = puyaf0x_get_flash_status(bank, &status);
		if (retval != ERROR_OK)
			return retval;
		LOG_DEBUG("status: 0x%" PRIx32 "", status);
		if ((status & FLASH_BSY) == 0)
			break;
		if (timeout-- <= 0) {
			LOG_ERROR("timed out waiting for flash");
			return ERROR_FLASH_BUSY;
		}
		alive_sleep(1);
	}

	if (status & FLASH_WRPRTERR) {
		LOG_ERROR("puyaf0x device protected");
		retval = ERROR_FLASH_PROTECTED;
	}

	if (status & FLASH_OPTVERR) {
		LOG_ERROR("puya device programming option fail");
		retval = ERROR_FLASH_OPERATION_FAILED;
	}


	if (!(status & FLASH_EOP) && expect_eop)
	{
		LOG_ERROR("puya device programming failed / flash not erased");
		retval = ERROR_FLASH_OPERATION_FAILED;
	}

	/* Clear all possible flags */
	if (status & (FLASH_WRPRTERR | FLASH_PGERR | FLASH_EOP)) {
		target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_SR),
				FLASH_WRPRTERR | FLASH_OPTVERR | FLASH_EOP);
	}
	return retval;
}

static int puyaf0x_check_operation_supported(struct flash_bank *bank)
{
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;

	/* if we have a dual flash bank device then
	 * we need to perform option byte stuff on bank0 only */
	if (puyaf0x_info->register_base != FLASH_REG_BASE_B0) {
		LOG_ERROR("Option byte operations must use bank 0");
		return ERROR_FLASH_OPERATION_FAILED;
	}

	return ERROR_OK;
}

static int puyaf0x_read_options(struct flash_bank *bank)
{
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;
	struct target *target = bank->target;
	uint32_t option_bytes;
	int retval;

	/* read user and read protection option bytes, user data option bytes */
	retval = target_read_u32(target, STM32_FLASH_OBR_B0, &option_bytes);
	if (retval != ERROR_OK)
		return retval;

	puyaf0x_info->option_bytes.rdp = (option_bytes & (1 << OPT_READOUT)) ? 0 : puyaf0x_info->default_rdp;
	puyaf0x_info->option_bytes.user = (option_bytes >> puyaf0x_info->option_offset >> 2) & 0xff;
	puyaf0x_info->option_bytes.data = (option_bytes >> puyaf0x_info->user_data_offset) & 0xffff;

	/* read write protection option bytes */
	retval = target_read_u32(target, PUYA_FLASH_WRPR_B0, &puyaf0x_info->option_bytes.protection);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}

static int puyaf0x_erase_options(struct flash_bank *bank)
{
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;
	struct target *target = bank->target;

	/* read current options */
	puyaf0x_read_options(bank);

	/* unlock flash registers */
	int retval = target_write_u32(target, PUYA_FLASH_KEYR_B0, KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, PUYA_FLASH_KEYR_B0, KEY2);
	if (retval != ERROR_OK)
		goto flash_lock;

	/* unlock option flash registers */
	retval = target_write_u32(target, PUYA_FLASH_OPTKEYR_B0, KEY1);
	if (retval != ERROR_OK)
		goto flash_lock;
	retval = target_write_u32(target, PUYA_FLASH_OPTKEYR_B0, KEY2);
	if (retval != ERROR_OK)
		goto flash_lock;

	/* erase option bytes */
	retval = target_write_u32(target, PUYA_FLASH_CR_B0, FLASH_OPTER | FLASH_OPTWRE);
	if (retval != ERROR_OK)
		goto flash_lock;
	retval = target_write_u32(target, PUYA_FLASH_CR_B0, FLASH_OPTER | FLASH_STRT | FLASH_OPTWRE);
	if (retval != ERROR_OK)
		goto flash_lock;

	retval = puyaf0x_wait_status_busy(bank, FLASH_ERASE_TIMEOUT, true);
	if (retval != ERROR_OK)
		goto flash_lock;

	/* clear read protection option byte
	 * this will also force a device unlock if set */
	puyaf0x_info->option_bytes.rdp = puyaf0x_info->default_rdp;

	return ERROR_OK;

flash_lock:
	target_write_u32(target, PUYA_FLASH_CR_B0, FLASH_LOCK);
	return retval;
}

static int puyaf0x_write_options(struct flash_bank *bank)
{
	struct puyaf0x_flash_bank *puyaf0x_info = NULL;
	struct target *target = bank->target;

	puyaf0x_info = bank->driver_priv;

	/* unlock flash registers */
	int retval = target_write_u32(target, PUYA_FLASH_KEYR_B0, KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, PUYA_FLASH_KEYR_B0, KEY2);
	if (retval != ERROR_OK)
		goto flash_lock;

	/* unlock option flash registers */
	retval = target_write_u32(target, PUYA_FLASH_OPTKEYR_B0, KEY1);
	if (retval != ERROR_OK)
		goto flash_lock;
	retval = target_write_u32(target, PUYA_FLASH_OPTKEYR_B0, KEY2);
	if (retval != ERROR_OK)
		goto flash_lock;

	/* program option bytes */
	retval = target_write_u32(target, PUYA_FLASH_CR_B0, FLASH_OPTPG | FLASH_OPTWRE);
	if (retval != ERROR_OK)
		goto flash_lock;

	uint8_t opt_bytes[16];

	target_buffer_set_u16(target, opt_bytes, puyaf0x_info->option_bytes.rdp);
	target_buffer_set_u16(target, opt_bytes + 2, puyaf0x_info->option_bytes.user);
	target_buffer_set_u16(target, opt_bytes + 4, puyaf0x_info->option_bytes.data & 0xff);
	target_buffer_set_u16(target, opt_bytes + 6, (puyaf0x_info->option_bytes.data >> 8) & 0xff);
	target_buffer_set_u16(target, opt_bytes + 8, puyaf0x_info->option_bytes.protection & 0xff);
	target_buffer_set_u16(target, opt_bytes + 10, (puyaf0x_info->option_bytes.protection >> 8) & 0xff);
	target_buffer_set_u16(target, opt_bytes + 12, (puyaf0x_info->option_bytes.protection >> 16) & 0xff);
	target_buffer_set_u16(target, opt_bytes + 14, (puyaf0x_info->option_bytes.protection >> 24) & 0xff);

	/* Block write is preferred in favour of operation with ancient ST-Link
	 * firmwares without 16-bit memory access. See
	 * 480: flash: puyaf0x: write option bytes using the loader
	 * https://review.openocd.org/c/openocd/+/480
	 */
	// TODO: solve this
	//retval = puyaf0x_write_block(bank, opt_bytes, STM32_OB_RDP, sizeof(opt_bytes) / 2);

flash_lock:
	{
		int retval2 = target_write_u32(target, PUYA_FLASH_CR_B0, FLASH_LOCK);
		if (retval == ERROR_OK)
			retval = retval2;
	}
	return retval;
}

static int puyaf0x_protect_check(struct flash_bank *bank)
{
	struct target *target = bank->target;
	uint32_t protection;

	int retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	/* medium density - each bit refers to a 4 sector protection block
	 * high density - each bit refers to a 2 sector protection block
	 * bit 31 refers to all remaining sectors in a bank */
	retval = target_read_u32(target, PUYA_FLASH_WRPR_B0, &protection);
	if (retval != ERROR_OK)
		return retval;

	for (unsigned int i = 0; i < bank->num_prot_blocks; i++)
		bank->prot_blocks[i].is_protected = (protection & (1 << i)) ? 0 : 1;

	return ERROR_OK;
}

// puya tested ok
static int puyaf0x_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	struct target *target = bank->target;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if ((first == 0) && (last == (bank->num_sectors - 1)))
		return puyaf0x_mass_erase(bank);

	// check busy, maybe another operation is pending
	int retval = puyaf0x_wait_status_busy(bank, FLASH_PRE_TIMEOUT, false);
	if (retval != ERROR_OK)
		return retval;

	/* unlock flash registers */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY2);
	if (retval != ERROR_OK)
		goto flash_lock;

	for (unsigned int i = first; i <= last; i++) {
		retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_PER /*| FLASH_EOPIE | FLASH_ERRIE*/);
		if (retval != ERROR_OK)
			goto flash_lock;
		
		// todo: better find out base address
		retval = target_write_u32(target, 0x08000000 + bank->sectors[i].offset, 0xFFFFFFFF);
		if (retval != ERROR_OK) {
			LOG_DEBUG("Ignoring address write retval %d ", retval);
		}

		retval = puyaf0x_wait_status_busy(bank, FLASH_ERASE_TIMEOUT, false /*true see FlashPrg.c */);
		if (retval != ERROR_OK)
			goto flash_lock;
	}

flash_lock:
	{
		int retval2 = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_LOCK);
		if (retval == ERROR_OK)
			retval = retval2;
	}
	return retval;
}

static int puyaf0x_protect(struct flash_bank *bank, int set, unsigned int first,
		unsigned int last)
{
	struct target *target = bank->target;
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	int retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	retval = puyaf0x_erase_options(bank);
	if (retval != ERROR_OK) {
		LOG_ERROR("puyaf0x failed to erase options");
		return retval;
	}

	for (unsigned int i = first; i <= last; i++) {
		if (set)
			puyaf0x_info->option_bytes.protection &= ~(1 << i);
		else
			puyaf0x_info->option_bytes.protection |= (1 << i);
	}

	return puyaf0x_write_options(bank);
}

/** Writes a block to flash either using target algorithm
 *  or use fallback, host controlled halfword-by-halfword access.
 *  Flash controller must be unlocked before this call.
 */
static int puyaf0x_write_sector(struct flash_bank *bank,
		const uint8_t *buffer, uint32_t address, uint32_t words_count)
{
	struct target *target = bank->target;
	int retval;

	/* The flash write must be aligned to a PUYA_PAGE_SIZE boundary.
	 * The flash infrastructure ensures it, do just a security check
	 */
	assert(address % PUYA_PAGE_SIZE == 0);
	assert(words_count > 0);

	//LOG_DEBUG("words count %d address 0x%x", words_count - 1, address);
	
	if (words_count > 1) {
		retval = target_write_memory(target, address, 4, words_count - 1, buffer);
		if (retval != ERROR_OK)
			return retval;
		address += 4 * (words_count - 1);
		buffer += 4 * (words_count - 1);
	}

	// set FLASH_PGSTRT before writing last word

	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_PG /*| FLASH_EOPIE | FLASH_ERRIE*/ | FLASH_PGSTRT);
	if (retval != ERROR_OK)
		return retval;

	retval = target_write_memory(target, address, 4, 1, buffer);
	if (retval != ERROR_OK) {
		LOG_DEBUG("Ignoring final address write retval %d ", retval);
		//return retval;
	}

	retval = puyaf0x_wait_status_busy(bank, 5, false/*true*/);
	if (retval != ERROR_OK)
		return retval;

	return retval;
}

static int puyaf0x_write(struct flash_bank *bank, const uint8_t *buffer,
		uint32_t offset, uint32_t count)
{
	struct target *target = bank->target;

	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* The flash write must be aligned to a word boundary (32bit).
	 * The flash infrastructure ensures it, do just a security check
	 */
	assert(offset % PUYA_PAGE_SIZE == 0);
	assert(count % PUYA_PAGE_SIZE == 0);

	int retval, retval2;


	// check busy, maybe another operation is pending
	retval = puyaf0x_wait_status_busy(bank, FLASH_PRE_TIMEOUT, false);
	if (retval != ERROR_OK)
		return retval;

	/* unlock flash registers */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY2);
	if (retval != ERROR_OK)
		goto reset_pg_and_lock;

	/* enable flash programming */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_PG /*| FLASH_EOPIE | FLASH_ERRIE*/);
	if (retval != ERROR_OK)
		goto reset_pg_and_lock;
	
	for (unsigned int sector=0; sector < bank->num_sectors; sector++)
	{
		if (bank->sectors[sector].offset == offset)
		{
			// need to program this sector
			/* write to flash */
			retval = puyaf0x_write_sector(bank, buffer, bank->base + offset, bank->sectors[sector].size / 4);
			if (retval != ERROR_OK)
				goto reset_pg_and_lock;

			offset += bank->sectors[sector].size;
			buffer += bank->sectors[sector].size;
		}
	}


reset_pg_and_lock:
	retval2 = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_LOCK);
	if (retval == ERROR_OK)
		retval = retval2;

	return retval;
}

struct puyaf0x_property_addr {
	uint32_t device_id;
	uint32_t flash_size;
};

static int puyaf0x_get_property_addr(struct target *target, struct puyaf0x_property_addr *addr)
{
	if (!target_was_examined(target)) {
		LOG_ERROR("Target not examined yet");
		return ERROR_TARGET_NOT_EXAMINED;
	}

	switch (cortex_m_get_impl_part(target)) {
	case CORTEX_M0P_PARTNO:
		addr->device_id = 0x40015800;
		addr->flash_size = 0x1FFF0FFC; // not sure
		return ERROR_OK;
	default:
		LOG_ERROR("Cannot identify target as a puyaf0x");
		return ERROR_FAIL;
	}
}

static int puyaf0x_get_device_id(struct flash_bank *bank, uint32_t *device_id)
{
	struct target *target = bank->target;
	struct puyaf0x_property_addr addr;

	int retval = puyaf0x_get_property_addr(target, &addr);
	if (retval != ERROR_OK)
		return retval;

	return target_read_u32(target, addr.device_id, device_id);
}

static int puyaf0x_get_flash_size(struct flash_bank *bank, uint16_t *flash_size_in_kb, uint16_t *ram)
{
	struct target *target = bank->target;
	struct puyaf0x_property_addr addr;

	int retval = puyaf0x_get_property_addr(target, &addr);
	if (retval != ERROR_OK)
		return retval;

	uint16_t value;
	retval = target_read_u16(target, addr.flash_size, &value);
	if (retval != ERROR_OK)
		return retval;
	switch (value & 0x7)
	{
		case 0:
			*flash_size_in_kb = 8;
			break;
		case 1:
			*flash_size_in_kb = 16;
			break;
		case 2:
			*flash_size_in_kb = 24;
			break;
		case 3:
			*flash_size_in_kb = 32;
			break;
		case 4:
			*flash_size_in_kb = 40;
			break;
		case 5:
			*flash_size_in_kb = 48;
			break;
		case 6:
			*flash_size_in_kb = 56;
			break;
		case 7:
			*flash_size_in_kb = 64;
			break;
	}

	switch ((value & 0x30)>>4)
	{
		case 0:
			*ram = 2;
			break;
		case 1:
			*ram = 4;
			break;
		case 2:
			*ram = 8;
			break;
		case 3:
			*ram = 16;
			break;
	}

	return ERROR_OK;
}

static int puyaf0x_probe(struct flash_bank *bank)
{
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;
	uint16_t flash_size_in_kb;
	uint16_t max_flash_size_in_kb;
	uint32_t dbgmcu_idcode;
	int page_size;
	uint32_t base_address = 0x08000000;

	puyaf0x_info->probed = false;
	puyaf0x_info->register_base = FLASH_REG_BASE_B0;
	puyaf0x_info->user_data_offset = 10;
	puyaf0x_info->option_offset = 0;

	/* default factory read protection level 0 */
	puyaf0x_info->default_rdp = 0xA5;

	/* read stm32 device id register */
	int retval = puyaf0x_get_device_id(bank, &dbgmcu_idcode);
	if (retval != ERROR_OK)
		return retval;

	LOG_INFO("device id = 0x%08" PRIx32 "", dbgmcu_idcode);

	uint16_t device_id = dbgmcu_idcode & 0xfff;
	uint16_t rev_id = dbgmcu_idcode >> 16;

	/* set page size, protection granularity and max flash size depending on family */
	switch (device_id) {
	case 0x00:
		if (rev_id == 0x6000)
		{
			LOG_WARNING("Puya MCU detected!");
			page_size = PUYA_PAGE_SIZE;
			puyaf0x_info->ppage_size = 4;
			max_flash_size_in_kb = 32;
			puyaf0x_info->user_data_offset = 16;
			puyaf0x_info->option_offset = 6;
			puyaf0x_info->default_rdp = 0xAA;
			puyaf0x_info->can_load_options = true;
			break;
		}
		__attribute__ ((fallthrough));
	default:
		LOG_WARNING("Cannot identify target as a Puya32f0x family.");
		return ERROR_FAIL;
	}

	/* get flash size from target. */
	uint16_t ram;
	retval = puyaf0x_get_flash_size(bank, &flash_size_in_kb, &ram);

	/* failed reading flash size or flash size invalid (early silicon),
	 * default to max target family */
	if (retval != ERROR_OK || flash_size_in_kb == 0xffff || flash_size_in_kb == 0) {
		LOG_WARNING("PY32 flash size failed, probe inaccurate - assuming %dk flash",
			max_flash_size_in_kb);
		flash_size_in_kb = max_flash_size_in_kb;
	}
	else
		LOG_INFO("PY32 flash size %dk, ram %dk",
				 max_flash_size_in_kb, ram);

	if (puyaf0x_info->has_dual_banks) {
		/* split reported size into matching bank */
		if (bank->base != 0x08080000) {
			/* bank 0 will be fixed 512k */
			flash_size_in_kb = 512;
		} else {
			flash_size_in_kb -= 512;
			/* bank1 also uses a register offset */
			puyaf0x_info->register_base = FLASH_REG_BASE_B1;
			base_address = 0x08080000;
		}
	}

	/* if the user sets the size manually then ignore the probed value
	 * this allows us to work around devices that have a invalid flash size register value */
	if (puyaf0x_info->user_bank_size) {
		LOG_INFO("ignoring flash probed value, using configured bank size");
		flash_size_in_kb = puyaf0x_info->user_bank_size / 1024;
	}

	LOG_INFO("flash size = %d KiB", flash_size_in_kb);

	/* did we assign flash size? */
	assert(flash_size_in_kb != 0xffff);

	/* calculate numbers of pages */
	int num_pages = flash_size_in_kb * 1024 / page_size;

	/* check that calculation result makes sense */
	assert(num_pages > 0);

	free(bank->sectors);
	bank->sectors = NULL;

	free(bank->prot_blocks);
	bank->prot_blocks = NULL;

	bank->base = base_address;
	bank->size = (num_pages * page_size);

	bank->num_sectors = num_pages;

	LOG_INFO("page size = %d", page_size);
	LOG_INFO("number of sectors/pages = %d", bank->num_sectors);

	bank->sectors = alloc_block_array(0, page_size, num_pages);
	if (!bank->sectors)
		return ERROR_FAIL;

	/* calculate number of write protection blocks */
	int num_prot_blocks = num_pages / puyaf0x_info->ppage_size;
	if (num_prot_blocks > 32)
		num_prot_blocks = 32;

	bank->num_prot_blocks = num_prot_blocks;
	bank->prot_blocks = alloc_block_array(0, puyaf0x_info->ppage_size * page_size, num_prot_blocks);
	if (!bank->prot_blocks)
		return ERROR_FAIL;

	if (num_prot_blocks == 32)
		bank->prot_blocks[31].size = (num_pages - (31 * puyaf0x_info->ppage_size)) * page_size;

	/* switch to 24 MHz */
	uint32_t rcc_icscr;
	retval = target_read_u32(bank->target, 0x40021000 + 0x4, &rcc_icscr);
	if (retval != ERROR_OK)
		return retval;
	uint32_t rcc_icscr_calibr;
	retval = target_read_u32(bank->target, 0x1FFF0F10, &rcc_icscr_calibr);
	if (retval != ERROR_OK)
		return retval;

	retval = target_write_u32(bank->target, 0x40021000 + 0x4,
							  (rcc_icscr & 0xFFFF0000) | rcc_icscr_calibr);
	if (retval != ERROR_OK)
		return retval;

	puyaf0x_info->probed = true;

	return ERROR_OK;
}

static int puyaf0x_auto_probe(struct flash_bank *bank)
{
	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;
	if (puyaf0x_info->probed)
		return ERROR_OK;
	return puyaf0x_probe(bank);
}


static int get_puyaf0x_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	uint32_t dbgmcu_idcode;

	/* read stm32 device id register */
	int retval = puyaf0x_get_device_id(bank, &dbgmcu_idcode);
	if (retval != ERROR_OK)
		return retval;

	const char *device_str;
	if (0x60001000 == dbgmcu_idcode)
		device_str = "Puya MCU";
	else
	{
		command_print_sameline(cmd, "Cannot identify target as a STM32F0/1/3\n");
		return ERROR_FAIL;
	}

	command_print_sameline(cmd, "%s", device_str);

	return ERROR_OK;
}

COMMAND_HANDLER(puyaf0x_handle_lock_command)
{
	struct target *target = NULL;
	struct puyaf0x_flash_bank *puyaf0x_info = NULL;

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	puyaf0x_info = bank->driver_priv;

	target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	if (puyaf0x_erase_options(bank) != ERROR_OK) {
		command_print(CMD, "puyaf0x failed to erase options");
		return ERROR_OK;
	}

	/* set readout protection */
	puyaf0x_info->option_bytes.rdp = 0;

	if (puyaf0x_write_options(bank) != ERROR_OK) {
		command_print(CMD, "puyaf0x failed to lock device");
		return ERROR_OK;
	}

	command_print(CMD, "puyaf0x locked");

	return ERROR_OK;
}

COMMAND_HANDLER(puyaf0x_handle_unlock_command)
{
	struct target *target = NULL;

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	if (puyaf0x_erase_options(bank) != ERROR_OK) {
		command_print(CMD, "puyaf0x failed to erase options");
		return ERROR_OK;
	}

	if (puyaf0x_write_options(bank) != ERROR_OK) {
		command_print(CMD, "puyaf0x failed to unlock device");
		return ERROR_OK;
	}

	command_print(CMD, "puyaf0x unlocked.\n"
			"INFO: a reset or power cycle is required "
			"for the new settings to take effect.");

	return ERROR_OK;
}

COMMAND_HANDLER(puyaf0x_handle_options_read_command)
{
	uint32_t optionbyte, protection;
	struct target *target = NULL;
	struct puyaf0x_flash_bank *puyaf0x_info = NULL;

	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	puyaf0x_info = bank->driver_priv;

	target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	retval = target_read_u32(target, STM32_FLASH_OBR_B0, &optionbyte);
	if (retval != ERROR_OK)
		return retval;

	uint16_t user_data = optionbyte >> puyaf0x_info->user_data_offset;

	retval = target_read_u32(target, PUYA_FLASH_WRPR_B0, &protection);
	if (retval != ERROR_OK)
		return retval;

	if (optionbyte & (1 << OPT_ERROR))
		command_print(CMD, "option byte complement error");

	command_print(CMD, "option byte register = 0x%" PRIx32 "", optionbyte);
	command_print(CMD, "write protection register = 0x%" PRIx32 "", protection);

	command_print(CMD, "read protection: %s",
				(optionbyte & (1 << OPT_READOUT)) ? "on" : "off");

	/* user option bytes are offset depending on variant */
	optionbyte >>= puyaf0x_info->option_offset;

	command_print(CMD, "watchdog: %sware",
				(optionbyte & (1 << OPT_RDWDGSW)) ? "soft" : "hard");

	command_print(CMD, "stop mode: %sreset generated upon entry",
				(optionbyte & (1 << OPT_RDRSTSTOP)) ? "no " : "");

	command_print(CMD, "standby mode: %sreset generated upon entry",
				(optionbyte & (1 << OPT_RDRSTSTDBY)) ? "no " : "");

	if (puyaf0x_info->has_dual_banks)
		command_print(CMD, "boot: bank %d", (optionbyte & (1 << OPT_BFB2)) ? 0 : 1);

	command_print(CMD, "user data = 0x%02" PRIx16 "", user_data);

	return ERROR_OK;
}

COMMAND_HANDLER(puyaf0x_handle_options_write_command)
{
	struct target *target = NULL;
	struct puyaf0x_flash_bank *puyaf0x_info = NULL;
	uint8_t optionbyte;
	uint16_t useropt;

	if (CMD_ARGC < 2)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	puyaf0x_info = bank->driver_priv;

	target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	retval = puyaf0x_read_options(bank);
	if (retval != ERROR_OK)
		return retval;

	/* start with current options */
	optionbyte = puyaf0x_info->option_bytes.user;
	useropt = puyaf0x_info->option_bytes.data;

	/* skip over flash bank */
	CMD_ARGC--;
	CMD_ARGV++;

	while (CMD_ARGC) {
		if (strcmp("SWWDG", CMD_ARGV[0]) == 0)
			optionbyte |= (1 << 0);
		else if (strcmp("HWWDG", CMD_ARGV[0]) == 0)
			optionbyte &= ~(1 << 0);
		else if (strcmp("NORSTSTOP", CMD_ARGV[0]) == 0)
			optionbyte |= (1 << 1);
		else if (strcmp("RSTSTOP", CMD_ARGV[0]) == 0)
			optionbyte &= ~(1 << 1);
		else if (strcmp("NORSTSTNDBY", CMD_ARGV[0]) == 0)
			optionbyte |= (1 << 2);
		else if (strcmp("RSTSTNDBY", CMD_ARGV[0]) == 0)
			optionbyte &= ~(1 << 2);
		else if (strcmp("USEROPT", CMD_ARGV[0]) == 0) {
			if (CMD_ARGC < 2)
				return ERROR_COMMAND_SYNTAX_ERROR;
			COMMAND_PARSE_NUMBER(u16, CMD_ARGV[1], useropt);
			CMD_ARGC--;
			CMD_ARGV++;
		} else if (puyaf0x_info->has_dual_banks) {
			if (strcmp("BOOT0", CMD_ARGV[0]) == 0)
				optionbyte |= (1 << 3);
			else if (strcmp("BOOT1", CMD_ARGV[0]) == 0)
				optionbyte &= ~(1 << 3);
			else
				return ERROR_COMMAND_SYNTAX_ERROR;
		} else
			return ERROR_COMMAND_SYNTAX_ERROR;
		CMD_ARGC--;
		CMD_ARGV++;
	}

	if (puyaf0x_erase_options(bank) != ERROR_OK) {
		command_print(CMD, "puyaf0x failed to erase options");
		return ERROR_OK;
	}

	puyaf0x_info->option_bytes.user = optionbyte;
	puyaf0x_info->option_bytes.data = useropt;

	if (puyaf0x_write_options(bank) != ERROR_OK) {
		command_print(CMD, "puyaf0x failed to write options");
		return ERROR_OK;
	}

	command_print(CMD, "puyaf0x write options complete.\n"
				"INFO: %spower cycle is required "
				"for the new settings to take effect.",
				puyaf0x_info->can_load_options
					? "'puyaf0x options_load' command or " : "");

	return ERROR_OK;
}

COMMAND_HANDLER(puyaf0x_handle_options_load_command)
{
	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	struct puyaf0x_flash_bank *puyaf0x_info = bank->driver_priv;

	if (!puyaf0x_info->can_load_options) {
		LOG_ERROR("Command not applicable to puyaf0x devices - power cycle is "
			"required instead.");
		return ERROR_FAIL;
	}

	struct target *target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	retval = puyaf0x_check_operation_supported(bank);
	if (retval != ERROR_OK)
		return retval;

	/* unlock option flash registers */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY2);
	if (retval != ERROR_OK) {
		(void)target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_LOCK);
		return retval;
	}

	/* force re-load of option bytes - generates software reset */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_OBL_LAUNCH);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}

// puya verified ok
static int puyaf0x_mass_erase(struct flash_bank *bank)
{
	struct target *target = bank->target;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	// check busy, maybe another operation is pending
	int retval = puyaf0x_wait_status_busy(bank, FLASH_PRE_TIMEOUT, false);
	if (retval != ERROR_OK)
		return retval;

	/* unlock option flash registers */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY1);
	if (retval != ERROR_OK)
		return retval;
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_KEYR), KEY2);
	if (retval != ERROR_OK)
		goto flash_lock;

	/* mass erase flash memory */
	retval = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_MER | FLASH_EOPIE | FLASH_ERRIE);
	if (retval != ERROR_OK)
		goto flash_lock;
	
	// according to datasheet we should write something to flash
	// todo: get location
	retval = target_write_u32(target, 0x08000000, 0xFFFFFFFF);
	if (retval != ERROR_OK) {
		LOG_DEBUG("Ignoring address write retval %d ", retval);
	}

	retval = puyaf0x_wait_status_busy(bank, FLASH_ERASE_TIMEOUT, true);
	if (retval != ERROR_OK)
		goto flash_lock;

flash_lock:
	{
		int retval2 = target_write_u32(target, puyaf0x_get_flash_reg(bank, PUYA_FLASH_CR), FLASH_LOCK);
		if (retval == ERROR_OK)
			retval = retval2;
	}
	return retval;
}

COMMAND_HANDLER(puyaf0x_handle_mass_erase_command)
{
	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (retval != ERROR_OK)
		return retval;

	retval = puyaf0x_mass_erase(bank);
	if (retval == ERROR_OK)
		command_print(CMD, "puya32f0x mass erase complete");
	else
		command_print(CMD, "puya32f0x mass erase failed");

	return retval;
}

static const struct command_registration puyaf0x_exec_command_handlers[] = {
	{
		.name = "lock",
		.handler = puyaf0x_handle_lock_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Lock entire flash device.",
	},
	{
		.name = "unlock",
		.handler = puyaf0x_handle_unlock_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Unlock entire protected flash device.",
	},
	{
		.name = "mass_erase",
		.handler = puyaf0x_handle_mass_erase_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Erase entire flash device.",
	},
	{
		.name = "options_read",
		.handler = puyaf0x_handle_options_read_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Read and display device option bytes.",
	},
	{
		.name = "options_write",
		.handler = puyaf0x_handle_options_write_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id ('SWWDG'|'HWWDG') "
			"('RSTSTNDBY'|'NORSTSTNDBY') "
			"('RSTSTOP'|'NORSTSTOP') ('USEROPT' user_data)",
		.help = "Replace bits in device option bytes.",
	},
	{
		.name = "options_load",
		.handler = puyaf0x_handle_options_load_command,
		.mode = COMMAND_EXEC,
		.usage = "bank_id",
		.help = "Force re-load of device option bytes.",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration puyaf0x_command_handlers[] = {
	{
		.name = "puyaf0x",
		.mode = COMMAND_ANY,
		.help = "puyaf0x flash command group",
		.usage = "",
		.chain = puyaf0x_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver puyaf0x_flash = {
	.name = "puyaf0x",
	.commands = puyaf0x_command_handlers,
	.flash_bank_command = puyaf0x_flash_bank_command,
	.erase = puyaf0x_erase,
	.protect = puyaf0x_protect,
	.write = puyaf0x_write,
	.read = default_flash_read,
	.probe = puyaf0x_probe,
	.auto_probe = puyaf0x_auto_probe,
	.erase_check = default_flash_blank_check,
	.protect_check = puyaf0x_protect_check,
	.info = get_puyaf0x_info,
	.free_driver_priv = default_flash_free_driver_priv,
};
