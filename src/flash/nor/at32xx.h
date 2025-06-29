
#ifndef AT32_XX_H
#define AT32_XX_H

#define NUM_OF_MCU_TYPE                   0x0D

#define AT32F403XX_ID                     0x02
#define AT32F413XX_ID                     0x04
#define AT32F415XX_ID                     0x05
#define AT32F403AXX_ID                   0x07
#define AT32F407XX_ID                     0x08
#define AT32F421XX_ID                     0x09
#define AT32F435XX_ID                     0x0D
#define AT32F437XX_ID                     0x0E
#define AT32F425XX_ID                     0x0F
#define AT32L021XX_ID                     0x10
#define AT32WB415XX_ID                  0x11
#define AT32F423XX_ID                     0x12

/* at32 mcu type*/
typedef struct mcu_type_info_
{
	uint8_t        project_id;
	uint32_t       flash_bank1_reg;
	uint32_t       flash_bank2_reg;
	uint32_t       usd_addr;
	const char     name[32];
}mcu_type_info;

extern mcu_type_info at32_mcu_type[NUM_OF_MCU_TYPE];

#endif


