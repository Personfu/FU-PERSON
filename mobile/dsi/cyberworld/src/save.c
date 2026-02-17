/*
 * CyberWorld — Save/Load System
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * Saves player data to SD card using FAT filesystem (libfat).
 * Save format: magic + Player struct + playtime + checksum.
 */
#include "save.h"
#include <fat.h>

#define SAVE_PATH "/cyberworld.sav"

static int fat_inited = 0;
static int playtime_frames = 0;

/* ══════════════════════════════════════════════════════════════
 *  INITIALIZE FAT FILESYSTEM
 * ══════════════════════════════════════════════════════════════ */
static int ensure_fat(void) {
    if (fat_inited) return 1;
    if (fatInitDefault()) {
        fat_inited = 1;
        return 1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  CALCULATE CHECKSUM (simple Fletcher-16)
 * ══════════════════════════════════════════════════════════════ */
static u32 calc_checksum(const u8 *data, int len) {
    u32 sum1 = 0;
    u32 sum2 = 0;
    for (int i = 0; i < len; i++) {
        sum1 = (sum1 + data[i]) % 255;
        sum2 = (sum2 + sum1) % 255;
    }
    return (sum2 << 16) | sum1;
}

/* ══════════════════════════════════════════════════════════════
 *  INCREMENT PLAYTIME (call every frame from game loop)
 * ══════════════════════════════════════════════════════════════ */
void save_tick(void) {
    playtime_frames++;
}

int save_get_playtime_seconds(void) {
    return playtime_frames / 60;
}

/* ══════════════════════════════════════════════════════════════
 *  SAVE GAME
 * ══════════════════════════════════════════════════════════════ */
int save_game(Player *p) {
    if (!ensure_fat()) return 0;

    FILE *f = fopen(SAVE_PATH, "wb");
    if (!f) return 0;

    SaveData sd;
    memset(&sd, 0, sizeof(SaveData));
    sd.magic = SAVE_MAGIC;
    memcpy(&sd.player, p, sizeof(Player));
    sd.playtime_seconds = playtime_frames / 60;

    /* Calculate checksum over player data */
    sd.checksum = calc_checksum((const u8 *)&sd.player, sizeof(Player));

    size_t written = fwrite(&sd, 1, sizeof(SaveData), f);
    fclose(f);

    return (written == sizeof(SaveData));
}

/* ══════════════════════════════════════════════════════════════
 *  LOAD GAME
 * ══════════════════════════════════════════════════════════════ */
int load_game(Player *p) {
    if (!ensure_fat()) return 0;

    FILE *f = fopen(SAVE_PATH, "rb");
    if (!f) return 0;

    SaveData sd;
    memset(&sd, 0, sizeof(SaveData));
    size_t read_bytes = fread(&sd, 1, sizeof(SaveData), f);
    fclose(f);

    if (read_bytes != sizeof(SaveData)) return 0;

    /* Validate magic number */
    if (sd.magic != SAVE_MAGIC) return 0;

    /* Validate checksum */
    u32 expected = calc_checksum((const u8 *)&sd.player, sizeof(Player));
    if (sd.checksum != expected) return 0;

    /* Restore player data */
    memcpy(p, &sd.player, sizeof(Player));
    playtime_frames = sd.playtime_seconds * 60;

    return 1;
}

/* ══════════════════════════════════════════════════════════════
 *  CHECK IF SAVE FILE EXISTS
 * ══════════════════════════════════════════════════════════════ */
int save_exists(void) {
    if (!ensure_fat()) return 0;

    FILE *f = fopen(SAVE_PATH, "rb");
    if (!f) return 0;

    SaveData sd;
    size_t read_bytes = fread(&sd, 1, sizeof(SaveData), f);
    fclose(f);

    if (read_bytes != sizeof(SaveData)) return 0;
    if (sd.magic != SAVE_MAGIC) return 0;

    u32 expected = calc_checksum((const u8 *)&sd.player, sizeof(Player));
    return (sd.checksum == expected);
}
