/*
 * CyberWorld — Type Definitions
 * FLLC | FU PERSON | DSi Homebrew RPG
 */
#ifndef TYPES_H
#define TYPES_H

#include <nds.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ── Daemon Types ──────────────────────────────────────────── */
typedef enum {
    TYPE_NETWORK  = 0,
    TYPE_WEB      = 1,
    TYPE_BINARY   = 2,
    TYPE_SOCIAL   = 3,
    TYPE_CRYPTO   = 4,
    TYPE_WIRELESS = 5,
    TYPE_PHYSICAL = 6,
    TYPE_ZERODAY  = 7,
    TYPE_COUNT    = 8
} DaemonType;

/* ── Status Conditions ─────────────────────────────────────── */
typedef enum {
    STATUS_NONE       = 0,
    STATUS_ENCRYPTED  = 1,  /* Can't attack for 1-3 turns */
    STATUS_SANDBOXED  = 2,  /* Attack power halved */
    STATUS_PATCHED    = 3,  /* Defense doubled, speed halved */
    STATUS_FIREWALLED = 4,  /* Takes no damage for 1 turn */
    STATUS_HONEYPOTTED = 5  /* Damages self on attack */
} StatusCondition;

/* ── Game States ───────────────────────────────────────────── */
typedef enum {
    STATE_TITLE,
    STATE_OVERWORLD,
    STATE_BATTLE,
    STATE_MENU,
    STATE_DIALOG,
    STATE_DAEMON_SELECT,
    STATE_SHOP,
    STATE_HEAL,
    STATE_WIFI_SCAN,
    STATE_SAVE,
    STATE_CREDITS
} GameState;

/* ── Move Definition ───────────────────────────────────────── */
typedef struct {
    char name[24];
    DaemonType type;
    int power;        /* 0-150 */
    int accuracy;     /* 0-100 */
    int pp_max;
    int pp_current;
    int status_chance; /* 0-100 */
    StatusCondition inflicts;
} Move;

/* ── Daemon Species (template) ─────────────────────────────── */
typedef struct {
    int id;
    char name[20];
    DaemonType type;
    int base_hp;
    int base_atk;
    int base_def;
    int base_spd;
    int base_spec;
    int evolves_at;   /* Level to evolve, 0 = no evolution */
    int evolves_to;   /* Species ID to evolve into */
    int move_ids[8];  /* Learnable move IDs (by level) */
    int move_levels[8];
    char lore[80];
} DaemonSpecies;

/* ── Daemon Instance (in party) ────────────────────────────── */
typedef struct {
    int species_id;
    char nickname[20];
    int level;
    int exp;
    int hp_current;
    int hp_max;
    int atk;
    int def;
    int spd;
    int spec;
    Move moves[4];
    int move_count;
    StatusCondition status;
    int status_turns;
} Daemon;

/* ── Player ────────────────────────────────────────────────── */
typedef struct {
    char name[16];
    int x, y;         /* Overworld position */
    int map_id;
    int money;
    int badges;
    Daemon party[6];
    int party_size;
    int items[32];     /* Item ID -> quantity */
    int daemons_seen;
    int daemons_caught;
} Player;

/* ── NPC / Trainer ─────────────────────────────────────────── */
typedef struct {
    char name[20];
    int x, y;
    int map_id;
    Daemon party[6];
    int party_size;
    int defeated;      /* 0 or 1 */
    char dialog_before[120];
    char dialog_after[120];
} Trainer;

/* ── Map Tile ──────────────────────────────────────────────── */
#define MAP_W 32
#define MAP_H 24

typedef struct {
    char name[24];
    int id;
    u8 tiles[MAP_H][MAP_W];  /* 0=floor, 1=wall, 2=grass, 3=water, 4=door, 5=npc, 6=heal */
    int wild_daemon_ids[8];
    int wild_daemon_count;
    int wild_level_min;
    int wild_level_max;
    int connections[4];       /* N,S,E,W map IDs (-1=none) */
} Map;

/* ── WiFi Scan Entry ───────────────────────────────────────── */
typedef struct {
    char ssid[33];
    char bssid[18];
    int signal;
    int channel;
    int encrypted;
} WiFiEntry;

/* ── Item Definition ───────────────────────────────────────── */
typedef struct {
    int id;
    char name[24];
    int type;       /* 0=heal, 1=capture, 2=battle, 3=key */
    int value;      /* HP restored, capture rate bonus, etc. */
    int price;
} Item;

/* ── Save Data ─────────────────────────────────────────────── */
typedef struct {
    u32 magic;      /* 0x4357524C = "CWRL" */
    Player player;
    int playtime_seconds;
    u32 checksum;
} SaveData;

/* ── Constants ─────────────────────────────────────────────── */
#define MAX_SPECIES   64
#define MAX_MOVES     80
#define MAX_MAPS      16
#define MAX_ITEMS     20
#define MAX_TRAINERS  40
#define MAX_WIFI      64

#define SAVE_MAGIC    0x4357524C

/* Type effectiveness table: [attacker][defender] */
/* 0=normal(100%), 1=super(200%), 2=resist(50%), 3=immune(0%) */
extern const u8 TYPE_CHART[TYPE_COUNT][TYPE_COUNT];

/* Type name strings */
extern const char *TYPE_NAMES[TYPE_COUNT];

#endif /* TYPES_H */
