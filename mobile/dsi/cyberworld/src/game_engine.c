/*
 * CyberWorld — Game Engine
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * Core game loop, state machine, initialization, and
 * all state transition handling.
 */
#include "types.h"
#include "daemon_data.h"
#include "battle.h"
#include "map.h"
#include "menu.h"
#include "wifi_scan.h"
#include "save.h"

/* ── Forward declarations for map init ─────────────────────── */
extern void init_maps(void);
extern void init_trainers(void);
extern void save_tick(void);
extern int save_get_playtime_seconds(void);
extern Trainer ALL_TRAINERS[];
extern int TRAINER_COUNT;

/* ── Game State ────────────────────────────────────────────── */
static GameState current_state = STATE_TITLE;
static Player player;
static int frame_count = 0;
static int bg_wifi_timer = 0;
static int starter_chosen = 0;
static int starter_cursor = 0;
static int dialog_trainer_idx = -1;

#define WIFI_SCAN_INTERVAL 300

/* ══════════════════════════════════════════════════════════════
 *  INITIALIZE PLAYER
 * ══════════════════════════════════════════════════════════════ */
void init_player(void) {
    memset(&player, 0, sizeof(Player));
    strcpy(player.name, "HACKER");
    player.x = 5;
    player.y = 5;
    player.map_id = 0;
    player.money = 500;
    player.party_size = 0;

    /* Starting items */
    player.items[0] = 3;   /* 3x Patch */
    player.items[4] = 5;   /* 5x Capture.exe */
}

/* ══════════════════════════════════════════════════════════════
 *  CREATE DAEMON FROM SPECIES + LEVEL
 * ══════════════════════════════════════════════════════════════ */
Daemon create_daemon(int species_id, int level) {
    Daemon d;
    memset(&d, 0, sizeof(Daemon));

    if (species_id < 0 || species_id >= SPECIES_COUNT) species_id = 0;
    DaemonSpecies *sp = &ALL_SPECIES[species_id];

    d.species_id = species_id;
    strncpy(d.nickname, sp->name, 19);
    d.nickname[19] = '\0';
    d.level = level;
    d.exp = 0;

    /* Stat calculation: base + level scaling */
    d.hp_max = sp->base_hp + (level * 2) + 10;
    d.hp_current = d.hp_max;
    d.atk = sp->base_atk + level;
    d.def = sp->base_def + level;
    d.spd = sp->base_spd + level;
    d.spec = sp->base_spec + level;

    d.status = STATUS_NONE;
    d.status_turns = 0;

    /* Assign moves learned up to this level */
    d.move_count = 0;
    for (int i = 0; i < 8 && d.move_count < 4; i++) {
        if (sp->move_levels[i] > 0 && sp->move_levels[i] <= level) {
            if (sp->move_ids[i] >= 0 && sp->move_ids[i] < MOVE_COUNT) {
                d.moves[d.move_count] = ALL_MOVES[sp->move_ids[i]];
                d.move_count++;
            }
        }
    }

    /* Ensure at least one move */
    if (d.move_count == 0) {
        d.moves[0] = ALL_MOVES[0]; /* Ping */
        d.move_count = 1;
    }

    return d;
}

/* ══════════════════════════════════════════════════════════════
 *  GIVE PLAYER A STARTER DAEMON
 * ══════════════════════════════════════════════════════════════ */
static void give_starter(int choice) {
    int starter_ids[] = { 0, 9, 18 };
    if (choice < 0 || choice > 2) choice = 0;
    player.party[0] = create_daemon(starter_ids[choice], 5);
    player.party_size = 1;
}

/* ══════════════════════════════════════════════════════════════
 *  TITLE SCREEN
 * ══════════════════════════════════════════════════════════════ */
static void draw_title(void) {
    consoleClear();
    iprintf("\n\n");
    iprintf("  +===========================+\n");
    iprintf("  |     C Y B E R W O R L D   |\n");
    iprintf("  |   ----------------------- |\n");
    iprintf("  |  Daemon Battle RPG v1.0    |\n");
    iprintf("  |  FLLC | Find You Person     |\n");
    iprintf("  +===========================+\n");
    iprintf("\n\n");
    if (starter_chosen) {
        iprintf("  [+] Press START to play\n");
    } else {
        iprintf("  [+] Press START to begin\n");
    }
    iprintf("  [*] Press SELECT for WiFi\n");
    if (save_exists()) {
        iprintf("  [L] Load saved game\n");
    }
    iprintf("\n  Catch Daemons. Defeat CISO.\n");
    iprintf("  WiFi recon runs in background.\n");
}

/* ══════════════════════════════════════════════════════════════
 *  STARTER SELECTION SCREEN
 * ══════════════════════════════════════════════════════════════ */
static void draw_starter_select(void) {
    consoleClear();
    iprintf("\n  CHOOSE YOUR STARTER DAEMON:\n");
    iprintf("  ===========================\n\n");

    const char *names[] = { "Ping", "XSSling", "Stacksmash" };
    const char *types[] = { "Network", "Web", "Binary" };
    int hps[]  = { 45, 39, 44 };
    int atks[] = { 49, 52, 48 };
    int defs[] = { 49, 43, 65 };
    const char *lores[] = {
        "Sends ICMP echoes to map the network.",
        "Injects scripts into unsanitized inputs.",
        "Overwrites the return address on the stack."
    };

    for (int i = 0; i < 3; i++) {
        iprintf("  %c [%d] %-12s (%s)\n",
                starter_cursor == i ? '>' : ' ',
                i + 1, names[i], types[i]);
        iprintf("      HP:%d ATK:%d DEF:%d\n", hps[i], atks[i], defs[i]);
        iprintf("      \"%s\"\n\n", lores[i]);
    }

    iprintf("  D-Pad to select, A to confirm\n");
}

/* ══════════════════════════════════════════════════════════════
 *  FIND TRAINER NEAR PLAYER (for dialog interactions)
 * ══════════════════════════════════════════════════════════════ */
static int find_adjacent_trainer(Player *p, int tx, int ty) {
    for (int i = 0; i < TRAINER_COUNT; i++) {
        if (ALL_TRAINERS[i].map_id == p->map_id &&
            ALL_TRAINERS[i].x == tx &&
            ALL_TRAINERS[i].y == ty) {
            return i;
        }
    }
    return -1;
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE DIALOG STATE (NPC/Trainer interaction)
 * ══════════════════════════════════════════════════════════════ */
static void handle_dialog_input(u16 keys) {
    if (dialog_trainer_idx < 0) {
        if (keys & KEY_B) {
            current_state = STATE_OVERWORLD;
            draw_overworld(&player);
        }
        return;
    }

    Trainer *t = &ALL_TRAINERS[dialog_trainer_idx];

    if (t->defeated) {
        if (keys & KEY_B) {
            dialog_trainer_idx = -1;
            current_state = STATE_OVERWORLD;
            draw_overworld(&player);
        }
    } else {
        if (keys & KEY_A) {
            /* Start trainer battle */
            start_trainer_battle(&player, t);
            current_state = STATE_BATTLE;
            dialog_trainer_idx = -1;
        }
        if (keys & KEY_B) {
            dialog_trainer_idx = -1;
            current_state = STATE_OVERWORLD;
            draw_overworld(&player);
        }
    }
}

/* ══════════════════════════════════════════════════════════════
 *  CUSTOM OVERWORLD HANDLER (wraps map.c + dialog detection)
 * ══════════════════════════════════════════════════════════════ */
static void game_handle_overworld(u16 keys) {
    GameState next_state = STATE_OVERWORLD;

    /* Track position before move for NPC detection */
    int old_x = player.x;
    int old_y = player.y;

    handle_overworld_input(&player, keys, &next_state);

    /* If state changed to DIALOG from NPC tile walk */
    if (next_state == STATE_DIALOG) {
        /* Find which NPC we bumped into */
        int nx = player.x, ny = player.y;
        if (keys & KEY_UP)    ny = old_y - 1;
        if (keys & KEY_DOWN)  ny = old_y + 1;
        if (keys & KEY_LEFT)  nx = old_x - 1;
        if (keys & KEY_RIGHT) nx = old_x + 1;

        dialog_trainer_idx = find_adjacent_trainer(&player, nx, ny);
        if (dialog_trainer_idx >= 0) {
            Trainer *t = &ALL_TRAINERS[dialog_trainer_idx];
            consoleClear();
            if (t->defeated) {
                iprintf("\n  %s:\n", t->name);
                iprintf("  \"%s\"\n", t->dialog_after);
                iprintf("\n  Press B to return.\n");
            } else {
                iprintf("\n  %s:\n", t->name);
                iprintf("  \"%s\"\n", t->dialog_before);
                iprintf("\n  Press A to battle!\n");
                iprintf("  Press B to decline.\n");
            }
        }
        current_state = STATE_DIALOG;
        return;
    }

    if (next_state == STATE_MENU) {
        current_state = STATE_MENU;
        return;
    }

    if (next_state == STATE_WIFI_SCAN) {
        current_state = STATE_WIFI_SCAN;
        wifi_show_results();
        return;
    }

    if (next_state == STATE_HEAL) {
        current_state = STATE_HEAL;
        return;
    }

    if (next_state == STATE_SHOP) {
        current_state = STATE_SHOP;
        return;
    }

    current_state = next_state;

    /* Random wild encounter on grass */
    if (current_state == STATE_OVERWORLD &&
        player_on_grass(&player) &&
        (old_x != player.x || old_y != player.y) &&
        (rand() % 100) < 15) {
        start_wild_battle(&player);
        current_state = STATE_BATTLE;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  MAIN — Entry point and game loop
 * ══════════════════════════════════════════════════════════════ */
int main(void) {
    /* ── Hardware Init ──────────────────────────────────────── */
    powerOn(POWER_ALL_2D);
    videoSetMode(MODE_0_2D);
    vramSetBankA(VRAM_A_MAIN_BG);

    consoleDemoInit();
    lcdMainOnTop();

    /* ── Seed RNG ───────────────────────────────────────────── */
    srand((unsigned)time(NULL));

    /* ── Game Data Init ─────────────────────────────────────── */
    init_player();
    init_maps();
    init_trainers();
    wifi_init();

    /* ── Title Screen ───────────────────────────────────────── */
    draw_title();

    /* ══════════════════════════════════════════════════════════
     *  MAIN GAME LOOP
     * ══════════════════════════════════════════════════════════ */
    while (1) {
        scanKeys();
        u16 keys = keysDown();
        frame_count++;

        /* Background WiFi scanning */
        bg_wifi_timer++;
        if (bg_wifi_timer >= WIFI_SCAN_INTERVAL) {
            wifi_background_scan();
            bg_wifi_timer = 0;
        }

        /* Track playtime */
        if (current_state == STATE_OVERWORLD ||
            current_state == STATE_BATTLE ||
            current_state == STATE_MENU) {
            save_tick();
        }

        /* ── State Machine ─────────────────────────────────── */
        switch (current_state) {

        /* ──────────────────────────────────────────────────── */
        case STATE_TITLE:
            if (keys & KEY_START) {
                if (!starter_chosen) {
                    current_state = STATE_DAEMON_SELECT;
                    starter_cursor = 0;
                    draw_starter_select();
                } else {
                    current_state = STATE_OVERWORLD;
                    draw_overworld(&player);
                }
            }
            if (keys & KEY_SELECT) {
                current_state = STATE_WIFI_SCAN;
                wifi_show_results();
            }
            if (keys & KEY_L) {
                if (load_game(&player)) {
                    starter_chosen = 1;
                    consoleClear();
                    iprintf("\n  [+] Game loaded!\n");
                    iprintf("  Welcome back, %s!\n", player.name);
                    iprintf("  Party: %d daemons\n", player.party_size);
                    iprintf("  Money: $%d\n", player.money);
                    iprintf("  Playtime: %ds\n", save_get_playtime_seconds());
                    iprintf("\n  Press START to continue.\n");
                } else {
                    consoleClear();
                    iprintf("\n  [-] No valid save found.\n");
                    iprintf("\n  Press START to begin.\n");
                }
            }
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_DAEMON_SELECT:
            if (keys & KEY_UP) {
                starter_cursor = (starter_cursor + 2) % 3;
                draw_starter_select();
            }
            if (keys & KEY_DOWN) {
                starter_cursor = (starter_cursor + 1) % 3;
                draw_starter_select();
            }
            if (keys & KEY_A) {
                give_starter(starter_cursor);
                starter_chosen = 1;
                consoleClear();
                iprintf("\n  [+] You received %s!\n\n",
                        player.party[0].nickname);
                iprintf("  Level 5 %s-type Daemon\n",
                        TYPE_NAMES[ALL_SPECIES[player.party[0].species_id].type]);
                iprintf("  HP: %d  ATK: %d  DEF: %d\n",
                        player.party[0].hp_max,
                        player.party[0].atk,
                        player.party[0].def);
                iprintf("  SPD: %d  SPC: %d\n",
                        player.party[0].spd,
                        player.party[0].spec);
                iprintf("\n  Moves:\n");
                for (int i = 0; i < player.party[0].move_count; i++) {
                    iprintf("    %s (PP:%d)\n",
                            player.party[0].moves[i].name,
                            player.party[0].moves[i].pp_max);
                }
                iprintf("\n  Press START for the overworld.\n");
                current_state = STATE_TITLE;
            }
            if (keys & KEY_B) {
                current_state = STATE_TITLE;
                draw_title();
            }
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_OVERWORLD:
            game_handle_overworld(keys);
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_BATTLE:
            handle_battle_input(keys, &current_state, &player);
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_MENU:
            handle_menu_input(keys, &current_state, &player);
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_DIALOG:
            handle_dialog_input(keys);
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_WIFI_SCAN:
            if (keys & KEY_B) {
                current_state = STATE_TITLE;
                draw_title();
            }
            if (keys & KEY_A) {
                wifi_force_scan();
                wifi_show_results();
            }
            if (keys & KEY_Y) {
                wifi_save_log();
            }
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_HEAL:
            /* Heal all party daemons */
            for (int i = 0; i < player.party_size; i++) {
                player.party[i].hp_current = player.party[i].hp_max;
                player.party[i].status = STATUS_NONE;
                player.party[i].status_turns = 0;
                for (int j = 0; j < player.party[i].move_count; j++) {
                    player.party[i].moves[j].pp_current =
                        player.party[i].moves[j].pp_max;
                }
            }
            consoleClear();
            iprintf("\n  [+] HEAL STATION\n");
            iprintf("  ─────────────────────\n");
            iprintf("  All Daemons fully patched!\n");
            iprintf("  HP and PP restored.\n");
            iprintf("  Status conditions cleared.\n");
            iprintf("\n  Party status:\n");
            for (int i = 0; i < player.party_size; i++) {
                iprintf("  %s: %d/%d HP\n",
                        player.party[i].nickname,
                        player.party[i].hp_current,
                        player.party[i].hp_max);
            }
            iprintf("\n  Press B to return.\n");

            if (keys & KEY_B) {
                current_state = STATE_OVERWORLD;
                draw_overworld(&player);
            }
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_SHOP:
            handle_shop_input(keys, &current_state, &player);
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_SAVE:
            if (save_game(&player)) {
                consoleClear();
                iprintf("\n  [+] Game saved!\n");
                iprintf("  Playtime: %ds\n", save_get_playtime_seconds());
            } else {
                consoleClear();
                iprintf("\n  [-] Save failed!\n");
                iprintf("  Check SD card.\n");
            }
            iprintf("\n  Press B to continue.\n");
            if (keys & KEY_B) {
                current_state = STATE_OVERWORLD;
                draw_overworld(&player);
            }
            break;

        /* ──────────────────────────────────────────────────── */
        case STATE_CREDITS:
            consoleClear();
            iprintf("\n\n  +=======================+\n");
            iprintf("  |    C Y B E R W O R L D  |\n");
            iprintf("  |     --- CREDITS ---     |\n");
            iprintf("  +=======================+\n\n");
            iprintf("  Developed by:\n");
            iprintf("    FLLC | Find You Person\n\n");
            iprintf("  Built with:\n");
            iprintf("    devkitPro / devkitARM\n");
            iprintf("    libnds / libfat\n\n");
            iprintf("  Inspired by:\n");
            iprintf("    Real cybersecurity tools\n");
            iprintf("    and the hacker community\n\n");
            iprintf("  Thank you for playing!\n\n");
            iprintf("  Press B to return.\n");
            if (keys & KEY_B) {
                current_state = STATE_TITLE;
                draw_title();
            }
            break;

        /* ──────────────────────────────────────────────────── */
        default:
            current_state = STATE_TITLE;
            draw_title();
            break;
        }

        swiWaitForVBlank();
    }

    return 0;
}
