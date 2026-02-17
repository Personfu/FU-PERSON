/*
 * CyberWorld — Menu System
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * Party viewer, item inventory, daemon details,
 * player info, save option, and shop.
 */
#include "menu.h"
#include "daemon_data.h"
#include "save.h"
#include "wifi_scan.h"

/* Module state */
static int menu_mode = MENU_MAIN;
static int menu_cursor = 0;
static int detail_daemon_idx = 0;
static int shop_cursor = 0;

/* ══════════════════════════════════════════════════════════════
 *  DRAW HP BAR (same as battle but reusable)
 * ══════════════════════════════════════════════════════════════ */
static void menu_draw_hp_bar(int current, int max) {
    if (max < 1) max = 1;
    int bars = (current * 10) / max;
    if (bars < 0) bars = 0;
    if (bars > 10) bars = 10;
    iprintf("[");
    for (int i = 0; i < 10; i++) {
        iprintf(i < bars ? "#" : "-");
    }
    iprintf("]");
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW MAIN MENU
 * ══════════════════════════════════════════════════════════════ */
static void draw_main_menu(Player *p) {
    consoleClear();
    iprintf("\n  ══ CYBERWORLD MENU ══\n\n");
    iprintf("  %c Party\n", menu_cursor == 0 ? '>' : ' ');
    iprintf("  %c Items\n", menu_cursor == 1 ? '>' : ' ');
    iprintf("  %c Player Info\n", menu_cursor == 2 ? '>' : ' ');
    iprintf("  %c WiFi Scan\n", menu_cursor == 3 ? '>' : ' ');
    iprintf("  %c Save Game\n", menu_cursor == 4 ? '>' : ' ');
    iprintf("  %c Close Menu\n", menu_cursor == 5 ? '>' : ' ');
    iprintf("\n  ─────────────────────\n");
    iprintf("  %s | $%d | B:%d\n", p->name, p->money, p->badges);
    iprintf("  Map: %d  Pos: %d,%d\n", p->map_id, p->x, p->y);
    iprintf("  Seen: %d  Caught: %d\n", p->daemons_seen, p->daemons_caught);
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW PARTY VIEW
 * ══════════════════════════════════════════════════════════════ */
static void draw_party(Player *p) {
    consoleClear();
    iprintf("\n  ══ DAEMON PARTY ══\n\n");
    for (int i = 0; i < p->party_size; i++) {
        Daemon *d = &p->party[i];
        DaemonSpecies *sp = &ALL_SPECIES[d->species_id];
        iprintf("  %c %d. %-12s Lv%d\n",
                menu_cursor == i ? '>' : ' ',
                i + 1, d->nickname, d->level);
        iprintf("    %s  HP:%3d/%3d ",
                TYPE_NAMES[sp->type], d->hp_current, d->hp_max);
        menu_draw_hp_bar(d->hp_current, d->hp_max);
        iprintf("\n");
        if (d->status != STATUS_NONE) {
            const char *st[] = {"", "Encrypted", "Sandboxed", "Patched", "Firewalled", "Honeypotted"};
            iprintf("    Status: %s\n", st[d->status]);
        }
    }
    if (p->party_size == 0) iprintf("  No daemons!\n");
    iprintf("\n  [A] Details  [B] Back\n");
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW DAEMON DETAIL VIEW
 * ══════════════════════════════════════════════════════════════ */
static void draw_detail(Player *p) {
    consoleClear();
    if (detail_daemon_idx >= p->party_size) return;

    Daemon *d = &p->party[detail_daemon_idx];
    DaemonSpecies *sp = &ALL_SPECIES[d->species_id];

    iprintf("\n  ══ %s ══\n", d->nickname);
    iprintf("  Species: %s (#%d)\n", sp->name, sp->id);
    iprintf("  Type: %s\n", TYPE_NAMES[sp->type]);
    iprintf("  Level: %d\n", d->level);
    iprintf("  EXP: %d / %d\n", d->exp, d->level * 100);
    iprintf("  ─────────────────────\n");
    iprintf("  HP:  %3d/%3d ", d->hp_current, d->hp_max);
    menu_draw_hp_bar(d->hp_current, d->hp_max);
    iprintf("\n");
    iprintf("  ATK: %3d  DEF: %3d\n", d->atk, d->def);
    iprintf("  SPD: %3d  SPC: %3d\n", d->spd, d->spec);
    iprintf("  ─────────────────────\n");
    iprintf("  MOVES:\n");
    for (int i = 0; i < d->move_count; i++) {
        Move *m = &d->moves[i];
        iprintf("  %d. %-14s %s\n", i + 1, m->name, TYPE_NAMES[m->type]);
        iprintf("     Pow:%3d Acc:%3d PP:%d/%d\n",
                m->power, m->accuracy, m->pp_current, m->pp_max);
    }
    iprintf("  ─────────────────────\n");
    iprintf("  %s\n", sp->lore);
    iprintf("\n  [B] Back\n");
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW ITEM INVENTORY
 * ══════════════════════════════════════════════════════════════ */
static void draw_items(Player *p) {
    consoleClear();
    iprintf("\n  ══ ITEMS ══\n\n");
    int shown = 0;
    int idx = 0;
    for (int i = 0; i < MAX_ITEMS && i < ITEM_COUNT; i++) {
        if (p->items[i] > 0) {
            Item *item = &ALL_ITEMS[i];
            iprintf("  %c %-16s x%d\n",
                    idx == menu_cursor ? '>' : ' ',
                    item->name, p->items[i]);
            if (idx == menu_cursor) {
                /* Show item description */
                const char *type_str;
                switch (item->type) {
                case 0: type_str = "Healing"; break;
                case 1: type_str = "Capture"; break;
                case 2: type_str = "Battle"; break;
                case 3: type_str = "Key Item"; break;
                default: type_str = "Unknown"; break;
                }
                iprintf("    [%s] Val:%d\n", type_str, item->value);
            }
            idx++;
            shown++;
        }
    }
    if (shown == 0) iprintf("  No items!\n");
    iprintf("\n  [A] Use  [B] Back\n");
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW PLAYER INFO
 * ══════════════════════════════════════════════════════════════ */
static void draw_player_info(Player *p) {
    consoleClear();
    iprintf("\n  ══ PLAYER INFO ══\n\n");
    iprintf("  Name: %s\n", p->name);
    iprintf("  Money: $%d\n", p->money);
    iprintf("  Badges: %d / 8\n", p->badges);
    iprintf("  ─────────────────────\n");
    iprintf("  Party: %d / 6\n", p->party_size);
    iprintf("  Daemons Seen: %d\n", p->daemons_seen);
    iprintf("  Daemons Caught: %d\n", p->daemons_caught);
    iprintf("  ─────────────────────\n");
    iprintf("  Map: %d\n", p->map_id);
    iprintf("  Position: %d, %d\n", p->x, p->y);
    iprintf("\n  BADGE COLLECTION:\n");
    const char *badge_names[] = {
        "Recon Badge", "Exploit Badge", "Crypto Badge", "Social Badge",
        "Wireless Badge", "Physical Badge", "Binary Badge", "Zero-Day Badge"
    };
    for (int i = 0; i < 8; i++) {
        iprintf("  %c %s\n",
                (p->badges & (1 << i)) ? '*' : '-',
                badge_names[i]);
    }
    iprintf("\n  [B] Back\n");
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW SHOP
 * ══════════════════════════════════════════════════════════════ */
static void draw_shop(Player *p) {
    consoleClear();
    iprintf("\n  ══ DAEMON SHOP ══\n");
    iprintf("  Your money: $%d\n\n", p->money);

    /* Show purchasable items */
    int shop_items[] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 10 };
    int shop_count = 10;

    for (int i = 0; i < shop_count; i++) {
        Item *item = &ALL_ITEMS[shop_items[i]];
        if (item->price > 0) {
            iprintf("  %c %-14s $%d x%d\n",
                    shop_cursor == i ? '>' : ' ',
                    item->name, item->price,
                    p->items[shop_items[i]]);
        }
    }
    iprintf("\n  [A] Buy  [B] Leave\n");
}

/* ══════════════════════════════════════════════════════════════
 *  USE ITEM FROM INVENTORY
 * ══════════════════════════════════════════════════════════════ */
static void use_item_on_party(Player *p, int item_id) {
    if (item_id < 0 || item_id >= ITEM_COUNT) return;
    Item *item = &ALL_ITEMS[item_id];

    if (item->type == 0 && p->party_size > 0) {
        /* Healing items: apply to first daemon that needs it */
        for (int i = 0; i < p->party_size; i++) {
            Daemon *d = &p->party[i];

            /* Revive items: target fainted daemons */
            if (item->value == 1 && d->hp_current <= 0) {
                d->hp_current = d->hp_max / 2;
                p->items[item_id]--;
                consoleClear();
                iprintf("\n  Used %s on %s!\n", item->name, d->nickname);
                iprintf("  HP restored to %d/%d\n", d->hp_current, d->hp_max);
                iprintf("\n  Press B to continue.\n");
                return;
            }
            if (item->value == 2 && d->hp_current <= 0) {
                d->hp_current = d->hp_max;
                p->items[item_id]--;
                consoleClear();
                iprintf("\n  Used %s on %s!\n", item->name, d->nickname);
                iprintf("  Fully rebooted!\n");
                iprintf("\n  Press B to continue.\n");
                return;
            }

            /* Normal heals: target damaged (but alive) daemons */
            if (item->value > 2 && d->hp_current > 0 && d->hp_current < d->hp_max) {
                if (item->value >= 9999) {
                    d->hp_current = d->hp_max;
                } else {
                    d->hp_current += item->value;
                    if (d->hp_current > d->hp_max)
                        d->hp_current = d->hp_max;
                }
                p->items[item_id]--;
                consoleClear();
                iprintf("\n  Used %s on %s!\n", item->name, d->nickname);
                iprintf("  HP: %d/%d\n", d->hp_current, d->hp_max);
                iprintf("\n  Press B to continue.\n");
                return;
            }

            /* Decryptor: cure status */
            if (item_id == 10 && d->status != STATUS_NONE) {
                d->status = STATUS_NONE;
                d->status_turns = 0;
                p->items[item_id]--;
                consoleClear();
                iprintf("\n  Used %s on %s!\n", item->name, d->nickname);
                iprintf("  Status cured!\n");
                iprintf("\n  Press B to continue.\n");
                return;
            }

            /* Bandwidth: restore PP */
            if (item_id == 11 && d->hp_current > 0) {
                int restored = 0;
                for (int j = 0; j < d->move_count; j++) {
                    if (d->moves[j].pp_current < d->moves[j].pp_max) {
                        d->moves[j].pp_current += 10;
                        if (d->moves[j].pp_current > d->moves[j].pp_max)
                            d->moves[j].pp_current = d->moves[j].pp_max;
                        restored = 1;
                    }
                }
                if (restored) {
                    p->items[item_id]--;
                    consoleClear();
                    iprintf("\n  Used %s on %s!\n", item->name, d->nickname);
                    iprintf("  PP restored!\n");
                    iprintf("\n  Press B to continue.\n");
                    return;
                }
            }
        }

        consoleClear();
        iprintf("\n  Can't use %s right now!\n", item->name);
        iprintf("\n  Press B to continue.\n");
    } else {
        consoleClear();
        iprintf("\n  Can't use that here!\n");
        iprintf("\n  Press B to continue.\n");
    }
}

/* ══════════════════════════════════════════════════════════════
 *  GET ITEM ID FROM CURSOR POSITION
 * ══════════════════════════════════════════════════════════════ */
static int get_menu_item_id(Player *p, int cursor) {
    int idx = 0;
    for (int i = 0; i < MAX_ITEMS && i < ITEM_COUNT; i++) {
        if (p->items[i] > 0) {
            if (idx == cursor) return i;
            idx++;
        }
    }
    return -1;
}

static int count_menu_items(Player *p) {
    int count = 0;
    for (int i = 0; i < MAX_ITEMS && i < ITEM_COUNT; i++) {
        if (p->items[i] > 0) count++;
    }
    return count;
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE MENU INPUT
 * ══════════════════════════════════════════════════════════════ */
void handle_menu_input(u16 keys, GameState *state, Player *p) {
    switch (menu_mode) {
    case MENU_MAIN:
        if (keys & KEY_UP) {
            if (menu_cursor > 0) menu_cursor--;
            draw_main_menu(p);
        }
        if (keys & KEY_DOWN) {
            if (menu_cursor < 5) menu_cursor++;
            draw_main_menu(p);
        }
        if (keys & KEY_A) {
            switch (menu_cursor) {
            case 0: /* Party */
                menu_mode = MENU_PARTY;
                menu_cursor = 0;
                draw_party(p);
                break;
            case 1: /* Items */
                menu_mode = MENU_ITEMS;
                menu_cursor = 0;
                draw_items(p);
                break;
            case 2: /* Player Info */
                menu_mode = MENU_PLAYER;
                draw_player_info(p);
                break;
            case 3: /* WiFi Scan */
                *state = STATE_WIFI_SCAN;
                wifi_show_results();
                menu_mode = MENU_MAIN;
                menu_cursor = 0;
                return;
            case 4: /* Save */
                save_game(p);
                consoleClear();
                iprintf("\n  [+] Game saved!\n");
                iprintf("\n  Press B to continue.\n");
                break;
            case 5: /* Close */
                menu_mode = MENU_MAIN;
                menu_cursor = 0;
                *state = STATE_OVERWORLD;
                draw_overworld(p);
                return;
            }
        }
        if (keys & KEY_B) {
            menu_mode = MENU_MAIN;
            menu_cursor = 0;
            *state = STATE_OVERWORLD;
            draw_overworld(p);
        }
        /* Redraw on first entry */
        if (keys == 0 && menu_mode == MENU_MAIN) {
            draw_main_menu(p);
        }
        break;

    case MENU_PARTY:
        if (keys & KEY_UP) {
            if (menu_cursor > 0) menu_cursor--;
            draw_party(p);
        }
        if (keys & KEY_DOWN) {
            if (menu_cursor < p->party_size - 1) menu_cursor++;
            draw_party(p);
        }
        if (keys & KEY_A) {
            detail_daemon_idx = menu_cursor;
            menu_mode = MENU_DETAIL;
            draw_detail(p);
        }
        if (keys & KEY_B) {
            menu_mode = MENU_MAIN;
            menu_cursor = 0;
            draw_main_menu(p);
        }
        break;

    case MENU_DETAIL:
        if (keys & KEY_B) {
            menu_mode = MENU_PARTY;
            menu_cursor = detail_daemon_idx;
            draw_party(p);
        }
        break;

    case MENU_ITEMS:
        {
            int item_count = count_menu_items(p);
            if (keys & KEY_UP) {
                if (menu_cursor > 0) menu_cursor--;
                draw_items(p);
            }
            if (keys & KEY_DOWN) {
                if (menu_cursor < item_count - 1) menu_cursor++;
                draw_items(p);
            }
            if (keys & KEY_A) {
                int item_id = get_menu_item_id(p, menu_cursor);
                if (item_id >= 0) {
                    use_item_on_party(p, item_id);
                }
            }
            if (keys & KEY_B) {
                menu_mode = MENU_MAIN;
                menu_cursor = 0;
                draw_main_menu(p);
            }
        }
        break;

    case MENU_PLAYER:
        if (keys & KEY_B) {
            menu_mode = MENU_MAIN;
            menu_cursor = 2;
            draw_main_menu(p);
        }
        break;

    default:
        if (keys & KEY_B) {
            menu_mode = MENU_MAIN;
            menu_cursor = 0;
            draw_main_menu(p);
        }
        break;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE SHOP INPUT
 * ══════════════════════════════════════════════════════════════ */
void handle_shop_input(u16 keys, GameState *state, Player *p) {
    int shop_items[] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 10 };
    int shop_count = 10;

    if (keys & KEY_UP) {
        if (shop_cursor > 0) shop_cursor--;
        draw_shop(p);
    }
    if (keys & KEY_DOWN) {
        if (shop_cursor < shop_count - 1) shop_cursor++;
        draw_shop(p);
    }
    if (keys & KEY_A) {
        if (shop_cursor < shop_count) {
            int item_id = shop_items[shop_cursor];
            Item *item = &ALL_ITEMS[item_id];
            if (item->price > 0 && p->money >= item->price) {
                p->money -= item->price;
                p->items[item_id]++;
                consoleClear();
                iprintf("\n  Bought %s!\n", item->name);
                iprintf("  Money: $%d\n", p->money);
                iprintf("\n  Press A to continue.\n");
            } else {
                consoleClear();
                iprintf("\n  Not enough money!\n");
                iprintf("  Need: $%d  Have: $%d\n", item->price, p->money);
                iprintf("\n  Press A to continue.\n");
            }
        }
    }
    if (keys & KEY_B) {
        shop_cursor = 0;
        *state = STATE_OVERWORLD;
        draw_overworld(p);
    }

    /* Initial draw */
    if (keys == 0) {
        draw_shop(p);
    }
}
