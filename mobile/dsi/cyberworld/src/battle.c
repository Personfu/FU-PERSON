/*
 * CyberWorld — Battle System
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * Full turn-based battle engine with type effectiveness,
 * status conditions, capture mechanics, and experience.
 */
#include "battle.h"
#include "daemon_data.h"

/* Current battle state (module-level) */
static BattleState bs;

/* ══════════════════════════════════════════════════════════════
 *  TYPE EFFECTIVENESS MULTIPLIER
 * ══════════════════════════════════════════════════════════════ */
static int get_type_multiplier(DaemonType atk_type, DaemonType def_type) {
    u8 eff = TYPE_CHART[atk_type][def_type];
    switch (eff) {
        case 1: return 200;  /* Super effective: 2x */
        case 2: return 50;   /* Not very effective: 0.5x */
        case 3: return 0;    /* Immune: 0x */
        default: return 100; /* Normal: 1x */
    }
}

/* ══════════════════════════════════════════════════════════════
 *  DAMAGE CALCULATION
 *  Formula: ((2*level/5 + 2) * power * atk/def) / 50 + 2
 *  Then apply type multiplier, STAB, random variance
 * ══════════════════════════════════════════════════════════════ */
int calculate_damage(Daemon *attacker, Daemon *defender, Move *move) {
    if (move->power == 0) return 0;

    int level = attacker->level;
    int power = move->power;
    int atk = attacker->atk;
    int def = defender->def;

    /* Status modifications */
    if (attacker->status == STATUS_SANDBOXED) atk /= 2;
    if (defender->status == STATUS_PATCHED) def *= 2;

    if (def < 1) def = 1;

    /* Base damage formula */
    int damage = ((2 * level / 5 + 2) * power * atk / def) / 50 + 2;

    /* STAB (Same Type Attack Bonus) - 1.5x */
    DaemonType atk_species_type = ALL_SPECIES[attacker->species_id].type;
    if (move->type == atk_species_type) {
        damage = damage * 150 / 100;
    }

    /* Type effectiveness */
    DaemonType def_species_type = ALL_SPECIES[defender->species_id].type;
    int type_mult = get_type_multiplier(move->type, def_species_type);
    damage = damage * type_mult / 100;

    /* Random variance: 85-100% */
    int variance = 85 + (rand() % 16);
    damage = damage * variance / 100;

    /* Minimum 1 damage if move has power and isn't immune */
    if (damage < 1 && type_mult > 0) damage = 1;

    return damage;
}

/* ══════════════════════════════════════════════════════════════
 *  CAPTURE ATTEMPT
 *  Rate = ((3*maxHP - 2*curHP) * base_rate + item_bonus) / (3*maxHP)
 *  Success if rand(256) < rate
 * ══════════════════════════════════════════════════════════════ */
int attempt_capture(Daemon *target, int item_bonus) {
    int max_hp = target->hp_max;
    int cur_hp = target->hp_current;
    if (max_hp < 1) max_hp = 1;

    int base_rate = 45;

    /* Harder to catch higher-level daemons */
    if (target->level > 30) base_rate -= 15;
    if (target->level > 50) base_rate -= 15;

    /* Status bonus */
    if (target->status == STATUS_ENCRYPTED || target->status == STATUS_SANDBOXED)
        base_rate += 12;

    int rate = ((3 * max_hp - 2 * cur_hp) * (base_rate + item_bonus)) / (3 * max_hp);

    if (rate < 1) rate = 1;
    if (rate > 255) rate = 255;

    /* ZeroDay.exe (item_bonus=100) is master capture */
    if (item_bonus >= 100) return 1;

    return (rand() % 256) < rate;
}

/* ══════════════════════════════════════════════════════════════
 *  EXPERIENCE & LEVELING
 * ══════════════════════════════════════════════════════════════ */
void gain_exp(Daemon *d, int amount, Player *p) {
    d->exp += amount;
    int needed = d->level * 100;

    while (d->exp >= needed && d->level < 100) {
        d->exp -= needed;
        d->level++;

        /* Recalculate stats */
        DaemonSpecies *sp = &ALL_SPECIES[d->species_id];
        int old_max = d->hp_max;
        d->hp_max = sp->base_hp + (d->level * 2) + 10;
        d->hp_current += (d->hp_max - old_max);
        if (d->hp_current > d->hp_max) d->hp_current = d->hp_max;
        d->atk = sp->base_atk + d->level;
        d->def = sp->base_def + d->level;
        d->spd = sp->base_spd + d->level;
        d->spec = sp->base_spec + d->level;

        /* Check for new moves */
        for (int i = 0; i < 8; i++) {
            if (sp->move_levels[i] == d->level && d->move_count < 4) {
                d->moves[d->move_count] = ALL_MOVES[sp->move_ids[i]];
                d->move_count++;
            }
        }

        needed = d->level * 100;
    }

    /* Check evolution */
    check_evolution(d);
}

/* ══════════════════════════════════════════════════════════════
 *  EVOLUTION CHECK
 * ══════════════════════════════════════════════════════════════ */
int check_evolution(Daemon *d) {
    DaemonSpecies *sp = &ALL_SPECIES[d->species_id];
    if (sp->evolves_at > 0 && d->level >= sp->evolves_at && sp->evolves_to >= 0) {
        int old_id = d->species_id;
        d->species_id = sp->evolves_to;
        DaemonSpecies *new_sp = &ALL_SPECIES[d->species_id];

        strncpy(d->nickname, new_sp->name, 19);
        d->nickname[19] = '\0';

        /* Recalc stats with new base */
        d->hp_max = new_sp->base_hp + (d->level * 2) + 10;
        d->hp_current = d->hp_max;
        d->atk = new_sp->base_atk + d->level;
        d->def = new_sp->base_def + d->level;
        d->spd = new_sp->base_spd + d->level;
        d->spec = new_sp->base_spec + d->level;

        (void)old_id;
        return 1;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  APPLY STATUS CONDITION EFFECTS (start of turn)
 * ══════════════════════════════════════════════════════════════ */
static int process_status(Daemon *d, char *msg) {
    if (d->status == STATUS_NONE) return 0;

    d->status_turns--;

    switch (d->status) {
    case STATUS_ENCRYPTED:
        if (d->status_turns <= 0) {
            d->status = STATUS_NONE;
            sprintf(msg, "%s was decrypted!", d->nickname);
        } else {
            sprintf(msg, "%s is encrypted! Can't act!", d->nickname);
            return 1; /* Skip turn */
        }
        break;

    case STATUS_FIREWALLED:
        if (d->status_turns <= 0) {
            d->status = STATUS_NONE;
            sprintf(msg, "%s's firewall expired.", d->nickname);
        }
        break;

    case STATUS_SANDBOXED:
        if (d->status_turns <= 0) {
            d->status = STATUS_NONE;
            sprintf(msg, "%s escaped the sandbox!", d->nickname);
        }
        break;

    case STATUS_PATCHED:
        if (d->status_turns <= 0) {
            d->status = STATUS_NONE;
            sprintf(msg, "%s's patch wore off.", d->nickname);
        }
        break;

    case STATUS_HONEYPOTTED:
        if (d->status_turns <= 0) {
            d->status = STATUS_NONE;
            sprintf(msg, "%s left the honeypot.", d->nickname);
        }
        break;

    default:
        break;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 *  TRY TO INFLICT STATUS
 * ══════════════════════════════════════════════════════════════ */
static void try_inflict_status(Daemon *target, Move *move, char *msg) {
    if (move->inflicts == STATUS_NONE) return;
    if (target->status != STATUS_NONE) return;
    if (move->status_chance <= 0) return;

    if ((rand() % 100) < move->status_chance) {
        target->status = move->inflicts;
        /* Set duration based on status */
        switch (move->inflicts) {
        case STATUS_ENCRYPTED:   target->status_turns = 1 + (rand() % 3); break;
        case STATUS_SANDBOXED:   target->status_turns = 3 + (rand() % 3); break;
        case STATUS_PATCHED:     target->status_turns = 3 + (rand() % 2); break;
        case STATUS_FIREWALLED:  target->status_turns = 1; break;
        case STATUS_HONEYPOTTED: target->status_turns = 2 + (rand() % 3); break;
        default: target->status_turns = 3; break;
        }

        const char *status_names[] = {
            "", "Encrypted", "Sandboxed", "Patched",
            "Firewalled", "Honeypotted"
        };
        sprintf(msg, "%s was %s!", target->nickname,
                status_names[move->inflicts]);
    }
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW HP BAR
 * ══════════════════════════════════════════════════════════════ */
static void draw_hp_bar(int current, int max) {
    if (max < 1) max = 1;
    int bars = (current * 10) / max;
    if (bars < 0) bars = 0;
    if (bars > 10) bars = 10;

    iprintf("[");
    for (int i = 0; i < 10; i++) {
        if (i < bars)
            iprintf("#");
        else
            iprintf("-");
    }
    iprintf("]");
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW BATTLE SCREEN
 * ══════════════════════════════════════════════════════════════ */
void draw_battle(BattleState *b) {
    consoleClear();

    Daemon *pd = b->player_daemon;
    Daemon *ed = b->enemy_daemon;

    /* Enemy daemon info (top) */
    iprintf("  --- %s (Lv%d) ---\n", b->is_wild ? "WILD" : "FOE", ed->level);
    iprintf("  %s [%s]\n", ed->nickname, TYPE_NAMES[ALL_SPECIES[ed->species_id].type]);
    iprintf("  HP: %3d/%3d ", ed->hp_current, ed->hp_max);
    draw_hp_bar(ed->hp_current, ed->hp_max);
    iprintf("\n");
    if (ed->status != STATUS_NONE) {
        const char *st[] = { "", "ENC", "SBX", "PAT", "FWL", "HPT" };
        iprintf("  Status: %s (%d turns)\n", st[ed->status], ed->status_turns);
    } else {
        iprintf("\n");
    }

    iprintf("  ─────────────────────────\n");

    /* Player daemon info */
    iprintf("  %s (Lv%d)\n", pd->nickname, pd->level);
    iprintf("  HP: %3d/%3d ", pd->hp_current, pd->hp_max);
    draw_hp_bar(pd->hp_current, pd->hp_max);
    iprintf("\n");
    if (pd->status != STATUS_NONE) {
        const char *st[] = { "", "ENC", "SBX", "PAT", "FWL", "HPT" };
        iprintf("  Status: %s (%d turns)\n", st[pd->status], pd->status_turns);
    } else {
        iprintf("\n");
    }
    iprintf("  EXP: %d/%d\n", pd->exp, pd->level * 100);

    iprintf("  ═════════════════════════\n");

    /* Show message if active */
    if (b->message_timer > 0) {
        iprintf("  %s\n", b->message);
        return;
    }

    /* Menu */
    switch (b->menu_mode) {
    case BMENU_MAIN:
        iprintf("  %c FIGHT    %c CAPTURE\n",
                b->cursor == 0 ? '>' : ' ',
                b->cursor == 1 ? '>' : ' ');
        iprintf("  %c DAEMON   %c RUN\n",
                b->cursor == 2 ? '>' : ' ',
                b->cursor == 3 ? '>' : ' ');
        break;

    case BMENU_MOVE:
        iprintf("  SELECT MOVE:\n");
        for (int i = 0; i < pd->move_count; i++) {
            Move *m = &pd->moves[i];
            iprintf("  %c %-14s PP:%2d/%2d\n",
                    b->cursor == i ? '>' : ' ',
                    m->name, m->pp_current, m->pp_max);
        }
        iprintf("  [B] Back\n");
        break;

    case BMENU_DAEMON:
        iprintf("  SWITCH DAEMON:\n");
        for (int i = 0; i < b->player->party_size; i++) {
            Daemon *d = &b->player->party[i];
            iprintf("  %c %-12s Lv%2d HP:%3d/%3d%s\n",
                    b->cursor == i ? '>' : ' ',
                    d->nickname, d->level,
                    d->hp_current, d->hp_max,
                    i == b->player_daemon_idx ? " *" : "");
        }
        iprintf("  [B] Back\n");
        break;

    case BMENU_ITEM:
        iprintf("  USE ITEM:\n");
        {
            int shown = 0;
            int idx = 0;
            for (int i = 0; i < MAX_ITEMS && i < ITEM_COUNT; i++) {
                if (b->player->items[i] > 0) {
                    iprintf("  %c %-14s x%d\n",
                            idx == b->cursor ? '>' : ' ',
                            ALL_ITEMS[i].name,
                            b->player->items[i]);
                    idx++;
                    shown++;
                    if (shown >= 6) break;
                }
            }
            if (shown == 0) iprintf("  No items!\n");
        }
        iprintf("  [B] Back\n");
        break;

    default:
        break;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  EXECUTE A MOVE (one daemon attacks another)
 * ══════════════════════════════════════════════════════════════ */
static void execute_move(Daemon *attacker, Daemon *defender, Move *move,
                         BattleState *b) {
    char tmp[120];

    /* Check PP */
    if (move->pp_current <= 0) {
        sprintf(b->message, "No PP left for %s!", move->name);
        b->message_timer = 60;
        return;
    }
    move->pp_current--;

    /* Accuracy check */
    if ((rand() % 100) >= move->accuracy) {
        sprintf(b->message, "%s used %s... but missed!", attacker->nickname, move->name);
        b->message_timer = 60;
        return;
    }

    /* Honeypot self-damage */
    if (attacker->status == STATUS_HONEYPOTTED && move->power > 0) {
        int self_dmg = attacker->hp_max / 8;
        if (self_dmg < 1) self_dmg = 1;
        attacker->hp_current -= self_dmg;
        if (attacker->hp_current < 0) attacker->hp_current = 0;
    }

    /* Calculate and apply damage */
    int damage = calculate_damage(attacker, defender, move);

    /* Firewalled blocks damage */
    if (defender->status == STATUS_FIREWALLED && move->power > 0) {
        sprintf(b->message, "%s used %s! Blocked by firewall!",
                attacker->nickname, move->name);
        b->message_timer = 60;
        return;
    }

    if (damage > 0) {
        defender->hp_current -= damage;
        if (defender->hp_current < 0) defender->hp_current = 0;

        /* Type effectiveness message */
        DaemonType def_type = ALL_SPECIES[defender->species_id].type;
        int eff = get_type_multiplier(move->type, def_type);

        if (eff >= 200) {
            sprintf(b->message, "%s used %s! %d dmg! Super effective!",
                    attacker->nickname, move->name, damage);
        } else if (eff <= 50 && eff > 0) {
            sprintf(b->message, "%s used %s! %d dmg. Not effective...",
                    attacker->nickname, move->name, damage);
        } else if (eff == 0) {
            sprintf(b->message, "%s used %s! No effect!",
                    attacker->nickname, move->name);
        } else {
            sprintf(b->message, "%s used %s! %d damage!",
                    attacker->nickname, move->name, damage);
        }
    } else {
        sprintf(b->message, "%s used %s!",
                attacker->nickname, move->name);
    }

    /* Try to inflict status */
    tmp[0] = '\0';
    try_inflict_status(defender, move, tmp);
    if (tmp[0] != '\0') {
        /* Append status message on next display */
        strncat(b->message, " ", sizeof(b->message) - strlen(b->message) - 1);
        strncat(b->message, tmp, sizeof(b->message) - strlen(b->message) - 1);
    }

    b->message_timer = 90;
}

/* ══════════════════════════════════════════════════════════════
 *  ENEMY AI — Choose best move
 * ══════════════════════════════════════════════════════════════ */
static int enemy_choose_move(Daemon *enemy, Daemon *player_d) {
    int best_idx = 0;
    int best_score = -1;

    for (int i = 0; i < enemy->move_count; i++) {
        Move *m = &enemy->moves[i];
        if (m->pp_current <= 0) continue;

        int score = m->power * m->accuracy / 100;

        /* Prefer super-effective moves */
        DaemonType def_type = ALL_SPECIES[player_d->species_id].type;
        int eff = get_type_multiplier(m->type, def_type);
        score = score * eff / 100;

        /* STAB bonus in scoring */
        if (m->type == ALL_SPECIES[enemy->species_id].type)
            score = score * 3 / 2;

        /* Some randomness */
        score += rand() % 20;

        if (score > best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    return best_idx;
}

/* ══════════════════════════════════════════════════════════════
 *  EXECUTE FULL TURN (both sides)
 * ══════════════════════════════════════════════════════════════ */
static void execute_turn(int player_move_idx, BattleState *b) {
    Daemon *pd = b->player_daemon;
    Daemon *ed = b->enemy_daemon;

    /* Process status effects */
    char status_msg[120];
    int player_skip = process_status(pd, status_msg);
    if (player_skip) {
        sprintf(b->message, "%s", status_msg);
        b->message_timer = 60;
    }

    int enemy_skip = 0;
    char enemy_status_msg[120];
    enemy_status_msg[0] = '\0';
    enemy_skip = process_status(ed, enemy_status_msg);

    /* Determine turn order by speed */
    int player_first = pd->spd >= ed->spd;

    if (player_first) {
        /* Player attacks first */
        if (!player_skip && pd->hp_current > 0) {
            execute_move(pd, ed, &pd->moves[player_move_idx], b);
        }

        /* Check if enemy fainted */
        if (ed->hp_current <= 0) {
            b->battle_over = 1;
            b->player_won = 1;
            return;
        }

        /* Enemy turn */
        if (!enemy_skip && ed->hp_current > 0) {
            int emove = enemy_choose_move(ed, pd);
            execute_move(ed, pd, &ed->moves[emove], b);
        }

        /* Check if player daemon fainted */
        if (pd->hp_current <= 0) {
            /* Check for remaining party members */
            int has_alive = 0;
            for (int i = 0; i < b->player->party_size; i++) {
                if (b->player->party[i].hp_current > 0) {
                    has_alive = 1;
                    break;
                }
            }
            if (!has_alive) {
                b->battle_over = 1;
                b->player_won = 0;
            }
        }
    } else {
        /* Enemy attacks first */
        if (!enemy_skip && ed->hp_current > 0) {
            int emove = enemy_choose_move(ed, pd);
            execute_move(ed, pd, &ed->moves[emove], b);
        }

        if (pd->hp_current <= 0) {
            int has_alive = 0;
            for (int i = 0; i < b->player->party_size; i++) {
                if (b->player->party[i].hp_current > 0) {
                    has_alive = 1;
                    break;
                }
            }
            if (!has_alive) {
                b->battle_over = 1;
                b->player_won = 0;
                return;
            }
        }

        /* Player attacks */
        if (!player_skip && pd->hp_current > 0) {
            execute_move(pd, ed, &pd->moves[player_move_idx], b);
        }

        if (ed->hp_current <= 0) {
            b->battle_over = 1;
            b->player_won = 1;
        }
    }

    b->turn++;
}

/* ══════════════════════════════════════════════════════════════
 *  FIND ITEM INDEX FROM CURSOR IN ITEMS LIST
 * ══════════════════════════════════════════════════════════════ */
static int get_item_id_from_cursor(Player *p, int cursor) {
    int idx = 0;
    for (int i = 0; i < MAX_ITEMS && i < ITEM_COUNT; i++) {
        if (p->items[i] > 0) {
            if (idx == cursor) return i;
            idx++;
        }
    }
    return -1;
}

static int count_available_items(Player *p) {
    int count = 0;
    for (int i = 0; i < MAX_ITEMS && i < ITEM_COUNT; i++) {
        if (p->items[i] > 0) count++;
    }
    return count;
}

/* ══════════════════════════════════════════════════════════════
 *  START WILD BATTLE
 * ══════════════════════════════════════════════════════════════ */
extern Map ALL_MAPS[];
extern Daemon create_daemon(int species_id, int level);

void start_wild_battle(Player *p) {
    memset(&bs, 0, sizeof(BattleState));
    bs.player = p;
    bs.is_wild = 1;
    bs.trainer = NULL;
    bs.battle_over = 0;
    bs.player_won = 0;
    bs.turn = 0;
    bs.cursor = 0;
    bs.menu_mode = BMENU_MAIN;
    bs.catch_attempts = 0;
    bs.run_attempts = 0;
    bs.message_timer = 0;

    /* Find current map and pick random wild daemon */
    Map *map = &ALL_MAPS[p->map_id];
    if (map->wild_daemon_count > 0) {
        int idx = rand() % map->wild_daemon_count;
        int species_id = map->wild_daemon_ids[idx];
        int level = map->wild_level_min +
                    (rand() % (map->wild_level_max - map->wild_level_min + 1));
        bs.enemy_copy = create_daemon(species_id, level);
    } else {
        /* Fallback */
        bs.enemy_copy = create_daemon(0, 3);
    }
    bs.enemy_daemon = &bs.enemy_copy;

    /* Set player's active daemon (first alive) */
    bs.player_daemon_idx = 0;
    for (int i = 0; i < p->party_size; i++) {
        if (p->party[i].hp_current > 0) {
            bs.player_daemon_idx = i;
            break;
        }
    }
    bs.player_daemon = &p->party[bs.player_daemon_idx];

    sprintf(bs.message, "Wild %s (Lv%d) appeared!",
            bs.enemy_daemon->nickname, bs.enemy_daemon->level);
    bs.message_timer = 90;

    p->daemons_seen++;
    draw_battle(&bs);
}

/* ══════════════════════════════════════════════════════════════
 *  START TRAINER BATTLE
 * ══════════════════════════════════════════════════════════════ */
void start_trainer_battle(Player *p, Trainer *t) {
    memset(&bs, 0, sizeof(BattleState));
    bs.player = p;
    bs.is_wild = 0;
    bs.trainer = t;
    bs.battle_over = 0;
    bs.player_won = 0;
    bs.turn = 0;
    bs.cursor = 0;
    bs.menu_mode = BMENU_MAIN;
    bs.catch_attempts = 0;
    bs.run_attempts = 0;
    bs.trainer_daemon_idx = 0;
    bs.message_timer = 0;

    bs.enemy_daemon = &t->party[0];

    bs.player_daemon_idx = 0;
    for (int i = 0; i < p->party_size; i++) {
        if (p->party[i].hp_current > 0) {
            bs.player_daemon_idx = i;
            break;
        }
    }
    bs.player_daemon = &p->party[bs.player_daemon_idx];

    sprintf(bs.message, "%s wants to battle!", t->name);
    bs.message_timer = 90;

    draw_battle(&bs);
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE BATTLE VICTORY
 * ══════════════════════════════════════════════════════════════ */
static void handle_victory(BattleState *b, GameState *state) {
    int exp_gained = b->enemy_daemon->level * 50;
    if (!b->is_wild) exp_gained = exp_gained * 3 / 2;

    gain_exp(b->player_daemon, exp_gained, b->player);

    consoleClear();
    iprintf("\n  [+] VICTORY!\n\n");
    iprintf("  %s gained %d EXP!\n", b->player_daemon->nickname, exp_gained);
    iprintf("  Level: %d\n", b->player_daemon->level);

    if (!b->is_wild && b->trainer != NULL) {
        int prize = b->trainer->party[0].level * 50;
        b->player->money += prize;
        b->trainer->defeated = 1;
        iprintf("  Won $%d!\n", prize);
    }

    iprintf("\n  Press B to continue.\n");
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE BATTLE DEFEAT
 * ══════════════════════════════════════════════════════════════ */
static void handle_defeat(BattleState *b, GameState *state) {
    consoleClear();
    iprintf("\n  [-] DEFEATED!\n\n");
    iprintf("  All your daemons fainted.\n");
    iprintf("  You blacked out...\n");

    /* Lose some money */
    int lost = b->player->money / 4;
    b->player->money -= lost;
    if (b->player->money < 0) b->player->money = 0;
    iprintf("  Lost $%d...\n", lost);

    /* Heal party and return to start */
    for (int i = 0; i < b->player->party_size; i++) {
        b->player->party[i].hp_current = b->player->party[i].hp_max;
        b->player->party[i].status = STATUS_NONE;
        for (int j = 0; j < b->player->party[i].move_count; j++) {
            b->player->party[i].moves[j].pp_current =
                b->player->party[i].moves[j].pp_max;
        }
    }
    b->player->x = 5;
    b->player->y = 5;
    b->player->map_id = 0;

    iprintf("\n  Press B to continue.\n");
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE BATTLE INPUT
 * ══════════════════════════════════════════════════════════════ */
void handle_battle_input(u16 keys, GameState *state, Player *p) {
    /* If message is displaying, wait for it to expire */
    if (bs.message_timer > 0) {
        bs.message_timer--;
        if (bs.message_timer == 0) {
            /* Check if battle ended */
            if (bs.battle_over) {
                if (bs.player_won)
                    handle_victory(&bs, state);
                else
                    handle_defeat(&bs, state);
                bs.message_timer = -1; /* Flag: waiting for B to exit */
                return;
            }
            /* Check if current daemon fainted - force switch */
            if (bs.player_daemon->hp_current <= 0) {
                int has_alive = 0;
                for (int i = 0; i < p->party_size; i++) {
                    if (p->party[i].hp_current > 0) { has_alive = 1; break; }
                }
                if (has_alive) {
                    bs.menu_mode = BMENU_DAEMON;
                    bs.cursor = 0;
                    sprintf(bs.message, "%s fainted! Switch daemon!", bs.player_daemon->nickname);
                    bs.message_timer = 60;
                    return;
                }
            }
            draw_battle(&bs);
        }
        return;
    }

    /* Waiting for exit press after battle end */
    if (bs.message_timer == -1) {
        if (keys & KEY_B) {
            *state = STATE_OVERWORLD;
            draw_overworld(p);
        }
        return;
    }

    switch (bs.menu_mode) {
    case BMENU_MAIN:
        /* Navigate main menu (2x2 grid) */
        if (keys & KEY_UP) { if (bs.cursor >= 2) bs.cursor -= 2; draw_battle(&bs); }
        if (keys & KEY_DOWN) { if (bs.cursor < 2) bs.cursor += 2; draw_battle(&bs); }
        if (keys & KEY_LEFT) { if (bs.cursor % 2 == 1) bs.cursor--; draw_battle(&bs); }
        if (keys & KEY_RIGHT) { if (bs.cursor % 2 == 0) bs.cursor++; draw_battle(&bs); }

        if (keys & KEY_A) {
            switch (bs.cursor) {
            case 0: /* FIGHT */
                bs.menu_mode = BMENU_MOVE;
                bs.cursor = 0;
                draw_battle(&bs);
                break;

            case 1: /* CAPTURE */
                if (!bs.is_wild) {
                    sprintf(bs.message, "Can't capture trainer daemons!");
                    bs.message_timer = 60;
                } else {
                    /* Find capture item */
                    int cap_item = -1;
                    int cap_bonus = 0;
                    if (p->items[6] > 0) { cap_item = 6; cap_bonus = 100; }
                    else if (p->items[5] > 0) { cap_item = 5; cap_bonus = 25; }
                    else if (p->items[4] > 0) { cap_item = 4; cap_bonus = 10; }

                    if (cap_item < 0) {
                        sprintf(bs.message, "No capture items!");
                        bs.message_timer = 60;
                    } else if (p->party_size >= 6) {
                        sprintf(bs.message, "Party is full!");
                        bs.message_timer = 60;
                    } else {
                        p->items[cap_item]--;
                        bs.catch_attempts++;

                        if (attempt_capture(bs.enemy_daemon, cap_bonus)) {
                            /* Captured! */
                            p->party[p->party_size] = bs.enemy_copy;
                            p->party_size++;
                            p->daemons_caught++;
                            sprintf(bs.message, "Captured %s!",
                                    bs.enemy_daemon->nickname);
                            bs.battle_over = 1;
                            bs.player_won = 1;
                            bs.message_timer = 90;
                        } else {
                            sprintf(bs.message, "%s broke free!",
                                    bs.enemy_daemon->nickname);
                            bs.message_timer = 60;
                            /* Enemy gets a turn */
                            /* (simplified: enemy attacks after failed capture) */
                        }
                    }
                }
                draw_battle(&bs);
                break;

            case 2: /* DAEMON (switch) */
                if (p->party_size <= 1) {
                    sprintf(bs.message, "No other daemons!");
                    bs.message_timer = 60;
                } else {
                    bs.menu_mode = BMENU_DAEMON;
                    bs.cursor = 0;
                }
                draw_battle(&bs);
                break;

            case 3: /* RUN */
                if (!bs.is_wild) {
                    sprintf(bs.message, "Can't flee trainer battles!");
                    bs.message_timer = 60;
                } else {
                    /* VPN item guarantees escape */
                    if (p->items[9] > 0) {
                        p->items[9]--;
                        *state = STATE_OVERWORLD;
                        draw_overworld(p);
                        return;
                    }
                    bs.run_attempts++;
                    int escape_chance = 50 + (bs.run_attempts * 15) +
                        (bs.player_daemon->spd - bs.enemy_daemon->spd);
                    if (escape_chance > 95) escape_chance = 95;
                    if ((rand() % 100) < escape_chance) {
                        *state = STATE_OVERWORLD;
                        draw_overworld(p);
                        return;
                    } else {
                        sprintf(bs.message, "Couldn't escape!");
                        bs.message_timer = 60;
                    }
                }
                draw_battle(&bs);
                break;
            }
        }
        break;

    case BMENU_MOVE:
        if (keys & KEY_UP) {
            if (bs.cursor > 0) bs.cursor--;
            draw_battle(&bs);
        }
        if (keys & KEY_DOWN) {
            if (bs.cursor < bs.player_daemon->move_count - 1) bs.cursor++;
            draw_battle(&bs);
        }
        if (keys & KEY_B) {
            bs.menu_mode = BMENU_MAIN;
            bs.cursor = 0;
            draw_battle(&bs);
        }
        if (keys & KEY_A) {
            Move *m = &bs.player_daemon->moves[bs.cursor];
            if (m->pp_current <= 0) {
                sprintf(bs.message, "No PP left for %s!", m->name);
                bs.message_timer = 60;
            } else {
                execute_turn(bs.cursor, &bs);
            }
            bs.menu_mode = BMENU_MAIN;
            bs.cursor = 0;
            draw_battle(&bs);
        }
        break;

    case BMENU_DAEMON:
        if (keys & KEY_UP) {
            if (bs.cursor > 0) bs.cursor--;
            draw_battle(&bs);
        }
        if (keys & KEY_DOWN) {
            if (bs.cursor < p->party_size - 1) bs.cursor++;
            draw_battle(&bs);
        }
        if (keys & KEY_B) {
            /* Can't back out if forced switch */
            if (bs.player_daemon->hp_current > 0) {
                bs.menu_mode = BMENU_MAIN;
                bs.cursor = 0;
                draw_battle(&bs);
            }
        }
        if (keys & KEY_A) {
            if (p->party[bs.cursor].hp_current <= 0) {
                sprintf(bs.message, "%s has fainted!", p->party[bs.cursor].nickname);
                bs.message_timer = 60;
            } else if (bs.cursor == bs.player_daemon_idx) {
                sprintf(bs.message, "Already in battle!");
                bs.message_timer = 60;
            } else {
                bs.player_daemon_idx = bs.cursor;
                bs.player_daemon = &p->party[bs.player_daemon_idx];
                sprintf(bs.message, "Go, %s!", bs.player_daemon->nickname);
                bs.message_timer = 60;
                bs.menu_mode = BMENU_MAIN;
                bs.cursor = 0;

                /* Enemy gets a free attack on switch */
                if (bs.enemy_daemon->hp_current > 0) {
                    int emove = enemy_choose_move(bs.enemy_daemon, bs.player_daemon);
                    execute_move(bs.enemy_daemon, bs.player_daemon,
                                &bs.enemy_daemon->moves[emove], &bs);
                }
            }
            draw_battle(&bs);
        }
        break;

    case BMENU_ITEM:
        {
            int item_count = count_available_items(p);
            if (keys & KEY_UP) {
                if (bs.cursor > 0) bs.cursor--;
                draw_battle(&bs);
            }
            if (keys & KEY_DOWN) {
                if (bs.cursor < item_count - 1) bs.cursor++;
                draw_battle(&bs);
            }
            if (keys & KEY_B) {
                bs.menu_mode = BMENU_MAIN;
                bs.cursor = 0;
                draw_battle(&bs);
            }
            if (keys & KEY_A) {
                int item_id = get_item_id_from_cursor(p, bs.cursor);
                if (item_id >= 0 && p->items[item_id] > 0) {
                    Item *item = &ALL_ITEMS[item_id];
                    p->items[item_id]--;

                    if (item->type == 0) {
                        /* Healing item */
                        if (item->value >= 9999) {
                            bs.player_daemon->hp_current = bs.player_daemon->hp_max;
                        } else if (item->value == 1) {
                            /* Reboot: revive with half HP (use from menu) */
                            bs.player_daemon->hp_current = bs.player_daemon->hp_max / 2;
                        } else if (item->value == 2) {
                            /* Full Reboot: revive with full HP */
                            bs.player_daemon->hp_current = bs.player_daemon->hp_max;
                        } else {
                            bs.player_daemon->hp_current += item->value;
                            if (bs.player_daemon->hp_current > bs.player_daemon->hp_max)
                                bs.player_daemon->hp_current = bs.player_daemon->hp_max;
                        }
                        sprintf(bs.message, "Used %s! HP restored!", item->name);
                    } else {
                        sprintf(bs.message, "Used %s!", item->name);
                    }
                    bs.message_timer = 60;
                    bs.menu_mode = BMENU_MAIN;
                    bs.cursor = 0;
                }
                draw_battle(&bs);
            }
        }
        break;

    default:
        bs.menu_mode = BMENU_MAIN;
        break;
    }
}
