/*
 * CyberWorld — Battle System Header
 * FLLC | FU PERSON | DSi Homebrew RPG
 */
#ifndef BATTLE_H
#define BATTLE_H

#include "types.h"

/* ── Battle Menu Modes ─────────────────────────────────────── */
#define BMENU_MAIN       0
#define BMENU_MOVE       1
#define BMENU_DAEMON     2
#define BMENU_ITEM       3
#define BMENU_MESSAGE    4

typedef struct {
    Daemon *player_daemon;
    Daemon *enemy_daemon;
    Daemon enemy_copy;       /* Owned copy for wild encounters */
    int is_wild;             /* 1=wild encounter, 0=trainer battle */
    int turn;
    int battle_over;
    int player_won;
    int cursor;              /* Menu cursor position */
    int menu_mode;           /* BMENU_* constant */
    int catch_attempts;
    Trainer *trainer;        /* NULL for wild battles */
    int trainer_daemon_idx;
    char message[120];
    int message_timer;
    Player *player;          /* Back-reference to player */
    int player_daemon_idx;   /* Index in player's party */
    int run_attempts;
} BattleState;

void start_wild_battle(Player *p);
void start_trainer_battle(Player *p, Trainer *t);
void handle_battle_input(u16 keys, GameState *state, Player *p);
void draw_battle(BattleState *bs);
int calculate_damage(Daemon *attacker, Daemon *defender, Move *move);
int attempt_capture(Daemon *target, int item_bonus);
void gain_exp(Daemon *d, int amount, Player *p);
int check_evolution(Daemon *d);
void draw_overworld(Player *p);

#endif /* BATTLE_H */
