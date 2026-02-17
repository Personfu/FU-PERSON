/*
 * CyberWorld — Map System Header
 * FLLC | FU PERSON | DSi Homebrew RPG
 */
#ifndef MAP_H
#define MAP_H

#include "types.h"

extern Map ALL_MAPS[];
extern Trainer ALL_TRAINERS[];
extern int MAP_COUNT;
extern int TRAINER_COUNT;

void draw_overworld(Player *p);
void handle_overworld_input(Player *p, u16 keys, GameState *state);
int player_on_grass(Player *p);
void init_maps(void);

#endif /* MAP_H */
