/*
 * CyberWorld — Save System Header
 * FLLC | FU PERSON | DSi Homebrew RPG
 */
#ifndef SAVE_H
#define SAVE_H

#include "types.h"

int save_game(Player *p);
int load_game(Player *p);
int save_exists(void);

#endif /* SAVE_H */
