/*
 * CyberWorld — Menu System Header
 * FLLC | FU PERSON | DSi Homebrew RPG
 */
#ifndef MENU_H
#define MENU_H

#include "types.h"

/* Menu modes */
#define MENU_MAIN     0
#define MENU_PARTY    1
#define MENU_ITEMS    2
#define MENU_DETAIL   3
#define MENU_PLAYER   4
#define MENU_SHOP     5

void draw_menu(Player *p, int mode, int cursor);
void handle_menu_input(u16 keys, GameState *state, Player *p);
void handle_shop_input(u16 keys, GameState *state, Player *p);

#endif /* MENU_H */
