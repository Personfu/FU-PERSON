/*
 * CyberWorld — Map & Overworld System
 * FLLC | FU PERSON | DSi Homebrew RPG
 *
 * 8 maps with tile-based movement, NPCs, wild encounters,
 * map connections, and heal stations.
 *
 * Tile Legend:
 *   0 = floor '.'    1 = wall '#'     2 = grass '~'
 *   3 = water '='    4 = door 'D'     5 = npc '@'
 *   6 = heal 'H'     7 = shop '$'
 */
#include "map.h"
#include "battle.h"
#include "daemon_data.h"

/* Viewport size (DS screen in text mode) */
#define VIEW_W 30
#define VIEW_H 18

/* ══════════════════════════════════════════════════════════════
 *  MAP DATA — 8 regions
 * ══════════════════════════════════════════════════════════════ */

/* Helper to fill a map row. Maps are 32x24. */
static void fill_row(u8 row[MAP_W], const char *pattern) {
    for (int i = 0; i < MAP_W && pattern[i] != '\0'; i++) {
        switch (pattern[i]) {
        case '#': row[i] = 1; break;
        case '~': row[i] = 2; break;
        case '=': row[i] = 3; break;
        case 'D': row[i] = 4; break;
        case '@': row[i] = 5; break;
        case 'H': row[i] = 6; break;
        case '$': row[i] = 7; break;
        default:  row[i] = 0; break;
        }
    }
}

Map ALL_MAPS[MAX_MAPS];
int MAP_COUNT = 8;

void init_maps(void) {
    memset(ALL_MAPS, 0, sizeof(ALL_MAPS));

    /* ── MAP 0: LAN Valley (starter town) ────────────────────── */
    {
        Map *m = &ALL_MAPS[0];
        strcpy(m->name, "LAN Valley");
        m->id = 0;
        m->connections[0] = -1; /* N */
        m->connections[1] = 1;  /* S: Packet Plains */
        m->connections[2] = 2;  /* E: Firewall Fortress */
        m->connections[3] = -1; /* W */
        m->wild_daemon_ids[0] = 0;  /* Ping */
        m->wild_daemon_ids[1] = 3;  /* Portknock */
        m->wild_daemon_ids[2] = 6;  /* Sniffer */
        m->wild_daemon_count = 3;
        m->wild_level_min = 2;
        m->wild_level_max = 6;

        const char *rows[] = {
            "################################",
            "#..............................#",
            "#..H...@.......................#",
            "#..............................#",
            "#....~~~~....####..............#",
            "#...~~~~~~...#..#....@.........#",
            "#...~~~~~~...#..#..............#",
            "#....~~~~....####..............#",
            "#..............................#",
            "#..........~~~~...........$$...#",
            "#.........~~~~~~..............D#",
            "#.........~~~~~~..............D#",
            "#..........~~~~................#",
            "#...@..........................#",
            "#..............................#",
            "#.....~~~~.....................#",
            "#....~~~~~~....................#",
            "#....~~~~~~.....@..............#",
            "#.....~~~~.....................#",
            "#..............................#",
            "#..............................#",
            "#..........@...................#",
            "#.............................D#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 1: Packet Plains ─────────────────────────────────── */
    {
        Map *m = &ALL_MAPS[1];
        strcpy(m->name, "Packet Plains");
        m->id = 1;
        m->connections[0] = 0;  /* N: LAN Valley */
        m->connections[1] = 3;  /* S: Wireless Woods */
        m->connections[2] = 4;  /* E: Cloud Citadel */
        m->connections[3] = -1; /* W */
        m->wild_daemon_ids[0] = 9;   /* XSSling */
        m->wild_daemon_ids[1] = 12;  /* SQLimp */
        m->wild_daemon_ids[2] = 15;  /* Crawlr */
        m->wild_daemon_ids[3] = 27;  /* Phishling */
        m->wild_daemon_count = 4;
        m->wild_level_min = 5;
        m->wild_level_max = 12;

        const char *rows[] = {
            "################################",
            "#D............................D#",
            "#..............................#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..............................#",
            "#........@.......@.............#",
            "#..............................#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..............................#",
            "#....H.........................#",
            "#..............................#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..............................#",
            "#..........@...................#",
            "#..............................#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..~~~...~~~...~~~...~~~........#",
            "#..............................#",
            "#..............................#",
            "#D............................D#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 2: Firewall Fortress ─────────────────────────────── */
    {
        Map *m = &ALL_MAPS[2];
        strcpy(m->name, "Firewall Fortress");
        m->id = 2;
        m->connections[0] = 5;  /* N: WAN Wasteland */
        m->connections[1] = -1; /* S */
        m->connections[2] = -1; /* E */
        m->connections[3] = 0;  /* W: LAN Valley */
        m->wild_daemon_ids[0] = 18;  /* Stacksmash */
        m->wild_daemon_ids[1] = 21;  /* Shellcode */
        m->wild_daemon_ids[2] = 24;  /* Debugger */
        m->wild_daemon_ids[3] = 36;  /* Hashling */
        m->wild_daemon_count = 4;
        m->wild_level_min = 8;
        m->wild_level_max = 16;

        const char *rows[] = {
            "####D###########################",
            "#..............................#",
            "#.####.####.####.####.####.....#",
            "#.#..#.#..#.#..#.#..#.#..#.....#",
            "#.####.####.####.####.####.....#",
            "#..............................#",
            "#...@......@.......H...........#",
            "#..............................#",
            "#.####.####.####.####.####.....#",
            "#.#..#.#..#.#..#.#..#.#..#.....#",
            "#.####.####.####.####.####.....#",
            "D..............................#",
            "#..............................#",
            "#.####.####.####.####.####.....#",
            "#.#..#.#..#.#..#.#..#.#..#.....#",
            "#.####.####.####.####.####.....#",
            "#..............................#",
            "#......@.........@.............#",
            "#..............................#",
            "#..~~~~..~~~~..~~~~..~~~~......#",
            "#..~~~~..~~~~..~~~~..~~~~......#",
            "#..............................#",
            "#..............................#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 3: Wireless Woods ────────────────────────────────── */
    {
        Map *m = &ALL_MAPS[3];
        strcpy(m->name, "Wireless Woods");
        m->id = 3;
        m->connections[0] = 1;  /* N: Packet Plains */
        m->connections[1] = 6;  /* S: Darknet Depths */
        m->connections[2] = -1; /* E */
        m->connections[3] = -1; /* W */
        m->wild_daemon_ids[0] = 45;  /* Beacon */
        m->wild_daemon_ids[1] = 48;  /* Probe */
        m->wild_daemon_ids[2] = 33;  /* Baiter */
        m->wild_daemon_ids[3] = 42;  /* Keylogr */
        m->wild_daemon_count = 4;
        m->wild_level_min = 10;
        m->wild_level_max = 20;

        const char *rows[] = {
            "####D###########################",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#~~~.~~~.~~~.~~~.~~~.~~~.~~~...#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#..............................#",
            "#..@...........................#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#~~~.~~~.~~~.~~~.~~~.~~~.~~~...#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#.............H................#",
            "#..............................#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#~~~.~~~.~~~.~~~.~~~.~~~.~~~...#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#..............................#",
            "#.......@..........@...........#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#~~~.~~~.~~~.~~~.~~~.~~~.~~~...#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#..............................#",
            "#..............................#",
            "#.~~~.~~~.~~~.~~~.~~~.~~~.~~~..#",
            "#D.............................#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 4: Cloud Citadel ─────────────────────────────────── */
    {
        Map *m = &ALL_MAPS[4];
        strcpy(m->name, "Cloud Citadel");
        m->id = 4;
        m->connections[0] = -1; /* N */
        m->connections[1] = -1; /* S */
        m->connections[2] = 5;  /* E: WAN Wasteland */
        m->connections[3] = 1;  /* W: Packet Plains */
        m->wild_daemon_ids[0] = 30;  /* Pretextr */
        m->wild_daemon_ids[1] = 39;  /* Cipher */
        m->wild_daemon_ids[2] = 51;  /* Rubberduck */
        m->wild_daemon_ids[3] = 54;  /* Lockpick */
        m->wild_daemon_count = 4;
        m->wild_level_min = 15;
        m->wild_level_max = 25;

        const char *rows[] = {
            "################################",
            "#====..........====............#",
            "#====...####...====............#",
            "#.......#..#...................#",
            "#.......#H.#.......~~~.........#",
            "#.......####......~~~~~........#",
            "#.................~~~~~........#",
            "#..................~~~.........#",
            "#..............................#",
            "#..@...........@...............#",
            "#..............................#",
            "D.........####.####............D",
            "#.........#..#.#..#............#",
            "#.........####.####............#",
            "#..............................#",
            "#...@..............@...........#",
            "#..............................#",
            "#.......~~~.......====.........#",
            "#......~~~~~......====.........#",
            "#......~~~~~...................#",
            "#.......~~~....................#",
            "#..............................#",
            "#.....$........................#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 5: WAN Wasteland ─────────────────────────────────── */
    {
        Map *m = &ALL_MAPS[5];
        strcpy(m->name, "WAN Wasteland");
        m->id = 5;
        m->connections[0] = -1; /* N */
        m->connections[1] = 2;  /* S: Firewall Fortress */
        m->connections[2] = 7;  /* E: Zero-Day Peaks */
        m->connections[3] = 4;  /* W: Cloud Citadel */
        m->wild_daemon_ids[0] = 1;   /* Tracert */
        m->wild_daemon_ids[1] = 10;  /* CrossSite */
        m->wild_daemon_ids[2] = 22;  /* Payload */
        m->wild_daemon_ids[3] = 28;  /* Spearphish */
        m->wild_daemon_ids[4] = 37;  /* Hasher */
        m->wild_daemon_ids[5] = 46;  /* Deauther */
        m->wild_daemon_count = 6;
        m->wild_level_min = 20;
        m->wild_level_max = 35;

        const char *rows[] = {
            "################################",
            "#..===.........................#",
            "#..===...~~~~.......====.......#",
            "#........~~~~.......====.......#",
            "#..............................#",
            "#...@.....@.........@..........#",
            "#..............................#",
            "#.....~~~~.......~~~~..........#",
            "#.....~~~~.......~~~~..........#",
            "#..............................#",
            "#............H.................#",
            "#..............................#",
            "D..~~~~.......~~~~.......~~~~..D",
            "#..~~~~.......~~~~.......~~~~..#",
            "#..............................#",
            "#.......@.........@............#",
            "#..............................#",
            "#..====.......====.......====..#",
            "#..====.......====.......====..#",
            "#..............................#",
            "#..............................#",
            "#..............................#",
            "#D.............................#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 6: Darknet Depths ────────────────────────────────── */
    {
        Map *m = &ALL_MAPS[6];
        strcpy(m->name, "Darknet Depths");
        m->id = 6;
        m->connections[0] = 3;  /* N: Wireless Woods */
        m->connections[1] = -1; /* S */
        m->connections[2] = 7;  /* E: Zero-Day Peaks */
        m->connections[3] = -1; /* W */
        m->wild_daemon_ids[0] = 19;  /* Overflow */
        m->wild_daemon_ids[1] = 25;  /* Reverser */
        m->wild_daemon_ids[2] = 31;  /* Impersonatr */
        m->wild_daemon_ids[3] = 43;  /* Cracker */
        m->wild_daemon_ids[4] = 49;  /* WifiSniff */
        m->wild_daemon_ids[5] = 52;  /* BadUSB */
        m->wild_daemon_count = 6;
        m->wild_level_min = 25;
        m->wild_level_max = 40;

        const char *rows[] = {
            "####D###########################",
            "#.#....#.....#.....#.....#.....#",
            "#.#.##.#.###.#.###.#.###.#.###.#",
            "#.#.#..#...#.#...#.....#...#...#",
            "#.#.#.####.#.###.#####.#####.#.#",
            "#...#......#.....#.....#.....#.#",
            "#.#####.####.#####.#####.#####.#",
            "#.#.....#..........#...........#",
            "#.#.###.#.#####.####.#####.###.#",
            "#...#.#.#.#...#......#...#.#...#",
            "#.###.#.#.#.#.########.#.#.#.###",
            "#.....#...#.#..........#.#.#...D",
            "#.#########.############.#.###.#",
            "#.........#..............#.....#",
            "#.#######.####.##########.#####.#",
            "#.......#......#........#.....#",
            "#.#####.########.######.#####.#",
            "#.#...#..........#....#.......#",
            "#.#.#.####.########.#.#########",
            "#...#......#.H......#.........#",
            "#.#########.########.#########.#",
            "#.........#..........#.........#",
            "#.#######.############.#######.#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }

    /* ── MAP 7: Zero-Day Peaks (endgame) ──────────────────────── */
    {
        Map *m = &ALL_MAPS[7];
        strcpy(m->name, "Zero-Day Peaks");
        m->id = 7;
        m->connections[0] = -1; /* N */
        m->connections[1] = -1; /* S */
        m->connections[2] = -1; /* E */
        m->connections[3] = 5;  /* W: WAN Wasteland */
        m->wild_daemon_ids[0] = 2;   /* Nmap */
        m->wild_daemon_ids[1] = 14;  /* Sqlmap */
        m->wild_daemon_ids[2] = 23;  /* Meterpreter */
        m->wild_daemon_ids[3] = 44;  /* JohnRipper */
        m->wild_daemon_ids[4] = 50;  /* Aircrack */
        m->wild_daemon_ids[5] = 57;  /* ZeroDawn (rare!) */
        m->wild_daemon_count = 6;
        m->wild_level_min = 35;
        m->wild_level_max = 55;

        const char *rows[] = {
            "################################",
            "#==============================#",
            "#==............................=#",
            "#==..####.####.####.####.####..=#",
            "#==..#..#.#..#.#..#.#..#.#..#..=#",
            "#==..####.####.####.####.####..=#",
            "#==............................=#",
            "#==...@......@......@......@...=#",
            "#==............................=#",
            "#==..~~~~..~~~~..~~~~..~~~~....=#",
            "#==..~~~~..~~~~..~~~~..~~~~....=#",
            "#==............................=#",
            "D==.........H..................=#",
            "#==............................=#",
            "#==..~~~~..~~~~..~~~~..~~~~....=#",
            "#==..~~~~..~~~~..~~~~..~~~~....=#",
            "#==............................=#",
            "#==...@......@......@......@...=#",
            "#==............................=#",
            "#==..####.####.####.####.####..=#",
            "#==..#..#.#..#.#..#.#..#.#..#..=#",
            "#==..####.####.####.####.####..=#",
            "#==............................=#",
            "################################",
        };
        for (int r = 0; r < MAP_H; r++)
            fill_row(m->tiles[r], rows[r]);
    }
}

/* ══════════════════════════════════════════════════════════════
 *  TRAINER DATA
 * ══════════════════════════════════════════════════════════════ */
extern Daemon create_daemon(int species_id, int level);

Trainer ALL_TRAINERS[MAX_TRAINERS];
int TRAINER_COUNT = 0;

static void init_trainer(int idx, const char *name, int map, int x, int y,
                         int species, int level,
                         const char *before, const char *after) {
    if (idx >= MAX_TRAINERS) return;
    Trainer *t = &ALL_TRAINERS[idx];
    memset(t, 0, sizeof(Trainer));
    strncpy(t->name, name, 19);
    t->x = x;
    t->y = y;
    t->map_id = map;
    t->party[0] = create_daemon(species, level);
    t->party_size = 1;
    t->defeated = 0;
    strncpy(t->dialog_before, before, 119);
    strncpy(t->dialog_after, after, 119);
    if (idx >= TRAINER_COUNT) TRAINER_COUNT = idx + 1;
}

void init_trainers(void) {
    TRAINER_COUNT = 0;

    /* LAN Valley trainers */
    init_trainer(0, "Script Kiddie", 0, 7, 2,
                 0, 5, "I just learned to ping!", "Whoa, you're good...");
    init_trainer(1, "Intern", 0, 20, 5,
                 3, 6, "First day on the SOC team!", "I need more training...");
    init_trainer(2, "Helpdesk Joe", 0, 6, 13,
                 6, 7, "Have you tried rebooting?", "I'll escalate this ticket.");
    init_trainer(3, "Newbie Admin", 0, 10, 17,
                 27, 6, "Password is admin123!", "I should change that...");
    init_trainer(4, "Jr Analyst", 0, 10, 21,
                 36, 8, "Let me check the hashes.", "Your crypto is strong.");

    /* Packet Plains trainers */
    init_trainer(5, "Web Dev", 1, 8, 6,
                 9, 10, "My code is fully sanitized!", "Maybe not fully...");
    init_trainer(6, "Pen Tester", 1, 17, 6,
                 12, 12, "Starting web recon now!", "Nice exploit chain!");
    init_trainer(7, "QA Tester", 1, 10, 16,
                 15, 11, "I found a bug in prod!", "That was a feature...");

    /* Firewall Fortress trainers */
    init_trainer(8, "Firewall Admin", 2, 4, 6,
                 18, 14, "Nothing gets past my rules!", "My ACLs failed!");
    init_trainer(9, "SOC Analyst", 2, 11, 6,
                 24, 15, "I see your packets!", "Blind spot detected.");
    init_trainer(10, "Binary Ninja", 2, 7, 17,
                  21, 16, "Time to reverse this!", "You broke my analysis.");
    init_trainer(11, "Crypto Bro", 2, 17, 17,
                  39, 15, "My encryption is unbreakable!", "Key compromised...");

    /* Wireless Woods trainers */
    init_trainer(12, "War Driver", 3, 3, 5,
                 45, 18, "Scanning all the APs!", "Signal lost...");
    init_trainer(13, "IoT Hacker", 3, 8, 15,
                 48, 19, "Smart devices everywhere!", "They were too smart.");
    init_trainer(14, "RF Expert", 3, 19, 15,
                 51, 20, "I control the spectrum!", "Jammed by your signal.");

    /* Cloud Citadel trainers */
    init_trainer(15, "Cloud Architect", 4, 3, 9,
                 30, 22, "My infra is serverless!", "Infrastructure as gone.");
    init_trainer(16, "DevOps Lead", 4, 12, 9,
                 42, 23, "CI/CD pipeline engaged!", "Pipeline broken.");
    init_trainer(17, "CISO Jr", 4, 4, 15,
                 34, 24, "Security is my priority!", "Budget request denied.");
    init_trainer(18, "Red Teamer", 4, 17, 15,
                 22, 25, "Payload delivered!", "Shell dropped. GG.");

    /* WAN Wasteland trainers */
    init_trainer(19, "APT Hunter", 5, 4, 5,
                 28, 30, "Tracking nation-state actors!", "Lost the trail...");
    init_trainer(20, "Threat Intel", 5, 10, 5,
                 37, 32, "I have the indicators!", "New IOCs needed.");
    init_trainer(21, "Exploit Dev", 5, 20, 5,
                 19, 33, "Crafting the perfect overflow!", "Patched! Nooo!");
    init_trainer(22, "Bug Bounty", 5, 8, 15,
                 10, 31, "Found a critical vuln!", "Duplicate... again.");
    init_trainer(23, "Dark Web Trader", 5, 18, 15,
                 43, 34, "Want some zero-days?", "Out of stock.");

    /* Zero-Day Peaks trainers (CISO boss fight) */
    init_trainer(24, "Elite Hacker", 7, 6, 7,
                 2, 42, "I am the Nmap.", "Impossible... you mapped me.");
    init_trainer(25, "APT Operator", 7, 14, 7,
                 23, 44, "Meterpreter is online.", "Session terminated.");
    init_trainer(26, "Malware Author", 7, 22, 7,
                 44, 45, "My code is polymorphic!", "Signature detected.");
    init_trainer(27, "CISO Final", 7, 6, 17,
                 59, 50, "I am the CISO. The final firewall.", "Impossible! My defenses!");
    init_trainer(28, "Shadow Admin", 7, 14, 17,
                 58, 48, "Root access: obtained.", "Permissions revoked.");
    init_trainer(29, "Zero-Day Broker", 7, 22, 17,
                 57, 46, "Selling the unseen.", "Disclosed and patched.");
}

/* ══════════════════════════════════════════════════════════════
 *  GET TILE CHARACTER FOR DISPLAY
 * ══════════════════════════════════════════════════════════════ */
static char tile_char(u8 tile) {
    switch (tile) {
    case 0: return '.';
    case 1: return '#';
    case 2: return '~';
    case 3: return '=';
    case 4: return 'D';
    case 5: return '@';
    case 6: return 'H';
    case 7: return '$';
    default: return '?';
    }
}

/* ══════════════════════════════════════════════════════════════
 *  CHECK IF TILE IS WALKABLE
 * ══════════════════════════════════════════════════════════════ */
static int is_walkable(u8 tile) {
    return tile == 0 || tile == 2 || tile == 4 || tile == 5 || tile == 6 || tile == 7;
}

/* ══════════════════════════════════════════════════════════════
 *  DRAW OVERWORLD VIEWPORT
 * ══════════════════════════════════════════════════════════════ */
void draw_overworld(Player *p) {
    consoleClear();
    Map *map = &ALL_MAPS[p->map_id];

    /* Calculate viewport offset centered on player */
    int vx = p->x - VIEW_W / 2;
    int vy = p->y - VIEW_H / 2;
    if (vx < 0) vx = 0;
    if (vy < 0) vy = 0;
    if (vx + VIEW_W > MAP_W) vx = MAP_W - VIEW_W;
    if (vy + VIEW_H > MAP_H) vy = MAP_H - VIEW_H;
    if (vx < 0) vx = 0;
    if (vy < 0) vy = 0;

    for (int row = 0; row < VIEW_H && (vy + row) < MAP_H; row++) {
        for (int col = 0; col < VIEW_W && (vx + col) < MAP_W; col++) {
            int mx = vx + col;
            int my = vy + row;
            if (mx == p->x && my == p->y) {
                iprintf("P");
            } else {
                iprintf("%c", tile_char(map->tiles[my][mx]));
            }
        }
        iprintf("\n");
    }

    /* Status bar */
    iprintf("%-12s Lv%d  $%d\n", map->name, p->party[0].level, p->money);
    iprintf("[%d,%d] HP:%d/%d  B%d\n",
            p->x, p->y,
            p->party[0].hp_current, p->party[0].hp_max,
            p->badges);
    iprintf("START:Menu SELECT:WiFi\n");
}

/* ══════════════════════════════════════════════════════════════
 *  CHECK IF PLAYER IS ON GRASS
 * ══════════════════════════════════════════════════════════════ */
int player_on_grass(Player *p) {
    Map *map = &ALL_MAPS[p->map_id];
    return map->tiles[p->y][p->x] == 2;
}

/* ══════════════════════════════════════════════════════════════
 *  FIND TRAINER AT POSITION
 * ══════════════════════════════════════════════════════════════ */
static Trainer *find_trainer_at(int map_id, int x, int y) {
    for (int i = 0; i < TRAINER_COUNT; i++) {
        if (ALL_TRAINERS[i].map_id == map_id &&
            ALL_TRAINERS[i].x == x &&
            ALL_TRAINERS[i].y == y) {
            return &ALL_TRAINERS[i];
        }
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 *  MAP TRANSITION
 * ══════════════════════════════════════════════════════════════ */
static void try_map_transition(Player *p, int dir) {
    Map *map = &ALL_MAPS[p->map_id];
    int next = map->connections[dir];
    if (next >= 0 && next < MAP_COUNT) {
        p->map_id = next;
        switch (dir) {
        case 0: p->y = MAP_H - 2; break; /* North: enter from bottom */
        case 1: p->y = 1; break;          /* South: enter from top */
        case 2: p->x = 1; break;          /* East: enter from left */
        case 3: p->x = MAP_W - 2; break;  /* West: enter from right */
        }
    }
}

/* ══════════════════════════════════════════════════════════════
 *  HANDLE OVERWORLD INPUT
 * ══════════════════════════════════════════════════════════════ */
void handle_overworld_input(Player *p, u16 keys, GameState *state) {
    Map *map = &ALL_MAPS[p->map_id];
    int nx = p->x;
    int ny = p->y;
    int moved = 0;

    if (keys & KEY_UP)    { ny--; moved = 1; }
    if (keys & KEY_DOWN)  { ny++; moved = 1; }
    if (keys & KEY_LEFT)  { nx--; moved = 1; }
    if (keys & KEY_RIGHT) { nx++; moved = 1; }

    if (moved) {
        /* Check map edge transitions */
        if (ny < 0) { try_map_transition(p, 0); draw_overworld(p); return; }
        if (ny >= MAP_H) { try_map_transition(p, 1); draw_overworld(p); return; }
        if (nx < 0) { try_map_transition(p, 3); draw_overworld(p); return; }
        if (nx >= MAP_W) { try_map_transition(p, 2); draw_overworld(p); return; }

        u8 tile = map->tiles[ny][nx];

        /* NPC/Trainer interaction */
        if (tile == 5) {
            Trainer *t = find_trainer_at(p->map_id, nx, ny);
            if (t != NULL) {
                consoleClear();
                if (t->defeated) {
                    iprintf("\n  %s:\n  \"%s\"\n", t->name, t->dialog_after);
                    iprintf("\n  Press B to return.\n");
                } else {
                    iprintf("\n  %s:\n  \"%s\"\n", t->name, t->dialog_before);
                    iprintf("\n  Press A to battle!\n");
                }
                *state = STATE_DIALOG;
                /* Store trainer reference for dialog handler */
                return;
            }
        }

        /* Door tile - same as walkable, may trigger special event */
        if (tile == 4) {
            /* Check if it leads to another map (edge door) */
            if (nx == 0) { try_map_transition(p, 3); draw_overworld(p); return; }
            if (nx == MAP_W - 1) { try_map_transition(p, 2); draw_overworld(p); return; }
            if (ny == 0) { try_map_transition(p, 0); draw_overworld(p); return; }
            if (ny == MAP_H - 1) { try_map_transition(p, 1); draw_overworld(p); return; }
        }

        /* Heal station */
        if (tile == 6) {
            *state = STATE_HEAL;
            return;
        }

        /* Shop tile */
        if (tile == 7) {
            *state = STATE_SHOP;
            return;
        }

        /* Normal movement */
        if (is_walkable(tile)) {
            p->x = nx;
            p->y = ny;
        }

        draw_overworld(p);
    }

    /* Menu */
    if (keys & KEY_START) {
        *state = STATE_MENU;
    }

    /* WiFi scan */
    if (keys & KEY_SELECT) {
        *state = STATE_WIFI_SCAN;
    }
}
