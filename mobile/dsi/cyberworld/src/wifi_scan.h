/*
 * CyberWorld — WiFi Scanning Header
 * FLLC | FU PERSON | DSi Homebrew RPG
 */
#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include "types.h"

void wifi_init(void);
void wifi_background_scan(void);
void wifi_force_scan(void);
void wifi_show_results(void);
void wifi_save_log(void);
int wifi_get_count(void);

#endif /* WIFI_SCAN_H */
