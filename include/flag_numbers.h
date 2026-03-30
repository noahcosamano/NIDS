#ifndef FLAG_NUMBERS_H
#define FLAG_NUMBERS_H

#include <stdint.h>
#include <windows.h>

static const char* GetFlagString(uint8_t flags) {
    static char str[64];
    str[0] = '\0';

    if (flags == 0) {
        return "NONE";
    }

    if (flags & 0x01) strcat(str, "FIN ");
    if (flags & 0x02) strcat(str, "SYN ");
    if (flags & 0x04) strcat(str, "RST ");
    if (flags & 0x08) strcat(str, "PSH ");
    if (flags & 0x10) strcat(str, "ACK ");
    if (flags & 0x20) strcat(str, "URG ");
    if (flags & 0x40) strcat(str, "ECE ");
    if (flags & 0x80) strcat(str, "CWR ");

    size_t len = strlen(str);
    if (len > 0) {
        str[len - 1] = '\0';
    }

    return str;
}

#endif