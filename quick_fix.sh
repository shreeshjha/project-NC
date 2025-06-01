#!/bin/bash

echo "Applying quick fix for BPF spinlock issue..."

# Create log.h and log.c files
cat > log.h << 'EOF'
#ifndef LOG_H_
#define LOG_H_

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#define LOG_LEVEL_DISABLED 0
#define LOG_LEVEL_FATAL    1
#define LOG_LEVEL_ERROR    2
#define LOG_LEVEL_WARNING  3
#define LOG_LEVEL_INFO     4
#define LOG_LEVEL_DEBUG    5
#define LOG_LEVEL_TRACE    6

#define COLOR_RESET   "\x1b[0m"
#define COLOR_RED     "\x1b[31m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_GREEN   "\x1b[32m"

extern int g_log_level;

static inline void get_time_string(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%H:%M:%S", tm_info);
}

static inline const char* get_filename(const char* path) {
    const char* filename = strrchr(path, '/');
    return filename ? filename + 1 : path;
}

static inline void log_message(int level, const char* file, int line, const char* fmt, ...) {
    if (level > g_log_level) return;
    
    char time_str[32];
    get_time_string(time_str, sizeof(time_str));
    
    const char* level_str;
    const char* color;
    
    switch (level) {
        case LOG_LEVEL_FATAL:   level_str = "FATAL"; color = COLOR_RED; break;
        case LOG_LEVEL_ERROR:   level_str = "ERROR"; color = COLOR_RED; break;
        case LOG_LEVEL_WARNING: level_str = "WARNING"; color = COLOR_YELLOW; break;
        case LOG_LEVEL_INFO:    level_str = "INFO"; color = COLOR_GREEN; break;
        case LOG_LEVEL_DEBUG:   level_str = "DEBUG"; color = COLOR_BLUE; break;
        case LOG_LEVEL_TRACE:   level_str = "TRACE"; color = COLOR_BLUE; break;
        default:                level_str = "UNKNOWN"; color = COLOR_RESET; break;
    }
    
    fprintf(stderr, "%s%s %s %s:%d: ", color, time_str, level_str, get_filename(file), line);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "%s\n", COLOR_RESET);
    
    if (level == LOG_LEVEL_FATAL) {
        exit(1);
    }
}

#define log_fatal(...)   log_message(LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...)   log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_warning(...) log_message(LOG_LEVEL_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...)    log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...)   log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_trace(...)   log_message(LOG_LEVEL_TRACE, __FILE__, __LINE__, __VA_ARGS__)

static inline void set_log_level(int level) {
    g_log_level = level;
}

#endif
EOF

cat > log.c << 'EOF'
#include "log.h"
int g_log_level = LOG_LEVEL_INFO;
EOF

# Fix the main BPF file by removing problematic log calls
echo "Backing up original BPF file..."
cp ebpf/conntrack.bpf.c ebpf/conntrack.bpf.c.backup

echo "Applying BPF spinlock fix..."
# This sed command removes the specific problematic log call while holding the lock
sed -i '/bpf_spin_lock/,/bpf_spin_unlock/{
    /bpf_log_debug.*Connection expired.*removing from map/d
    /bpf_log_debug.*\[FW_DIRECTION\]/d
    /bpf_log_debug.*\[REV_DIRECTION\]/d
    /bpf_log_debug.*Changing state/d
    /bpf_log_debug.*Connnection is ESTABLISHED/d
    /bpf_log_debug.*Failed.*check/d
    /bpf_log_debug.*Should not get here/d
}' ebpf/conntrack.bpf.c

echo "✓ Applied BPF spinlock fix"
echo "✓ Created log.h and log.c files"
echo ""
echo "Now try building and running:"
echo "  make clean && make"
echo "  sudo ./create-topo.sh"
echo "  sudo ./conntrack -1 veth1 -2 veth2 -l 5"
