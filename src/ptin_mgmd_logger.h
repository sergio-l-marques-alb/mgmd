/**
 * ptin_mgmd_logger.h 
 *  
 * Provides logging features 
 *  
 * Created on: 2011/06/18 
 * Author:     Alexandre Santos (alexandre-r-santos@ptinovacao.pt) 
 *  
 * Notes: 
 */

#ifndef _PTIN_MGMD_LOGGER_H
#define _PTIN_MGMD_LOGGER_H

#include <stdio.h>
#include "ptin_mgmd_defs.h"

#if (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)

#define PTIN_MGMD_LOG_OUTPUT_FILE_DEFAULT "/var/log/mgmd.log"

#define PTIN_MGMD_LOG_OUTPUT_DEFAULT  PTIN_MGMD_LOG_OUTOUT_STDOUT

typedef enum {
  PTIN_MGMD_LOG_OUTPUT_UNINIT=0,
  PTIN_MGMD_LOG_OUTPUT_STDERR,
  PTIN_MGMD_LOG_OUTOUT_STDOUT,
  PTIN_MGMD_LOG_OUTPUT_FILE
}ptin_mgmd_log_output_t;
/* Colors list */
typedef enum {
    PTIN_MGMD_LOG_COLOR_DEFAULT = 0,
    /* Normal */
    PTIN_MGMD_LOG_COLOR_BLACK,
    PTIN_MGMD_LOG_COLOR_RED,
    PTIN_MGMD_LOG_COLOR_GREEN,
    PTIN_MGMD_LOG_COLOR_YELLOW,
    PTIN_MGMD_LOG_COLOR_BLUE,
    PTIN_MGMD_LOG_COLOR_MAGENTA,
    PTIN_MGMD_LOG_COLOR_CYAN,
    LOG_COLOR_WHITE,
    /* Bright */
    PTIN_MGMD_LOG_BRIGHT_BLACK,
    PTIN_MGMD_LOG_BRIGHT_RED,
    PTIN_MGMD_LOG_BRIGHT_GREEN,
    PTIN_MGMD_LOG_BRIGHT_YELLOW,
    PTIN_MGMD_LOG_BRIGHT_BLUE,
    PTIN_MGMD_LOG_BRIGHT_MAGENTA,
    PTIN_MGMD_LOG_BRIGHT_CYAN,
    PTIN_MGMD_LOG_BRIGHT_WHITE,
    /* Last element */
    PTIN_MGMD_LOG_COLOR_LAST,
} ptiin_mgmd_log_color_t;

/* Log configuration entry */
struct ptin_mgmd_log_cfg_entry_s {
    int            context;
    ptin_mgmd_log_severity_t severity;
    int            color;
};
/**
 * Initialize logger
 * 
 * @param output : type of output
 */
extern void ptin_mgmd_log_init(ptin_mgmd_log_output_t output);

/**
 * Deinitialize logger
 */
extern void ptin_mgmd_log_deinit(void);

/**
 * Redirect logger to a specific file
 *  
 * @param output : type of output
 * @param output_file_path : path and file name
 */
extern void ptin_mgmd_log_redirect(ptin_mgmd_log_output_t output, char* output_file_path);

/**
 * Log help
 */
extern void ptin_mgmd_log_help(void);

/**
 * Sets severity level for a group of contexts
 * 
 * @param ctx_mask bitmap that defines which contexts are affected 
 * (bit position corresponds to the context index) 
 * @param sev severity threshold
 * 
 * @return int Zero if OK, otherwise means error
 */
extern int ptin_mgmd_log_sev_set(unsigned int ctx_mask, int sev);

/**
 * Sets a color for a group of contexts
 * 
 * @param ctx_mask bitmap that defines which contexts are affected 
 * (bit position corresponds to the context index) 
 * @param color color array index of desired color (log_color_t)
 * 
 * @return int Zero if OK, otherwise means error
 */
extern int ptin_mgmd_log_color_set(unsigned int ctx_mask, int color);
#elif (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)

void ptin_mgmd_set_logger_api_fnx(int (*log_sev_check_fnx)(unsigned int ctx, ptin_mgmd_log_severity_t sev),
                                  void (*log_print_fnx)(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file, char const *func, int line, char const *fmt, ...));
#endif //MGMD_INTERNAL_LOGGER



#if (MGMD_LOGGER==MGMD_LOGGER_INTERNAL || MGMD_LOGGER==MGMD_LOGGER_DYNAMIC)
    /**
     * Optimized (inline) function for severity check
     *
     * @param ctx Context index
     * @param sev Severity level
     *
     * @return int 0 if false, 1 if true
     */
    extern int ptin_mgmd_log_sev_check(unsigned int ctx,
                                       ptin_mgmd_log_severity_t sev);

    /**
     * Prints a log message
     * 
     * @param ctx  Context
     * @param sev  Severity
     * @param file Filename (can be NULL)
     * @param func Function name (can be NULL)
     * @param line Line# (if zero, is ignored)
     * @param fmt  Format string+ arguments (like printf)
     */
    extern void ptin_mgmd_log_print(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file,
                   char const *func, int line, char const *fmt, ...) __attribute__ ((format (printf, 6, 7)));

    extern void ptin_mgmd_log_set_string(char *outbuf, ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file,
                   char const *func, int line, char const *fmt, ...) __attribute__ ((format (printf, 7, 8)));

    #define PTIN_MGMD_LOG_TRACE( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_TRACE) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_TRACE, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_DEBUG( ctx , fmt , args... ) \
         (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_DEBUG) ? \
          ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_DEBUG, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_INFO( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_INFO) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_INFO, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_NOTICE( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_NOTICE) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_NOTICE, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_WARNING( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_WARNING) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_WARNING, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_ERR( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_ERROR) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_ERROR, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_CRITICAL( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_CRITICAL) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_CRITICAL, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
    #define PTIN_MGMD_LOG_FATAL( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_FATAL) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_FATAL, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
        
    #define PTIN_MGMD_LOG_PRINT( ctx , fmt , args... ) \
        (ptin_mgmd_log_sev_check(ctx, PTIN_MGMD_LOG_SEV_PRINT) ? \
         ptin_mgmd_log_print(ctx, PTIN_MGMD_LOG_SEV_PRINT, NULL, __FUNCTION__, __LINE__, fmt, ##args) :0)
        
#elif (MGMD_LOGGER == MGMD_LOGGER_LIBLOGGER)

    #include <nbtools/logger.h>
        
    #define PTIN_MGMD_LOG_TRACE xLOG_TRACE
    #define PTIN_MGMD_LOG_DEBUG xLOG_DEBUG
    #define PTIN_MGMD_LOG_INFO xLOG_INFO
    #define PTIN_MGMD_LOG_NOTICE xLOG_NOTICE
    #define PTIN_MGMD_LOG_WARNING xLOG_WARN
    #define PTIN_MGMD_LOG_ERR xLOG_ERROR
    #define PTIN_MGMD_LOG_CRITICAL xLOG_CRITIC
    #define PTIN_MGMD_LOG_FATAL xLOG_FATAL
        
#endif    
    
/**
 * Composes a string with a timestamp
 * 
 * @param output Pointer to the output string
 * 
 * @return char* Returns the same input pointer
 */
char* ptin_mgmd_get_time(char* output);

#endif /* _LOGGER_H */
