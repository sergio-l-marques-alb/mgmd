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

#include "ptin_mgmd_logger.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#if (MGMD_LOGGER==MGMD_LOGGER_INTERNAL || MGMD_LOGGER==MGMD_LOGGER_DYNAMIC)

#define MAX_OUTBUF_LEN          512 /* Output buffer max length */
#define MAX_FILE_LEN            15  /* Filename max length */
#define MAX_FUNC_LEN            35  /* Function max length */
#define MAX_LINE_LEN            5   /* Line# max length */
#define MAX_FILEFUNCLINE_LEN    30  /* Filename+function+line# max length */

/* Severity strings */
static const char *log_sev_str[PTIN_MGMD_LOG_SEV_LAST] = {
    "OFF",
    "[PRINT]   ",
    "[FATAL]   ",
    "[CRITICAL]",
    "[ERROR]   ",
    "[WARNING] ",
    "[NOTICE]  ",
    "[INFO]    ",
    "[DEBUG]   ",
    "[TRACE]   ",
};

/* Context strings */
static const char *log_ctx_str[PTIN_MGMD_LOG_CONTEXT_LAST] = {
    "LOG  ",
    "MSG  ",
    "MGMD ",
    "TIMER",
    "FIFO ",
    "START",
};

#elif (MGMD_LOGGER == MGMD_LOGGER_LIBLOGGER)

uint32_t PTIN_MGMD_LOG_CTX_PTIN_MSG=0;
uint32_t PTIN_MGMD_LOG_CTX_PTIN_IGMP=0;
uint32_t PTIN_MGMD_LOG_CTX_PTIN_TIMER=0;
uint32_t PTIN_MGMD_LOG_CTX_PTIN_FIFO=0;
uint32_t PTIN_MGMD_LOG_CTX_STARTUP=0;

#endif


#if (MGMD_LOGGER == MGMD_LOGGER_INTERNAL)

/* Severity color */
static int log_sev_color[PTIN_MGMD_LOG_SEV_LAST] = {
    PTIN_MGMD_LOG_COLOR_DEFAULT,  /* (off) */
    PTIN_MGMD_LOG_COLOR_DEFAULT,  /* Always print */
    PTIN_MGMD_LOG_BRIGHT_RED,
    PTIN_MGMD_LOG_BRIGHT_RED,
    PTIN_MGMD_LOG_BRIGHT_RED,
    PTIN_MGMD_LOG_BRIGHT_YELLOW,
    PTIN_MGMD_LOG_COLOR_YELLOW,
    PTIN_MGMD_LOG_COLOR_DEFAULT,
    PTIN_MGMD_LOG_BRIGHT_MAGENTA,
    PTIN_MGMD_LOG_COLOR_DEFAULT,
};

/* Colors escape string */
static char *log_colors[PTIN_MGMD_LOG_COLOR_LAST] = {
    "\x1B[00m",     /* Reset */
    "\x1B[00;30m",  /* Black */
    "\x1B[00;31m",  /* Red */
    "\x1B[00;32m",  /* Green */
    "\x1B[00;33m",  /* Yellow */
    "\x1B[00;34m",  /* Blue */
    "\x1B[00;35m",  /* Magenta */
    "\x1B[00;36m",  /* Cyan */
    "\x1B[00;37m",  /* White */
    "\x1B[01;30m",  /* Bright Black */
    "\x1B[01;31m",  /* Bright Red */
    "\x1B[01;32m",  /* Bright Green */
    "\x1B[01;33m",  /* Bright Yellow */
    "\x1B[01;34m",  /* Bright Blue */
    "\x1B[01;35m",  /* Bright Magenta */
    "\x1B[01;36m",  /* Bright Cyan */
    "\x1B[01;37m"   /* Bright White */
};

/* Colors escape string */
static char *log_colors_str[PTIN_MGMD_LOG_COLOR_LAST] = {
    "Reset",
    "Black",
    "Red",
    "Green",
    "Yellow",
    "Blue",
    "Magenta",
    "Cyan",
    "White",
    "Bright Black",
    "Bright Red",
    "Bright Green",
    "Bright Yellow",
    "Bright Blue",
    "Bright Magenta",
    "Bright Cyan",
    "Bright White",
};

/* Logger default configuration
 * NOTE: it is assumed that entries are sorted by context indexes! */
static struct ptin_mgmd_log_cfg_entry_s log_cfg[PTIN_MGMD_LOG_CONTEXT_LAST] = {    
    {PTIN_MGMD_LOG_CTX_LOGGER,            PTIN_MGMD_LOG_SEV_DEBUG,       PTIN_MGMD_LOG_COLOR_DEFAULT},
    {PTIN_MGMD_LOG_CTX_PTIN_MSG,          PTIN_MGMD_LOG_SEV_DEBUG,       PTIN_MGMD_LOG_COLOR_DEFAULT},
    {PTIN_MGMD_LOG_CTX_PTIN_IGMP,         PTIN_MGMD_LOG_SEV_DEBUG,       PTIN_MGMD_LOG_COLOR_DEFAULT},
    {PTIN_MGMD_LOG_CTX_PTIN_TIMER,        PTIN_MGMD_LOG_SEV_ERROR,       PTIN_MGMD_LOG_COLOR_DEFAULT},
    {PTIN_MGMD_LOG_CTX_PTIN_FIFO,         PTIN_MGMD_LOG_SEV_TRACE,       PTIN_MGMD_LOG_COLOR_DEFAULT},
    {PTIN_MGMD_LOG_CTX_STARTUP,           PTIN_MGMD_LOG_SEV_TRACE,       PTIN_MGMD_LOG_COLOR_DEFAULT},
};

typedef enum {
  WRITE_UNLOCK,
  WRITE_LOCK
}write_lock_t;

static struct s_outFile {
  ptin_mgmd_log_output_t output;
  write_lock_t lock;
  FILE *stream;
} outFile = { PTIN_MGMD_LOG_OUTPUT_UNINIT, WRITE_UNLOCK, NULL };


/**
 * Outputs (stdout) help on how to configure logger on-the-fly
 */
void ptin_mgmd_log_help(void) {
    int i;

    printf("Logger help:\n"
           "\n"
           "Configuration functions\n"
           "  log_sev_set  (<ctx_mask>, <severity>)\n"
           "  log_color_set(<ctx_mask>, <color>)\n");

    printf("\nContext mask\n");
    for ( i=0; i<PTIN_MGMD_LOG_CONTEXT_LAST; i++ )
        printf("  bit# %02d - %s\n", i, log_ctx_str[i]);

    printf("\nSeverity levels\n");
    for ( i=0; i<PTIN_MGMD_LOG_SEV_LAST; i++ )
        printf("  #%02d - %s\n", i, log_sev_str[i]);

    printf("\nColors list\n");
    for ( i=0; i<PTIN_MGMD_LOG_COLOR_LAST; i++ )
        printf("  #%02d - %s%s%s\n", i, log_colors[i], log_colors_str[i], log_colors[PTIN_MGMD_LOG_COLOR_DEFAULT]);
}

/**
 * Initialize logger
 * 
 * @param output : type of output
 */
void ptin_mgmd_log_init(ptin_mgmd_log_output_t output)
{
  if (outFile.output != PTIN_MGMD_LOG_OUTPUT_UNINIT)
  {
    fprintf(stderr,"log already initialized with output = %u\r\n", outFile.output );
    return;
  }

  if ( output == PTIN_MGMD_LOG_OUTOUT_STDOUT )
  {
    outFile.lock    = WRITE_LOCK;
    outFile.output  = PTIN_MGMD_LOG_OUTOUT_STDOUT;
    outFile.stream  = stdout;
    outFile.lock    = WRITE_UNLOCK;
  }
  else if ( output == PTIN_MGMD_LOG_OUTPUT_STDERR )
  {
    outFile.lock    = WRITE_LOCK;
    outFile.output  = PTIN_MGMD_LOG_OUTPUT_STDERR;
    outFile.stream  = stderr;
    outFile.lock    = WRITE_UNLOCK;
  }
  else if ( output == PTIN_MGMD_LOG_OUTPUT_FILE )
  {
    if ( NULL != outFile.stream)
      return;
    
    outFile.lock = WRITE_LOCK;

    outFile.stream = fopen( PTIN_MGMD_LOG_OUTPUT_FILE_DEFAULT , "a+");

    if (NULL == outFile.stream)
    {
      fprintf(stderr,"log NOT initialized error %d \"%s\"\r\n", errno, strerror(errno) );
    }
    else
    {
      outFile.output  = PTIN_MGMD_LOG_OUTPUT_FILE;
      fprintf(outFile.stream,"\n\n");
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_LOGGER, "log initialized at \"%s\"",PTIN_MGMD_LOG_OUTPUT_FILE_DEFAULT );
    }

    outFile.lock = WRITE_UNLOCK;
  }
  else
  {
    outFile.output = PTIN_MGMD_LOG_OUTPUT_UNINIT;
    fprintf(stderr,"Invalid output identifier: %d \r\n", output );
  }
}

/**
 * Deinitialize logger
 */
void ptin_mgmd_log_deinit(void)
{
  if (outFile.output == PTIN_MGMD_LOG_OUTPUT_UNINIT)
  {
    fprintf(stderr,"log already uninitialized!\r\n" );
    return;
  }

  outFile.lock = WRITE_LOCK;

  if ( outFile.output == PTIN_MGMD_LOG_OUTPUT_FILE )
  {
    fclose( outFile.stream );
  }
    
  outFile.output  = PTIN_MGMD_LOG_OUTPUT_UNINIT;
  outFile.stream  = (FILE *) NULL;
  outFile.lock = WRITE_UNLOCK;

  fprintf(stdout,"log uninitialized!\r\n" );
}

/**
 * Redirect logger to a specific file
 *  
 * @param output : type of output
 * @param output_file_path : path and file name
 */
void ptin_mgmd_log_redirect(ptin_mgmd_log_output_t output, char* output_file_path)
{
  FILE * temp_stream;
  char * file_name;
  
  /* Check if logger is initialized */
  if (outFile.output == PTIN_MGMD_LOG_OUTPUT_UNINIT)
  {
    ptin_mgmd_log_init(output);
    return;
  }

  /* If output is a file */
  if ( output == PTIN_MGMD_LOG_OUTPUT_FILE )
  {
    file_name = (output_file_path!=NULL && output_file_path[0]!='\0') ? output_file_path : PTIN_MGMD_LOG_OUTPUT_FILE_DEFAULT;

    /* Firstly, try to open the new file */
    temp_stream = fopen( file_name, "a+");

    /* If error, do nothing */
    if (NULL == outFile.stream)
    {
      fprintf(stdout,"log NOT initialized error %d \"%s\"\r\n", errno, strerror(errno) );
      return;
    }

    /* Otherwise, close the previous file */
    outFile.lock = WRITE_LOCK;
    if ( outFile.output == PTIN_MGMD_LOG_OUTPUT_FILE )
    {
      fclose(outFile.stream);
    }
    outFile.output  = PTIN_MGMD_LOG_OUTPUT_FILE;
    outFile.stream  = temp_stream;
    outFile.lock    = WRITE_UNLOCK;
    fprintf(stdout,"log redirected to \"%s\"\r\n", file_name );
    PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_LOGGER, "log redirected to \"%s\"", file_name );
  }
  else
  {
    /* Unconfig previous configuration */
    outFile.lock = WRITE_LOCK;
    if ( outFile.output == PTIN_MGMD_LOG_OUTPUT_FILE)
    {
      fclose(outFile.stream);
    }
    outFile.output  = PTIN_MGMD_LOG_OUTPUT_UNINIT;
    outFile.stream  = (FILE *) NULL;
    outFile.lock = WRITE_UNLOCK;

    /* Make new configuration */
    if ( output == PTIN_MGMD_LOG_OUTOUT_STDOUT )
    {
      outFile.lock    = WRITE_LOCK;
      outFile.output  = PTIN_MGMD_LOG_OUTOUT_STDOUT;
      outFile.stream  = stdout;
      outFile.lock    = WRITE_UNLOCK;
      fprintf(stdout,"log redirected to stdout\r\n");
    }
    else if ( output == PTIN_MGMD_LOG_OUTPUT_STDERR )
    {
      outFile.lock    = WRITE_LOCK;
      outFile.output  = PTIN_MGMD_LOG_OUTPUT_STDERR;
      outFile.stream  = stderr;
      outFile.lock    = WRITE_UNLOCK;
      fprintf(stdout,"log redirected to stderr\r\n");
    }
    else
    {
      fprintf(stderr,"Invalid output identifier: %d \r\n", output );
      PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_LOGGER, "Invalid output identifier: %d", output );
    }
  }
}

/**
 * Sets severity level for a group of contexts
 * 
 * @param ctx_mask bitmap that defines which contexts are affected 
 * (bit position corresponds to the context index) 
 * @param sev severity threshold
 * 
 * @return int Zero if OK, otherwise means error
 */
int ptin_mgmd_log_sev_set(unsigned int ctx_mask, int sev)
{
    unsigned int ctx;

    /* Validate input parameters */
    if ( (sev < 0) || (sev >= PTIN_MGMD_LOG_SEV_LAST) )
        return 1;

    for ( ctx = 0; ctx_mask != 0; ctx_mask >>= 1, ctx++ ) {
        if ( ctx >= PTIN_MGMD_LOG_CONTEXT_LAST )
            break;

        if ( ctx_mask & 1 ) {
            log_cfg[ctx].severity = sev;
            PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_LOGGER, "%s severity level set to %s", log_ctx_str[ctx], log_sev_str[sev]);
        }
    }

    return 0;
}


/**  
 * Sets a color for a group of contexts
 * 
 * @param ctx_mask bitmap that defines which contexts are affected 
 * (bit position corresponds to the context index) 
 * @param color color array index of desired color (log_color_t)
 * 
 * @return int Zero if OK, otherwise means error
 */
int ptin_mgmd_log_color_set(unsigned int ctx_mask, int color)
{
    unsigned int ctx;

    /* Validate input parameters */
    if ( (color < 0) || (color >= PTIN_MGMD_LOG_COLOR_LAST) )
        return 1;

    for ( ctx = 0; ctx_mask != 0; ctx_mask >>= 1, ctx++ ) {
        if ( ctx >= PTIN_MGMD_LOG_CONTEXT_LAST )
            break;

        if ( ctx_mask & 1 ) {
            log_cfg[ctx].color = color;
            PTIN_MGMD_LOG_INFO(PTIN_MGMD_LOG_CTX_LOGGER, "%s color set to '%s**** COLOR ****%s'", log_ctx_str[ctx], log_colors[color], log_colors[PTIN_MGMD_LOG_COLOR_DEFAULT]);
        }
    }

    return 0;
}

int ptin_mgmd_log_sev_check(unsigned int ctx, ptin_mgmd_log_severity_t sev)
{
    /* Validate input parameters */
    if ( (ctx >= PTIN_MGMD_LOG_CONTEXT_LAST) || (sev >= PTIN_MGMD_LOG_SEV_LAST) ) {
        return 0;
    }

    /* For the requested context, check if log severity allows print */
    if ( sev > log_cfg[ctx].severity )
        return 0;

    return 1;
}

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
void ptin_mgmd_log_print(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file,
               char const *func, int line, char const *fmt, ...)
{
    va_list vargs;
    char    timestamp[PTIN_MGMD_MAX_TIMESTAMP_LEN];
    char    filefunc[MAX_OUTBUF_LEN];
    char    outbuf[MAX_OUTBUF_LEN];
    int     maxlen;
    int     offset;
    int     nchars;
    char   *color;
    FILE   *stream = stdout;

    /* IMPORTANT: It is mandatory to run log_sev_check() before this function
       because it validates the 'ctx' and 'sev' parameters and decide if the
       print must occur or not */

    /* Get color: give priority to context color (only if != default)*/
    if ( log_cfg[ctx].color == PTIN_MGMD_LOG_COLOR_DEFAULT )
        color = log_colors[log_sev_color[sev]];
    else
        color = log_colors[log_cfg[ctx].color];

    /* Determine maximum length for file+func+line and compose string */
    nchars = 0;
    maxlen = 0;
    filefunc[0] = '\0';
    if ( file != NULL ) {
        maxlen += MAX_FILE_LEN;
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "%s ", file);
    }
    if ( func != NULL ) {
        maxlen += MAX_FUNC_LEN;
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "%s", func);
    }
    if ( line > 0 ) {
        maxlen += MAX_LINE_LEN;
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "(%d)", line);
    }
    else
    {
        /* Add the () to the function name (without line nr) */
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "()");
    }

    /* Determine offset to truncate string size */
    offset = 0;
    if ( nchars > maxlen ) {
        offset = nchars - maxlen;
        filefunc[offset+0] = '.';
        filefunc[offset+1] = '.';
        filefunc[offset+2] = '.';
    }

    /* Print to a string the std pattern */
    nchars = snprintf(outbuf, MAX_OUTBUF_LEN, "%s %s %-*s %s ", ptin_mgmd_get_time(timestamp),
                      log_ctx_str[ctx], maxlen, filefunc+offset, log_sev_str[sev]);

    /* Continue printing the log itself */
    va_start(vargs, fmt);
    vsnprintf (outbuf + nchars, MAX_OUTBUF_LEN-nchars, fmt, vargs);
    va_end(vargs);

    /* Can we print? */
    if (outFile.lock==WRITE_LOCK)  return;

    /* Print to where? */
    if ( outFile.output!=PTIN_MGMD_LOG_OUTPUT_UNINIT && outFile.stream!=NULL )
    {
      stream = outFile.stream;
    }

    /* Output it... */
    fprintf( stream, "%s%.*s%s\r\n", color, MAX_OUTBUF_LEN, outbuf, log_colors[PTIN_MGMD_LOG_COLOR_DEFAULT]);

    /* fflush for files */
    if (stream!=stdout && stream!=stderr)
    {
      fflush(stream);
    }

    return;
}

#elif (MGMD_LOGGER == MGMD_LOGGER_DYNAMIC)

static int (*mgmd_log_sev_check)(unsigned int ctx, ptin_mgmd_log_severity_t sev)=NULL;
static void (*mgmd_log_print)(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file, char const *func, int line, char const *fmt, ...)=NULL;

void ptin_mgmd_set_logger_api_fnx(int (*log_sev_check_fnx)(unsigned int ctx, ptin_mgmd_log_severity_t sev),
                                    void (*log_print_fnx)(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file, char const *func, int line, char const *fmt, ...))
{
    mgmd_log_sev_check=log_sev_check_fnx;
    mgmd_log_print=log_print_fnx;
    return;
}

int ptin_mgmd_log_sev_check(unsigned int ctx, ptin_mgmd_log_severity_t sev)
{
    if (mgmd_log_sev_check) 
    {
        return (mgmd_log_sev_check(ctx,sev));
    }
    else
    {
        return 1;
    }
}

void ptin_mgmd_log_print(ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file,
               char const *func, int line, char const *fmt, ...)
{

    /* IMPORTANT: It is mandatory to run log_sev_check() before this function
       because it validates the 'ctx' and 'sev' parameters and decide if the
       print must occur or not */

    if (mgmd_log_print)
    {
        char str[MAX_OUTBUF_LEN];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(str, MAX_OUTBUF_LEN, fmt, ap);

        mgmd_log_print(ctx,sev,file,func,line,"%s",str);
        va_end(ap);
        return;
    }
    else
    {
        return;
    }
}

void ptin_mgmd_log_set_string(char *outbuf, ptin_mgmd_log_context_t ctx, ptin_mgmd_log_severity_t sev, char const *file,
               char const *func, int line, char const *fmt, ...)
{
    va_list vargs;
    char    timestamp[PTIN_MGMD_MAX_TIMESTAMP_LEN];
    char    filefunc[MAX_OUTBUF_LEN];
    int     maxlen;
    int     offset;
    int     nchars;

    /* Determine maximum length for file+func+line and compose string */
    nchars = 0;
    maxlen = 0;
    filefunc[0] = '\0';
    if ( file != NULL ) {
        maxlen += MAX_FILE_LEN;
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "%s ", file);
    }
    if ( func != NULL ) {
        maxlen += MAX_FUNC_LEN;
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "%s", func);
    }
    if ( line > 0 ) {
        maxlen += MAX_LINE_LEN;
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "(%d)", line);
    }
    else
    {
        /* Add the () to the function name (without line nr) */
        nchars += snprintf(filefunc+nchars, MAX_OUTBUF_LEN-nchars, "()");
    }

    /* Determine offset to truncate string size */
    offset = 0;
    if ( nchars > maxlen ) {
        offset = nchars - maxlen;
        filefunc[offset+0] = '.';
        filefunc[offset+1] = '.';
        filefunc[offset+2] = '.';
    }

    /* Print to a string the std pattern */
    nchars = snprintf(outbuf, MAX_OUTBUF_LEN, "%s %s %-*s %s ", ptin_mgmd_get_time(timestamp),
                      log_ctx_str[ctx], maxlen, filefunc+offset, log_sev_str[sev]);

    /* Continue printing the log itself */
    va_start(vargs, fmt);
    vsnprintf (outbuf + nchars, MAX_OUTBUF_LEN-nchars, fmt, vargs);
    va_end(vargs);

    return;
}

#elif (MGMD_LOGGER == MGMD_LOGGER_LIBLOGGER)



#include <stdlib.h>

void ptin_mgmd_liblogger_init(uint32_t file_id) {
    log_ctx_entry_t log_context = { "", "", LOG_SEV_ERROR, LOG_COLOR_DEFAULT, LOG_MODE_FILE, file_id };
    log_ret_t ret;

    snprintf(log_context.description, LOG_CTX_DESC_MAXLEN, "MGMD MSG");
    snprintf(log_context.tag, LOG_CTX_TAG_MAXLEN, "MSG");
    ret = logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_MSG);
    if (ret != 0) {
        fprintf(stderr, "Error: logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_MSG); ret=%d\n", ret);
        return;
    }

    snprintf(log_context.description, LOG_CTX_DESC_MAXLEN, "MGMD IGMP");
    snprintf(log_context.tag, LOG_CTX_TAG_MAXLEN, "IGMP");
    ret = logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_IGMP);
    if (ret != 0) {
        fprintf(stderr, "Error: logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_IGMP); ret=%d\n", ret);
        return;
    }

    snprintf(log_context.description, LOG_CTX_DESC_MAXLEN, "MGMD TIMER");
    snprintf(log_context.tag, LOG_CTX_TAG_MAXLEN, "TIMER");
    ret = logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_TIMER);
    if (ret != 0) {
        fprintf(stderr, "Error: logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_TIMER); ret=%d\n", ret);
        return;
    }

    snprintf(log_context.description, LOG_CTX_DESC_MAXLEN, "MGMD FIFO");
    snprintf(log_context.tag, LOG_CTX_TAG_MAXLEN, "FIFO");
    ret = logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_FIFO);
    if (ret != 0) {
        fprintf(stderr, "Error: logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_PTIN_FIFO); ret=%d\n", ret);
        return;
    }

    snprintf(log_context.description, LOG_CTX_DESC_MAXLEN, "MGMD STARTUP");
    snprintf(log_context.tag, LOG_CTX_TAG_MAXLEN, "STRUP");
    ret = logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_STARTUP);
    if (ret != 0) {
        fprintf(stderr, "Error: logger_ctx_dyn_add(&log_context, &PTIN_MGMD_LOG_CTX_STARTUP); ret=%d\n", ret);
        return;
    }
}

#endif
/**
 * Composes a string with a timestamp
 * 
 * @param output Pointer to the output string
 * 
 * @return char* Returns the same input pointer
 */
char* ptin_mgmd_get_time(char* output)
{
    struct timeval   tv;
    struct tm        date;
    time_t           timeabs;

    if (output) {
        time (&timeabs);
        localtime_r (&timeabs, &date);
        gettimeofday (&tv, NULL);
        sprintf (output, "%04d%02d%02d-%02dh%02dm%02d.%03d",
                 date.tm_year+1900, date.tm_mon+1, date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec, (int)(tv.tv_usec/1000));
    }

    return output;
}

