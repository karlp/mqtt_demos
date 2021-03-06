/* 
 * Ugly, low performance, configurable level, logging "framework"
 * Karl Palsson, ReMake Electric ehf, 2011
 */

#ifndef UGLYLOGGING_H
#define	UGLYLOGGING_H

#ifdef	__cplusplus
extern "C" {
#endif
    
    
#define UDEBUG 90
#define UINFO  50
#define UWARN  30
#define UERROR 20
#define UFATAL 10

    int ugly_init(int level);
    int ugly_log(int level, const char *tag, const char *format, ...);


#ifdef	__cplusplus
}
#endif

#endif	/* UGLYLOGGING_H */

