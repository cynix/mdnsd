/*
 * $hrs: openbgpd/openbsd-compat/openbsd-compat.h,v 1.8 2012/10/13 18:50:10 hrs Exp $
 */

#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#define	__dead

#ifndef T_NSEC
#define T_NSEC 47
#endif

#ifndef IFT_CARP
#define IFT_CARP 0xf8
#endif

#ifndef LINK_STATE_IS_UP
#define LINK_STATE_IS_UP(_s) ((_s) >= LINK_STATE_UP)
#endif

#ifndef timespeccmp
#define timespeccmp(tsp, usp, cmp)			\
	(((tsp)->tv_sec == (usp)->tv_sec) ?		\
	((tsp)->tv_nsec cmp (usp)->tv_nsec) :	\
	((tsp)->tv_sec cmp (usp)->tv_sec))
#endif

#ifndef timespecsub
#define timespecsub(tsp, usp, vsp)							\
	do {													\
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;		\
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;	\
		if ((vsp)->tv_nsec < 0) {							\
			(vsp)->tv_sec--;								\
			(vsp)->tv_nsec += 1000000000L;					\
		}													\
	} while (0)
#endif

#endif /* _OPENBSD_COMPAT_H */
