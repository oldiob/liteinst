
#ifndef _LITEINST_HPP_
#define _LITEINST_HPP_

#include <cstdint>
#include <vector>
#include <atomic>
#include <string>
#include <list>
#include <memory>
#include <cstdio>
#include <unordered_map>

/*
 * Copyright (c) 2003, 2007-8 Matteo Frigo
 * Copyright (c) 2003, 2007-8 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */


/* machine-dependent cycle counters code. Needs to be inlined. */

/***************************************************************************/
/* To use the cycle counters in your code, simply #include "cycle.h" (this
   file), and then use the functions/macros:

                 ticks getticks(void);

   ticks is an opaque typedef defined below, representing the current time.
   You extract the elapsed time between two calls to gettick() via:

                 double elapsed(ticks t1, ticks t0);

   which returns a double-precision variable in arbitrary units.  You
   are not expected to convert this into human units like seconds; it
   is intended only for *comparisons* of time intervals.

   (In order to use some of the OS-dependent timer routines like
   Solaris' gethrtime, you need to paste the autoconf snippet below
   into your configure.ac file and #include "config.h" before cycle.h,
   or define the relevant macros manually if you are not using autoconf.)
*/

/***************************************************************************/
/* This file uses macros like HAVE_GETHRTIME that are assumed to be
   defined according to whether the corresponding function/type/header
   is available on your system.  The necessary macros are most
   conveniently defined if you are using GNU autoconf, via the tests:

   dnl ---------------------------------------------------------------------

   AC_C_INLINE
   AC_HEADER_TIME
   AC_CHECK_HEADERS([sys/time.h c_asm.h intrinsics.h mach/mach_time.h])

   AC_CHECK_TYPE([hrtime_t],[AC_DEFINE(HAVE_HRTIME_T, 1, [Define to 1 if hrtime_t is defined in <sys/time.h>])],,[#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif])

   AC_CHECK_FUNCS([gethrtime read_real_time time_base_to_time clock_gettime mach_absolute_time])

   dnl Cray UNICOS _rtc() (real-time clock) intrinsic
   AC_MSG_CHECKING([for _rtc intrinsic])
   rtc_ok=yes
   AC_TRY_LINK([#ifdef HAVE_INTRINSICS_H
#include <intrinsics.h>
#endif], [_rtc()], [AC_DEFINE(HAVE__RTC,1,[Define if you have the UNICOS _rtc() intrinsic.])], [rtc_ok=no])
   AC_MSG_RESULT($rtc_ok)

   dnl ---------------------------------------------------------------------
*/

/***************************************************************************/

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#define INLINE_ELAPSED(INL) static INL double elapsed(ticks t1, ticks t0) \
{									  \
     return (double)t1 - (double)t0;					  \
}

/*----------------------------------------------------------------*/
/* Solaris */
#if defined(HAVE_GETHRTIME) && defined(HAVE_HRTIME_T) && !defined(HAVE_TICK_COUNTER)
typedef hrtime_t ticks;

#define getticks gethrtime

INLINE_ELAPSED(inline)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/* AIX v. 4+ routines to read the real-time clock or time-base register */
#if defined(HAVE_READ_REAL_TIME) && defined(HAVE_TIME_BASE_TO_TIME) && !defined(HAVE_TICK_COUNTER)
typedef timebasestruct_t ticks;

static __inline ticks getticks(void)
{
     ticks t;
     read_real_time(&t, TIMEBASE_SZ);
     return t;
}

static __inline double elapsed(ticks t1, ticks t0) /* time in nanoseconds */
{
     time_base_to_time(&t1, TIMEBASE_SZ);
     time_base_to_time(&t0, TIMEBASE_SZ);
     return (((double)t1.tb_high - (double)t0.tb_high) * 1.0e9 +
	     ((double)t1.tb_low - (double)t0.tb_low));
}

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/*
 * PowerPC ``cycle'' counter using the time base register.
 */
#if ((((defined(__GNUC__) && (defined(__powerpc__) || defined(__ppc__))) || (defined(__MWERKS__) && defined(macintosh)))) || (defined(__IBM_GCC_ASM) && (defined(__powerpc__) || defined(__ppc__))))  && !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks;

static __inline__ ticks getticks(void)
{
     unsigned int tbl, tbu0, tbu1;

     do {
	  __asm__ __volatile__ ("mftbu %0" : "=r"(tbu0));
	  __asm__ __volatile__ ("mftb %0" : "=r"(tbl));
	  __asm__ __volatile__ ("mftbu %0" : "=r"(tbu1));
     } while (tbu0 != tbu1);

     return (((unsigned long long)tbu0) << 32) | tbl;
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif

/* MacOS/Mach (Darwin) time-base register interface (unlike UpTime,
   from Carbon, requires no additional libraries to be linked). */
#if defined(HAVE_MACH_ABSOLUTE_TIME) && defined(HAVE_MACH_MACH_TIME_H) && !defined(HAVE_TICK_COUNTER)
#include <mach/mach_time.h>
typedef uint64_t ticks;
#define getticks mach_absolute_time
INLINE_ELAPSED(__inline__)
#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/*
 * Pentium cycle counter
 */
#if (defined(__GNUC__) || defined(__ICC)) && defined(__i386__)  && !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks;

static __inline__ ticks getticks(void)
{
     ticks ret;

     __asm__ __volatile__("rdtsc": "=A" (ret));
     /* no input, nothing else clobbered */
     return ret;
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#define TIME_MIN 5000.0   /* unreliable pentium IV cycle counter */
#endif

/* Visual C++ -- thanks to Morten Nissov for his help with this */
#if _MSC_VER >= 1200 && _M_IX86 >= 500 && !defined(HAVE_TICK_COUNTER)
#include <windows.h>
typedef LARGE_INTEGER ticks;
#define RDTSC __asm __emit 0fh __asm __emit 031h /* hack for VC++ 5.0 */

static __inline ticks getticks(void)
{
     ticks retval;

     __asm {
	  RDTSC
	  mov retval.HighPart, edx
	  mov retval.LowPart, eax
     }
     return retval;
}

static __inline double elapsed(ticks t1, ticks t0)
{
     return (double)t1.QuadPart - (double)t0.QuadPart;
}

#define HAVE_TICK_COUNTER
#define TIME_MIN 5000.0   /* unreliable pentium IV cycle counter */
#endif

/*----------------------------------------------------------------*/
/*
 * X86-64 cycle counter
 */
#if (defined(__GNUC__) || defined(__ICC) || defined(__SUNPRO_C)) && defined(__x86_64__)  && !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks;

ticks getticks(void) __attribute__((no_instrument_function));
__inline__ ticks getticks(void)
{
     unsigned a, d;
     asm volatile("rdtsc" : "=a" (a), "=d" (d));
     return ((ticks)a) | (((ticks)d) << 32);
}

// __attribute__((no_instrument_function))
static __inline__ ticks getstart(void) {
  unsigned cycles_high = 0, cycles_low = 0;
    asm volatile ("CPUID\n\t"
                  "RDTSC\n\t"
                  "mov %%edx, %0\n\t"
                  "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
                    "%rax", "%rbx", "%rcx", "%rdx");
  return ((ticks)cycles_high << 32) | (((ticks)cycles_low));
}

// __attribute__((no_instrument_function))
static __inline__ ticks getend(void) {
  unsigned cycles_high = 0, cycles_low = 0;
  asm volatile("RDTSCP\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               "CPUID\n\t": "=r" (cycles_high), "=r" (cycles_low)::
                 "%rax", "%rbx", "%rcx", "%rdx");
  return ((ticks)cycles_high << 32) | (((ticks)cycles_low));
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif

/* PGI compiler, courtesy Cristiano Calonaci, Andrea Tarsi, & Roberto Gori.
   NOTE: this code will fail to link unless you use the -Masmkeyword compiler
   option (grrr). */
#if defined(__PGI) && defined(__x86_64__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks;
static ticks getticks(void)
{
    asm(" rdtsc; shl    $0x20,%rdx; mov    %eax,%eax; or     %rdx,%rax;    ");
}
INLINE_ELAPSED(__inline__)
#define HAVE_TICK_COUNTER
#endif

/* Visual C++, courtesy of Dirk Michaelis */
#if _MSC_VER >= 1400 && (defined(_M_AMD64) || defined(_M_X64)) && !defined(HAVE_TICK_COUNTER)

#include <intrin.h>
#pragma intrinsic(__rdtsc)
typedef unsigned __int64 ticks;
#define getticks __rdtsc
INLINE_ELAPSED(__inline)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/*
 * IA64 cycle counter
 */

/* intel's icc/ecc compiler */
#if (defined(__EDG_VERSION) || defined(__ECC)) && defined(__ia64__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long ticks;
#include <ia64intrin.h>

static __inline__ ticks getticks(void)
{
     return __getReg(_IA64_REG_AR_ITC);
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif

/* gcc */
#if defined(__GNUC__) && defined(__ia64__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long ticks;

static __inline__ ticks getticks(void)
{
     ticks ret;

     __asm__ __volatile__ ("mov %0=ar.itc" : "=r"(ret));
     return ret;
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif

/* HP/UX IA64 compiler, courtesy Teresa L. Johnson: */
#if defined(__hpux) && defined(__ia64) && !defined(HAVE_TICK_COUNTER)
#include <machine/sys/inline.h>
typedef unsigned long ticks;

static inline ticks getticks(void)
{
     ticks ret;

     ret = _Asm_mov_from_ar (_AREG_ITC);
     return ret;
}

INLINE_ELAPSED(inline)

#define HAVE_TICK_COUNTER
#endif

/* Microsoft Visual C++ */
#if defined(_MSC_VER) && defined(_M_IA64) && !defined(HAVE_TICK_COUNTER)
typedef unsigned __int64 ticks;

#  ifdef __cplusplus
extern "C"
#  endif
ticks __getReg(int whichReg);
#pragma intrinsic(__getReg)

static __inline ticks getticks(void)
{
     volatile ticks temp;
     temp = __getReg(3116);
     return temp;
}

INLINE_ELAPSED(inline)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/*
 * PA-RISC cycle counter
 */
#if defined(__hppa__) || defined(__hppa) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long ticks;

#  ifdef __GNUC__
static __inline__ ticks getticks(void)
{
     ticks ret;

     __asm__ __volatile__("mfctl 16, %0": "=r" (ret));
     /* no input, nothing else clobbered */
     return ret;
}
#  else
#  include <machine/inline.h>
static inline unsigned long getticks(void)
{
     register ticks ret;
     _MFCTL(16, ret);
     return ret;
}
#  endif

INLINE_ELAPSED(inline)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/* S390, courtesy of James Treacy */
#if defined(__GNUC__) && defined(__s390__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks;

static __inline__ ticks getticks(void)
{
     ticks cycles;
     __asm__("stck 0(%0)" : : "a" (&(cycles)) : "memory", "cc");
     return cycles;
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif
/*----------------------------------------------------------------*/
#if defined(__GNUC__) && defined(__alpha__) && !defined(HAVE_TICK_COUNTER)
/*
 * The 32-bit cycle counter on alpha overflows pretty quickly,
 * unfortunately.  A 1GHz machine overflows in 4 seconds.
 */
typedef unsigned int ticks;

static __inline__ ticks getticks(void)
{
     unsigned long cc;
     __asm__ __volatile__ ("rpcc %0" : "=r"(cc));
     return (cc & 0xFFFFFFFF);
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
#if defined(__GNUC__) && defined(__sparc_v9__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long ticks;

static __inline__ ticks getticks(void)
{
     ticks ret;
     __asm__ __volatile__("rd %%tick, %0" : "=r" (ret));
     return ret;
}

INLINE_ELAPSED(__inline__)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
#if (defined(__DECC) || defined(__DECCXX)) && defined(__alpha) && defined(HAVE_C_ASM_H) && !defined(HAVE_TICK_COUNTER)
#  include <c_asm.h>
typedef unsigned int ticks;

static __inline ticks getticks(void)
{
     unsigned long cc;
     cc = asm("rpcc %v0");
     return (cc & 0xFFFFFFFF);
}

INLINE_ELAPSED(__inline)

#define HAVE_TICK_COUNTER
#endif
/*----------------------------------------------------------------*/
/* SGI/Irix */
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_SGI_CYCLE) && !defined(HAVE_TICK_COUNTER)
typedef struct timespec ticks;

static inline ticks getticks(void)
{
     struct timespec t;
     clock_gettime(CLOCK_SGI_CYCLE, &t);
     return t;
}

static inline double elapsed(ticks t1, ticks t0)
{
     return ((double)t1.tv_sec - (double)t0.tv_sec) * 1.0E9 +
	  ((double)t1.tv_nsec - (double)t0.tv_nsec);
}
#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/* Cray UNICOS _rtc() intrinsic function */
#if defined(HAVE__RTC) && !defined(HAVE_TICK_COUNTER)
#ifdef HAVE_INTRINSICS_H
#  include <intrinsics.h>
#endif

typedef long long ticks;

#define getticks _rtc

INLINE_ELAPSED(inline)

#define HAVE_TICK_COUNTER
#endif

/*----------------------------------------------------------------*/
/* MIPS ZBus */
#if HAVE_MIPS_ZBUS_TIMER
#if defined(__mips__) && !defined(HAVE_TICK_COUNTER)
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

typedef uint64_t ticks;

static inline ticks getticks(void)
{
  static uint64_t* addr = 0;

  if (addr == 0)
  {
    uint32_t rq_addr = 0x10030000;
    int fd;
    int pgsize;

    pgsize = getpagesize();
    fd = open ("/dev/mem", O_RDONLY | O_SYNC, 0);
    if (fd < 0) {
      perror("open");
      return NULL;
    }
    addr = mmap(0, pgsize, PROT_READ, MAP_SHARED, fd, rq_addr);
    close(fd);
    if (addr == (uint64_t *)-1) {
      perror("mmap");
      return NULL;
    }
  }

  return *addr;
}

INLINE_ELAPSED(inline)

#define HAVE_TICK_COUNTER
#endif
#endif /* HAVE_MIPS_ZBUS_TIMER */

#ifndef _CONCURRENCY_HPP_
#define _CONCURRENCY_HPP_

#include <atomic>
#include <cassert>
#include <thread>
#include <functional>
#include <map>
#include <utility>
#include <stdexcept>

namespace utils {
namespace concurrency {

class SpinLock {
  public:
    SpinLock() : lock_owner(lock_is_free), is_latched(false), lock_count(0) {
    }

    inline bool tryLock() {
      if (lock_owner != std::this_thread::get_id()) {
        bool non_latched_value = false;
        bool locked = is_latched.compare_exchange_strong(non_latched_value,
            true, std::memory_order_acquire, std::memory_order_relaxed);
        if (locked) {
          lock_count++;
        }

        lock_owner = std::this_thread::get_id();
        return locked;
      }

      lock_count++;
      return true;
    }

    inline void lock() {
      if (lock_owner != std::this_thread::get_id()) {

        bool non_latched_value = false;
        // Test until we see a potential unlocked state
        while(is_latched.load(std::memory_order_relaxed) != non_latched_value) {
          __asm__("pause"); // Gentle spinning.
        }

        // Now try test and set
        while(!is_latched.compare_exchange_weak(non_latched_value,
              true, std::memory_order_acquire,
              std::memory_order_relaxed)) {
          non_latched_value = false;
          // Again test until we a potential unlocked state
          while(is_latched.load(std::memory_order_relaxed) != non_latched_value) {
            __asm__("pause"); // Gentle spinning.
          }
        }

        lock_owner = std::this_thread::get_id();
        // printf("[Lock %p] Assigned owner to : %ld\n", this, lock_owner);
      }

      lock_count++;
    }

    inline void unlock() {
      assert(isSet());

      // printf("[Unlock %p] Lock owner : %ld\n", this, lock_owner);
      // printf("[Unlock %p] Current thread : %ld\n", this, std::this_thread::get_id());
      // assert(lock_owner == std::this_thread::get_id());
      assert(lock_count != 0);

      --lock_count;

      if (lock_count == 0) {
        // There can be a window of is_latched locked but without any owner due
        // to non atomicity of this update. But that doesn't negatively affect
        // the correctness of the lock.
        lock_owner = lock_is_free;

        is_latched.store(false, std::memory_order_release);
      }

      // printf("[Unlock %p] Unlock done with lock owner : %ld\n\n", this, lock_owner);
    }

    inline bool isOwner() {
      return lock_owner == std::this_thread::get_id();
    }

    inline bool isSet() {
      return is_latched.load(std::memory_order_relaxed);
    }

  private:
    std::thread::id lock_is_free;
    std::thread::id lock_owner;
    std::atomic<bool> is_latched;
    int lock_count;
};

/** \brief A non blocking readers writers lock.
 *
 *  1. The lock is recursive.
 *  2. The lock implmentation gives weak priority to writers.
 */
class ReadWriteLock {
  public:
    inline void readLock() {
      if (tx_lock.isSet() && tx_lock.isOwner()) {
        // Short circuit. We already have the exclusive lock.
        return;
      }

      if (w_lock.isSet() && w_lock.isOwner()) {
        return;
      }

      r_lock.lock();
      while (num_writers != 0);

      if (num_readers == 0) {
        w_lock.lock();
      }

      num_readers++;
      assert(num_writers == 0);

      r_lock.unlock();
    }

    inline void readUnlock() {
      if (tx_lock.isSet() && tx_lock.isOwner()) {
        // Short circuit. We already have the exclusive lock.
        return;
      }

      r_lock.lock();
      num_readers--;
      if (num_readers == 0) {
        assert(num_writers == 0);
        w_lock.unlock();
      }
      r_lock.unlock();
    }

    inline void writeLock() {
      if (tx_lock.isSet() && tx_lock.isOwner()) {
        // Short circuit. We already have the exclusive lock.
        return;
      }

      w_lock.lock();
      assert(w_lock.isOwner());
      assert(w_lock.isSet());
      if (num_writers >= 1) {
        // printf("Is already owned : %d Is already set : %d \n", is_already_owned, isSet);
        abort();
      }
      num_writers++;
      assert(num_writers == 1 && w_lock.isSet());
    }

    inline void writeUnlock() {
      if (tx_lock.isSet() && tx_lock.isOwner()) {
        // Short circuit. We already have the exclusive lock.
        return;
      }

      num_writers--;
      assert(num_writers == 0);
      w_lock.unlock();
    }

    inline void clear() {
      writeLock();
      writeUnlock();
    }

    inline bool isSet() {
      return tx_lock.isSet() || r_lock.isSet() || w_lock.isSet();
    }

    inline bool isOwner() {
      return tx_lock.isOwner() || r_lock.isOwner() || w_lock.isOwner();
    }

    inline void exclusiveLock() {
      w_lock.lock();
      tx_lock.lock();
    }

    inline void exclusiveUnlock() {
      tx_lock.unlock();
      w_lock.unlock();
    }

  private:
    SpinLock r_lock;
    SpinLock w_lock;
    SpinLock tx_lock;
    int32_t num_readers = 0;
    int32_t num_writers = 0;
};

/** \brief A concurrent ordered map.
 */
template <class Key, class T, class Compare = std::less<Key>>
class ConcurrentMap {
  public:
    typedef typename std::map<Key, T, Compare>::iterator Iterator;
    typedef typename std::pair<Iterator, bool> InsertResult;

    ConcurrentMap() {
    }

    void acquireUpdateLock() {
      rw_lock.exclusiveLock();
    }

    void releaseUpdateLock() {
      rw_lock.exclusiveUnlock();
    }

    // TODO: Make a proper wrapper. Currently this exposes
    // underlying map iterator.
    void upsert(Key k, T value) {
      rw_lock.writeLock();
      auto it = map.find(k);
      if (it != map.end()) {
        if (it.first != k) {
          map.erase(it.first);
        }
      }

      map[k] = value;
      rw_lock.writeUnlock();
    }

    template<class... Args>
    InsertResult emplace(Args&&... args) {
      rw_lock.writeLock();
      InsertResult res = map.emplace(std::forward<Args>(args)...);
      rw_lock.writeUnlock();
      return res;
    }

    Iterator find(Key k) {
      rw_lock.readLock();
      auto result = map.find(k);
      rw_lock.readUnlock();
      return result;
    }

    InsertResult insert(Key k, T value) {
      rw_lock.writeLock();
      auto result = map.insert(std::pair<Key,T>(k, value));
      rw_lock.writeUnlock();
      return result;
    }

    void erase(Key k) {
      rw_lock.writeLock();
      map.erase(k);
      rw_lock.writeUnlock();
    }

    void clear() {
      rw_lock.writeLock();
      map.clear();
      rw_lock.writeUnlock();
    }

    Iterator begin() {
      return map.begin();
    }

    Iterator end() {
      return map.end();
    }

    int size() {
      return map.size();
    }

    Iterator lower_bound(const Key& k) {
      rw_lock.readLock();
      Iterator it = map.lower_bound(k);
      rw_lock.readUnlock();
      return it;
    }

    Iterator upper_bound(const Key& k) {
      rw_lock.readLock();
      Iterator it = map.upper_bound(k);
      rw_lock.readUnlock();
      return it;
    }

  private:
    ReadWriteLock rw_lock;
    std::map<Key, T, Compare> map;

};

} /* End concurrency */
} /* End utils */

#endif /* _CONCURRENCY_HPP_ */


#ifndef _DEFS_HPP_
#define _DEFS_HPP_

#include <cstdint>
#include <ostream>
#include <cstdint>
#include <string>

namespace utils {

/// A byte addressible data type
typedef uint8_t* Address;

/// An implementable marker interface for printing data members of a class
class Show {

  public:
    /** \brief Prints formatted information about data members of the class
     *         to given file stream
     *
     * NOTE: Doing C I/O instead of C++ stream I/O here C++ streams not
     * working pre main.
     */
    virtual void show(FILE* fp, int nspaces) = 0;

    std::string getPadding(int nspaces) {
      std::string pad = "";
      while (nspaces-- > 0) {
        pad += " ";
      }

      return pad;
    }
};

/** \brief An implementable marker interface for denoting an optional
 *         reference.
 *
 *  Achieves something similar to boost::optional via inheritance. Not taking
 *  a boost dependency just for this.
 */
class Optional {
  public:
    bool is_valid = true; ///< Is this reference valid?
};

} /* End utils */

#endif /* _DEFS_HPP_ */

namespace liteinst {

/// This is used to specify which provider needs to be selected
/// at initialization time.
enum class ProviderType { ZCA, FINSTRUMENT, DTRACE, DYNINST, LITEPROBES };

/// In the future we will aim to support an open universe of probe
/// providers.  In the short term, we explicitly enumerate the probe
/// providers.  Any use of this field violates the abstraction of the
/// ProbeProvider by depending on implementation details.
enum class ProbeType { ZCA, FINSTRUMENT, DTRACE, DYNINST, RPROBES }; 

/// Opaque identifier for a ProbeGroup
typedef uint64_t ProbeGroupId;

/// Opaque identifier for a Probe
typedef uint64_t ProbeId;

/// Opaque identifier for an Instrumentor instance
typedef uint16_t InstrumentationId;

/// Opaque identifier for a probe registration
typedef uint64_t RegistrationId;

/// The probe groupings available. 
enum class ProbeGroupType : uint8_t { 
  FUNCTION,
  LOOP,
  BASIC_BLOCK,
  OFFSET,
  LINE_NUM, 
  INS_TYPE,
  ADDRESS
};

/// The placement of probes within a given probe grouping.
enum class ProbePlacement : uint8_t { 
  ENTRY,
  EXIT,
  NONE,
  BOUNDARY /* ENTRY + EXIT */
};

struct ProbeContext {
  ProbeId p_id;
  ProbeGroupId pg_id;
  InstrumentationId i_id;
  ProbePlacement placement;
  utils::Address u_regs;
};

struct ProbeInfo {
  utils::Address address;
  ProbeContext ctx;
};

class ProbeAxis {
  public:
    ProbeAxis(std::string spec, ProbePlacement placement) : spec(spec),
      placement(placement) {

    }

    virtual void setSpec(std::string ss) {
      spec = ss;
    }

    virtual void setPlacement(ProbePlacement p) {
      placement = p;
    }

    virtual std::string getSpec() {
      return spec;
    }

    ProbePlacement getPlacement() {
      return placement;
    }

  protected:
    std::string spec;
    ProbePlacement placement;
};

class Module : public ProbeAxis {
  public:
    Module(std::string spec = "", ProbePlacement p = ProbePlacement::NONE) : 
      ProbeAxis(spec, p) {
    }
};

class Function : public ProbeAxis {
  public:
    Function(std::string spec = "", ProbePlacement p = ProbePlacement::NONE) : 
      ProbeAxis(spec, p) {
    }
};

class Loop : public ProbeAxis {
  public:
    Loop(std::string spec = "", ProbePlacement p = ProbePlacement::NONE) : 
      ProbeAxis(spec, p) {
    }
};

class BasicBlock : public ProbeAxis {
  public:
    BasicBlock(std::string spec = "", ProbePlacement p = ProbePlacement::NONE) :
      ProbeAxis(spec, p) {
    }
};

class Offset : public ProbeAxis {
  public:
    Offset(std::string spec = "", ProbePlacement p = ProbePlacement::NONE) :
      ProbeAxis(spec, p) {
    }
};

class InstructionType : public ProbeAxis {
  public:
    InstructionType(std::string spec = "", ProbePlacement p = ProbePlacement::NONE) :
      ProbeAxis(spec, p) {
    } 
};

class VMAddress : public ProbeAxis {
  public:
    VMAddress(std::string spec = "", utils::Address address = nullptr,
        ProbePlacement p = ProbePlacement::NONE) :
      ProbeAxis(spec, p) {
        if (address != nullptr) {
          addr = address;
        } else if (spec.compare("")) {
          addr = reinterpret_cast<utils::Address>(std::stol(spec, nullptr, 16));
        } else {
          addr = nullptr;
        }
    } 

    utils::Address getVMAddress() {
      return addr;
    }

  private:
    utils::Address addr;
};

/*
class ProbeGroup {
  public:
    ProbeGroupId id;
    std::string name;
    Module module;
    Function function;
    Loop loop;
    BasicBlock basic_block;
    Offset offset;
    ProbePlacement placement;
};
*/

/// Opaque identifier for uniquely identifying a probe group
typedef uint64_t ProbeGroupId;

/// The type of the instrumentation function.
typedef void (*InstrumentationFunction) ();


class InstrumentationProvider {
  public:
    InstrumentationId id;

    InstrumentationProvider(std::string name, InstrumentationFunction entry, 
        InstrumentationFunction exit) : name(name), entry(entry), exit(exit) {
    }

    InstrumentationProvider(std::string name, uint8_t* probe, int probe_size) : name(name), 
      probe(probe), probe_size(probe_size) {
    }

    InstrumentationFunction getEntryInstrumentation() const {
      return entry;
    }

    InstrumentationFunction getExitInstrumentation() const {
      return exit;
    }

    uint8_t* getInstrumentation() const {
      return probe;
    }

    int getProbeSize() const {
      return probe_size;
    }

    std::string getName() {
      return name;
    }

  private:
    std::string name;
    InstrumentationFunction entry = NULL;
    InstrumentationFunction exit = NULL;
    uint8_t* probe = nullptr;
    int probe_size = 0;
};

class Coordinates {
  public:

    // Setters
    Coordinates& setModule(Module m) {
      module = m;
      return *this; 
    }

    Coordinates& setFunction(Function f) {
      function = f;
      return *this; 
    }

    Coordinates& setLoop(Loop l) {
      loop = l;
      return *this; 
    }

    Coordinates& setBasicBlock(BasicBlock bb) {
      basic_block = bb;
      return *this; 
    }

    Coordinates& setOffset(Offset o) {
      offset = o;
      return *this; 
    }

    Coordinates& setInstructionType(InstructionType i) {
      ins_type = i;
      return *this;
    }

    Coordinates& setAddress(VMAddress addr) {
      address = addr;
      return *this;
    }

    Coordinates& setProbePlacement(ProbePlacement placement) {
      if (address.getVMAddress() != nullptr) {
        address.setPlacement(placement);
      } else if (ins_type.getSpec().compare("")) {
        ins_type.setPlacement(placement);
      } else if (offset.getSpec().compare("")) {
        offset.setPlacement(placement);
      } else if (basic_block.getSpec().compare("")) {
        basic_block.setPlacement(placement);
      } else if (loop.getSpec().compare("")) {
        loop.setPlacement(placement);
      } else if (function.getSpec().compare("")) {
        function.setPlacement(placement);
      } else if (module.getSpec().compare("")) {
        module.setPlacement(placement);
      } else {
        throw std::invalid_argument("At least one probe coordinate must be" 
            " specified");
      }
      return *this;
    }

    // Getters
    Module getModule() {
      return module;
    }

    Function getFunction() {
      return function;
    }

    Loop getLoop() {
      return loop;
    }

    BasicBlock getBasicBlock() {
      return basic_block;
    }

    Offset getOffset() {
      return offset;
    }

    InstructionType getInstructionType() {
      return ins_type;
    }

    VMAddress getAddress(){
      return address; 
    }

  private:
    Module module;
    Function function;
    Loop loop; 
    BasicBlock basic_block;
    Offset offset;
    InstructionType ins_type;
    VMAddress address;
};

class ProbeGroupInfo {
  public:
    ProbeGroupId id;
    std::string name;
    utils::Address start;

    ProbeGroupInfo(ProbeGroupId id) : id(id) {

    }

    ProbeGroupInfo(ProbeGroupId id, std::string name, utils::Address start) 
      : id(id), name(name), start(start) {
    }

    bool operator == (const ProbeGroupInfo& pgi) {
      return (id == pgi.id);
    }
};

class ProbeRegistration {
  public:
    RegistrationId reg_id;
    std::map<std::string, std::vector<ProbeGroupInfo>> pg_by_function;
    std::list<ProbeGroupInfo> conflicts;
    bool failures;
    int num_probed_pgs;
    int num_skipped_pgs;
    int num_failed_pgs;
    int discoverd_pgs;
    ticks probing_costs;
    ticks meta_data_costs;
    ticks injection_costs;
    ticks punning_costs;

    std::vector<ProbeGroupInfo> getProbeGroupsForFunction(std::string name) {
      auto it = pg_by_function.find(name);
      if (it != pg_by_function.end()) {
        return it->second;
      }

      return std::vector<ProbeGroupInfo>();
    }

    std::vector<std::string> getProbedFunctions() {
      std::vector<std::string> fns;
      for (auto it = pg_by_function.begin(); it != pg_by_function.end(); it++) {
        fns.push_back(it->first);
      }
      return fns;
    }
};

/// The signature for a callback that registers a newly discovered
/// probe.  The ProbeProvider owns the ProbeMetadata record, so the
/// callback may read it, but should not free it.
///
/// This probe-discovery callback has two main obligations:
///
///  (1) Call initialize() to set up the constant argument to future
///      probe invocations.
///
///  (2) Call either activate() or deactivate() any number of times,
///      to leave the probe in a valid state by callback completion.
///
/// These methods can be called by accessing the owning ProbeProvider
/// through the ProbeMetadata pointer itself.
typedef void (*Callback) (const ProbeInfo* pi);

/// Initialization call back function which willl be called when probe provider
/// gets initialized
typedef void (*InitCallback) (void);

/// probeId -> probeGroupId
///   

/// [Module]:Function:[Loop]:[Basic Block]\([Offset]|[Ins])@Entry
/// Module:Function:Loop:Basic Block:Offset:Ins:*
/// [Module]:Function:[Loop]:[Basic Block]:[Offset]:*
/// /* $exit != offset1&offset2 & $granularity == LOOP*/
class ProbeProvider {
  public:
    ProbeProvider(Callback cb, InitCallback init) : 
      callback(cb), init_callback(init) {
      // probe_meta_data = new ProbeVec;
    }

    InstrumentationId registerInstrumentationProvider(
        InstrumentationProvider instrumentation) {

      ProviderEntry pe(instrumentation.getName());
      auto it = i_providers.find(pe);
      if (it != i_providers.end()) {
        printf("Error adding provider..\n");
        throw std::invalid_argument("Provider with the same name already " 
            "exists");
      } else {
        lock.lock();
        pe.provider_id = i_provider_counter++;
        instrumentation.id = pe.provider_id;
        i_providers.insert(
            std::pair<ProviderEntry, InstrumentationProvider>(pe, 
              instrumentation));
        lock.unlock();
        return pe.provider_id;
      }
    }

    const InstrumentationProvider& getInstrumentationProvider(
        std::string name) {
      ProviderEntry pe(name);
      auto it = i_providers.find(pe);
      if (it != i_providers.end()) {
        return it->second;
      } else {
        throw std::invalid_argument("Provider with the given name does not" 
            " exist");
      }
    }

    virtual ProbeRegistration registerProbes(Coordinates coords, 
        std::string instrumentation_provider) = 0;

    // Per probe operations
    virtual bool activate(ProbeInfo probe) = 0;
    virtual bool deactivate(ProbeInfo probe) = 0;

    // Per probe group operations
    virtual bool activate(ProbeGroupInfo pg) = 0;
    virtual bool deactivate(ProbeGroupInfo pg) = 0;

    // Bulk operations
    virtual bool activate(ProbeRegistration registration) = 0;
    virtual bool deactivate(ProbeRegistration registraiton) = 0;

    // Low level instrumentation functions
    // virtual bool instrumentAddress(Address addr, char* injected_bytes);

    static ProbeProvider* getGlobalProbeProvider();

    static ProbeProvider* initializeGlobalProbeProvider(ProviderType type, 
      Callback callback, InitCallback init);

    InitCallback init_callback;

  protected:
    Callback callback;

  private:
    static std::unique_ptr<ProbeProvider> p;
    static utils::concurrency::SpinLock lock;

    class ProviderEntry {
      public:
        int provider_id;
        std::string provider_name;

        ProviderEntry(std::string name) : provider_name(name) {

        }

        bool operator==(const ProviderEntry& other) const { 
          return (provider_name == other.provider_name);
        }
    };

    class ProviderEntryHasher {
      public:
        std::size_t operator()(const ProviderEntry& k) const {
          return (std::hash<std::string>()(k.provider_name));
        }
    };

    std::unordered_map<ProviderEntry, InstrumentationProvider, 
      ProviderEntryHasher> i_providers;
    int32_t i_provider_counter;
};

} /* End liteinst */

#endif /* _LITEINST_HPP_ */
