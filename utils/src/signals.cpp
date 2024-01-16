
#include "signals.hpp"
#include <algorithm>
#include <sstream>
#include <stdio.h>
#include <stdexcept>
#include <cstring>

using namespace utils::signals;

using std::vector;
using std::sort;
using std::memory_order_acquire;
using std::ostringstream;
using std::memory_order_release;
using std::range_error;
using std::logic_error;
using std::invalid_argument;

bool SignalHandlerRegistry::priority_enabled = false;
SignalHandlerRegistry::SigEntry SignalHandlerRegistry::sig_entries[NSIG];

void SignalHandlerRegistry::enableHandlerPriority() {
  priority_enabled = true;
}

void SignalHandlerRegistry::disableHandlerPriority() {
  priority_enabled = false;
}

void SignalHandlerRegistry::registerSignalHandler(HandlerRegistration& reg,
    bool sync, int priority) {

  SigEntry* entry = &sig_entries[reg.signum];

  {
     std::lock_guard<std::mutex> lck(entry->init_lock) ;

    if (!entry->initialized) {
      entry->signum = reg.signum;
      entry->n_sync_handlers = 0;
      entry->n_async_handlers = 0;

      entry->sync_handlers.reserve(MAX_HANDLERS);
      entry->async_handlers.reserve(MAX_HANDLERS);

      for (int i=0; i < MAX_HANDLERS; i++) {
          entry->sync_handlers.emplace_back();
        entry->async_handlers.emplace_back();
        entry->sync_handlers[i].used = false;
        entry->async_handlers[i].used = false;
      }

      entry->initialized = true;
    }
  }

  // Acquire lock

  std::lock_guard<std::mutex> lck(entry->reg_lock);

  int index = -1;

  if (sync) {

    if (entry->n_sync_handlers < MAX_HANDLERS) {

      bool registered = false;
      for (int i=0; i < MAX_HANDLERS; i++) {
        if (!entry->sync_handlers[i].used) {
          entry->sync_handlers[i].used = true;
          entry->sync_handlers[i].priority = priority;
          entry->sync_handlers[i].handler = reg.act.sa_sigaction;
        }

        entry->n_sync_handlers++;
        registered = true;
        index = i;
        break;
      }

      if (!registered) {
          fprintf(stderr, "Maximum number of asynchrounous handlers exceeded for signal %d\n", reg.signum);
          exit(1);
      }

    } else {
        fprintf(stderr, "Maximum number of asynchrounous handlers exceeded for signal %d\n", reg.signum);
        exit(1);
    }
  } else {
    if (entry->n_async_handlers < MAX_HANDLERS) {
      bool registered = false;
      for (int i=0; i < MAX_HANDLERS; i++) {
        if (!entry->async_handlers[i].used) {
          entry->async_handlers[i].used = true;
          entry->async_handlers[i].priority = priority;
          entry->async_handlers[i].handler = reg.act.sa_sigaction;
        }

        entry->n_async_handlers++;
        registered = true;
        index = i;
        break;
      }

      if (!registered) {
          fprintf(stderr, "Maximum number of asynchrounous handlers exceeded for signal %d\n", reg.signum);
          exit(1);
      }
    } else {
        fprintf(stderr, "Maximum number of asynchrounous handlers exceeded for signal %d\n", reg.signum);
        exit(1);
    }
  }

  /*
  // Do the actual signal registration
  struct sigaction act;
  memset( &act, 0, sizeof act);
  act.sa_sigaction = &handler_dispatcher;
  // act.sa_mask = reg.act.sa_mask;
  sigemptyset(& (act.sa_mask));
  act.sa_flags = SA_SIGINFO; // Check if reg.act.sa_flags are valid first

  int ret = sigaction(reg.signum, &act, NULL);
  */

  struct sigaction act;
  memset( &act, 0, sizeof act);
  act.sa_flags = SA_SIGINFO; 
  act.sa_sigaction = reg.act.sa_sigaction;

  sigemptyset(& (act.sa_mask));
  int ret = sigaction(SIGILL, &act, NULL);

  if (!ret) {
    reg.reg_id = index;
    reg.sync = sync;
  } else {
      fprintf(stderr, "Failed registering signal handler with error : %m\n");
      exit(1);
  }
}

void SignalHandlerRegistry::unregisterSignalHandler(HandlerRegistration& reg) {
  SigEntry* entry = &sig_entries[reg.signum];

  if (!entry->initialized) {
    ostringstream out;  
    out << "No handler registered for signal : " << reg.signum << "\n"; 
    throw invalid_argument(out.str());
  }

  std::lock_guard<std::mutex> lck(entry->reg_lock);

  if (reg.sync) {
    entry->sync_handlers[reg.reg_id].used = false;
    entry->n_sync_handlers--;
  } else {
    entry->async_handlers[reg.reg_id].used = false;
    entry->n_async_handlers--;
  }

  if (entry->n_sync_handlers == 0 
      && entry->n_async_handlers == 0) {
    // Do the actual signal unregistration
    struct sigaction act;
    memset( &act, 0, sizeof act);
    act.sa_handler = SIG_DFL; 

    sigaction(reg.signum, &act, NULL);
  }
}

/********** Private helper functions **********/
vector<SignalHandlerRegistry::SigHandlerEntry> 
  SignalHandlerRegistry::handlerSort(int signum, bool sync) {

  SigEntry* entry = &sig_entries[signum];
  vector<SignalHandlerRegistry::SigHandlerEntry> handlers;
  if (sync) {
    handlers = entry->sync_handlers;
  } else {
    handlers = entry->async_handlers;
  } 

  sort(handlers.begin(), handlers.end(),
      [] (SigHandlerEntry const& a, SigHandlerEntry const& b) -> bool {
      return a.priority < b.priority;
      }); 

  return handlers;
}

void SignalHandlerRegistry::handler_dispatcher(int signum, siginfo_t* siginfo,
    void* context) {
  SigEntry* entry = &sig_entries[signum]; 

  if (!entry->initialized) {
    return;
  }

  if (!priority_enabled) {
    for (int i=0; i < MAX_HANDLERS; i++) {
      if (entry->sync_handlers[i].used) {
        entry->sync_handlers[i].handler(signum, siginfo, context);
      }
    }
  } else {
    vector<SigHandlerEntry> handlers = handlerSort(signum, true);
    for (int i=0; i < MAX_HANDLERS; i++) {
      if (handlers[i].used) {
        handlers[i].handler(signum, siginfo, context);
      }
    }
  }

  // Do some signalfd stuff to invoke async handlers
}
