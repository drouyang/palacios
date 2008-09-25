/* (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> */
/* (c) 2008, The V3VEE Project <http://www.v3vee.org> */

#include <geekos/debug.h>


void PrintBoth(const char * format, ...) {
  va_list args;

  va_start(args, format);
  PrintList(format, args);
  SerialPrintList(format, args);
  va_end(args);
}
