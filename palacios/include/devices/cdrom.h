/*
 * Zheng Cui
 * cuizheng@cs.unm.edu
 * July 2008
 */

#ifndef __DEVICES_CDROM_H_
#define __DEVICES_CDROM_H_

#include <geekos/ktypes.h>

typedef unsigned int rd_bool;
typedef uchar_t Bit8u;
typedef ushort_t Bit16u;
typedef uint_t Bit32u;
typedef ullong_t Bit64u;

#define uint8 Bit8u 
#define uint16 Bit16u 
#define uint32 Bit32u 

struct cdrom_interface;

struct cdrom_ops {
  
  void (*init)(struct cdrom_interface *cdrom);

  /* 
   * Load CD-ROM. Returns false if CD is not ready. 
   */
  rd_bool (*insert_cdrom)(struct cdrom_interface *cdrom, char *dev /*= NULL*/);

  /* 
   * Logically eject the CD.
   */
  void (*eject_cdrom)(struct cdrom_interface *cdrom);
  
  /* 
   * Read CD TOC. Returns false if start track is out of bounds.
   */
  rd_bool (*read_toc)(struct cdrom_interface *cdrom, uint8* buf, int* length, rd_bool msf, int start_track);
  
  /* 
   * Return CD-ROM capacity (in 2048 byte frames)
   */
  uint32 (*capacity)(struct cdrom_interface *cdrom);
  
  /*
   * Read a single block from the CD
   */
  void (*read_block)(struct cdrom_interface *cdrom, uint8* buf, int lba);
  
  /*
   * Start (spin up) the CD.
   */
  int (*start_cdrom)(struct cdrom_interface *cdrom);
};


struct cdrom_interface {

  struct cdrom_ops ops;

  ulong_t fd; //memory address
  ulong_t capacity_B;
  ulong_t head; //current position

  uchar_t lba;

  char *path; //for ramdisk, NULL
  int using_file; //no
};

void init_cdrom(struct cdrom_interface *cdrom);

#endif
