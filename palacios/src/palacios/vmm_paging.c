/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm_paging.h>

#include <palacios/vmm.h>

#include <palacios/vm_guest_mem.h>



#define USE_VMM_PAGING_DEBUG
// All of the debug functions defined in vmm_paging.h are implemented in this file
#include "vmm_paging_debug.h"
#undef USE_VMM_PAGING_DEBUG


void delete_page_tables_32(pde32_t * pde) {
  int i;

  if (pde == NULL) { 
    return;
  }

  for (i = 0; (i < MAX_PDE32_ENTRIES); i++) {
    if (pde[i].present) {
      // We double cast, first to an addr_t to handle 64 bit issues, then to the pointer
      PrintDebug("PTE base addr %x \n", pde[i].pt_base_addr);
      pte32_t * pte = (pte32_t *)((addr_t)(uint_t)(pde[i].pt_base_addr << PAGE_POWER));

      PrintDebug("Deleting PTE %d (%p)\n", i, pte);
      V3_FreePage(pte);
    }
  }

  PrintDebug("Deleting PDE (%p)\n", pde);
  V3_FreePage(V3_PAddr(pde));
}

void delete_page_tables_32PAE(pdpe32pae_t * pdpe) { 
  PrintError("Unimplemented function\n");
}

void delete_page_tables_64(pml4e64_t * pml4) {
  PrintError("Unimplemented function\n");
}


int v3_translate_guest_pt_32(struct guest_info * info, v3_reg_t guest_cr3, addr_t vaddr, addr_t * paddr) {
  addr_t guest_pde_pa = CR3_TO_PDE32_PA(guest_cr3);
  pde32_t * guest_pde = 0;
  addr_t guest_pte_pa = 0;

  if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t*)&guest_pde) == -1) {
    PrintError("Could not get virtual address of Guest PDE32 (PA=%p)\n", 
	       (void *)guest_pde_pa);
    return -1;
  }
  
  switch (pde32_lookup(guest_pde, vaddr, &guest_pte_pa)) {
  case PT_ENTRY_NOT_PRESENT:
    *paddr = 0;  
    return -1;
  case PT_ENTRY_LARGE_PAGE:
    *paddr = guest_pte_pa;
    return 0;
  case PT_ENTRY_PAGE:
    {
      pte32_t * guest_pte = NULL;

      if (guest_pa_to_host_va(info, guest_pte_pa, (addr_t*)&guest_pte) == -1) {
	PrintError("Could not get virtual address of Guest PTE32 (PA=%p)\n", 
		   (void *)guest_pte_pa);
	return -1;
      }

      if (pte32_lookup(guest_pte, vaddr, paddr) == PT_ENTRY_NOT_PRESENT) {
	return -1;
      }

      return 0;
    }
  }

  // should never get here
  return -1;
}


int v3_translate_guest_pt_32pae(struct guest_info * info, v3_reg_t guest_cr3, addr_t vaddr, addr_t * paddr) {
  addr_t guest_pdpe_pa = CR3_TO_PDPE32PAE_PA(guest_cr3);
  pdpe32pae_t * guest_pdpe = 0;
  addr_t guest_pde_pa = 0;

  if (guest_pa_to_host_va(info, guest_pdpe_pa, (addr_t*)&guest_pdpe) == -1) {
    PrintError("Could not get virtual address of Guest PDPE32PAE (PA=%p)\n",
	       (void *)guest_pdpe_pa);
    return -1;
  }

  switch (pdpe32pae_lookup(guest_pdpe, vaddr, &guest_pde_pa)) 
    {
    case PT_ENTRY_NOT_PRESENT:
      *paddr = 0;
      return -1;
    case PT_ENTRY_PAGE:
      {
	pde32pae_t * guest_pde = NULL;
	addr_t guest_pte_pa = 0;
	
	if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t *)&guest_pde) == -1) {
	  PrintError("Could not get virtual Address of Guest PDE32PAE (PA=%p)\n", 
		     (void *)guest_pde_pa);
	  return -1;
	}
	
	switch (pde32pae_lookup(guest_pde, vaddr, &guest_pte_pa)) 
	  {
	  case PT_ENTRY_NOT_PRESENT:
	    *paddr = 0;
	    return -1;
	  case PT_ENTRY_LARGE_PAGE:
	    *paddr = guest_pte_pa;
	    return 0;
	  case PT_ENTRY_PAGE:
	    {
	      pte32pae_t * guest_pte = NULL;
	      
	      if (guest_pa_to_host_va(info, guest_pte_pa, (addr_t *)&guest_pte) == -1) {
		PrintError("Could not get virtual Address of Guest PTE32PAE (PA=%p)\n", 
			   (void *)guest_pte_pa);
		return -1;
	      }

	      if (pte32pae_lookup(guest_pte, vaddr, paddr) == PT_ENTRY_NOT_PRESENT) {
		return -1;
	      }

	      return 0;
	    }
	  }
      }
    default:
      return -1;
    }

  // should never get here
  return -1;
}

int v3_translate_guest_pt_64(struct guest_info * info, v3_reg_t guest_cr3, addr_t vaddr, addr_t * paddr) {
  addr_t guest_pml4_pa = CR3_TO_PML4E64_PA(guest_cr3);
  pml4e64_t * guest_pmle = 0;
  addr_t guest_pdpe_pa = 0;

  if (guest_pa_to_host_va(info, guest_pml4_pa, (addr_t*)&guest_pmle) == -1) {
    PrintError("Could not get virtual address of Guest PML4E64 (PA=%p)\n", 
	       (void *)guest_pml4_pa);
    return -1;
  }
  
  switch (pml4e64_lookup(guest_pmle, vaddr, &guest_pdpe_pa)) {
  case PT_ENTRY_NOT_PRESENT:
    *paddr = 0;
    return -1;
  case PT_ENTRY_PAGE:
    {
      pdpe64_t * guest_pdp = NULL;
      addr_t guest_pde_pa = 0;

      if (guest_pa_to_host_va(info, guest_pdpe_pa, (addr_t *)&guest_pdp) == -1) {
	PrintError("Could not get virtual address of Guest PDPE64 (PA=%p)\n", 
		   (void *)guest_pdpe_pa);
	return -1;
      }

      switch (pdpe64_lookup(guest_pdp, vaddr, &guest_pde_pa)) {
      case PT_ENTRY_NOT_PRESENT:
	*paddr = 0;
	return -1;
      case PT_ENTRY_LARGE_PAGE:
	*paddr = 0;
	PrintError("1 Gigabyte Pages not supported\n");
	return -1;
      case PT_ENTRY_PAGE:
	{
	  pde64_t * guest_pde = NULL;
	  addr_t guest_pte_pa = 0;

	  if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t *)&guest_pde) == -1) {
	    PrintError("Could not get virtual address of guest PDE64 (PA=%p)\n", 
		       (void *)guest_pde_pa);
	    return -1;
	  }

	  switch (pde64_lookup(guest_pde, vaddr, &guest_pte_pa)) {
	  case PT_ENTRY_NOT_PRESENT:
	    *paddr = 0;
	    return -1;
	  case PT_ENTRY_LARGE_PAGE:
	    *paddr = guest_pte_pa;
	    return 0;
	  case PT_ENTRY_PAGE:
	    {
	      pte64_t * guest_pte = NULL;
	      
	      if (guest_pa_to_host_va(info, guest_pte_pa, (addr_t *)&guest_pte) == -1) {
		PrintError("Could not get virtual address of guest PTE64 (PA=%p)\n", 
			   (void *)guest_pte_pa);
		return -1;
	      }
		
	      if (pte64_lookup(guest_pte, vaddr, paddr) == PT_ENTRY_NOT_PRESENT) {
		return -1;
	      }

	      return 0;
	    }
	  }
	}
      }
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}



int v3_translate_host_pt_32(v3_reg_t host_cr3, addr_t vaddr, addr_t * paddr) {
  pde32_t * host_pde = (pde32_t *)CR3_TO_PDE32_VA(host_cr3);
  pte32_t * host_pte = 0;
    
  switch (pde32_lookup(host_pde, vaddr, (addr_t *)&host_pte)) {
  case PT_ENTRY_NOT_PRESENT:
    *paddr = 0;
    return -1;
  case PT_ENTRY_LARGE_PAGE:
    *paddr = (addr_t)host_pte;
    return 0;
  case PT_ENTRY_PAGE:
    if (pte32_lookup(V3_VAddr(host_pte), vaddr, paddr) == PT_ENTRY_NOT_PRESENT) {
      return -1;
    }
    return 0;
  }
  
  // should never get here
  return -1;
}


int v3_translate_host_pt_32pae(v3_reg_t host_cr3, addr_t vaddr, addr_t * paddr) {
  pdpe32pae_t * host_pdpe = (pdpe32pae_t *)CR3_TO_PDPE32PAE_VA(host_cr3);
  pde32pae_t * host_pde = NULL;
  pte32pae_t * host_pte = NULL;

  switch (pdpe32pae_lookup(host_pdpe, vaddr, (addr_t *)&host_pde)) {
  case PT_ENTRY_NOT_PRESENT:
    *paddr = 0;
    return -1;
  case PT_ENTRY_PAGE:
    switch (pde32pae_lookup(V3_VAddr(host_pde), vaddr, (addr_t *)&host_pte)) {
    case PT_ENTRY_NOT_PRESENT:
      *paddr = 0;
      return -1;
    case PT_ENTRY_LARGE_PAGE:
      *paddr = (addr_t)host_pte;
      return 0;
    case PT_ENTRY_PAGE:
      if (pte32pae_lookup(V3_VAddr(host_pte), vaddr, paddr) == PT_ENTRY_NOT_PRESENT) {
	return -1;
      }
      return 0;
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}


int v3_translate_host_pt_64(v3_reg_t host_cr3, addr_t vaddr, addr_t * paddr) {
  pml4e64_t * host_pmle = (pml4e64_t *)CR3_TO_PML4E64_VA(host_cr3);
  pdpe64_t * host_pdpe = NULL;
  pde64_t * host_pde = NULL;
  pte64_t * host_pte = NULL;

  switch(pml4e64_lookup(host_pmle, vaddr, (addr_t *)&host_pdpe)) {
  case PT_ENTRY_NOT_PRESENT:
    *paddr = 0;
    return -1;
  case PT_ENTRY_PAGE:
    switch(pdpe64_lookup(V3_VAddr(host_pdpe), vaddr, (addr_t *)&host_pde)) {
    case PT_ENTRY_NOT_PRESENT:
      *paddr = 0;
      return -1;
    case PT_ENTRY_LARGE_PAGE:
      *paddr = 0;
      PrintError("1 Gigabyte Pages not supported\n");
      return -1;
    case PT_ENTRY_PAGE:
      switch (pde64_lookup(V3_VAddr(host_pde), vaddr, (addr_t *)&host_pte)) {
      case PT_ENTRY_NOT_PRESENT:
	*paddr = 0;
	return -1;
      case PT_ENTRY_LARGE_PAGE:
	*paddr = (addr_t)host_pte;
	return 0;
      case PT_ENTRY_PAGE:
	if (pte64_lookup(V3_VAddr(host_pte), vaddr, paddr) == PT_ENTRY_NOT_PRESENT) {
	  return -1;
	}
	return 0;
      }
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}





/*
 * PAGE TABLE LOOKUP FUNCTIONS
 *
 *
 * The value of entry is a return type:
 * Page not present: *entry = 0
 * Large Page: *entry = translated physical address (byte granularity)
 * PTE entry: *entry is the address of the PTE Page
 */

/**
 * 
 *  32 bit Page Table lookup functions
 *
 **/

pt_entry_type_t pde32_lookup(pde32_t * pd, addr_t addr, addr_t * entry) {
  pde32_t * pde_entry = &(pd[PDE32_INDEX(addr)]);

  if (!pde_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else if (pde_entry->large_page) {
    pde32_4MB_t * large_pde = (pde32_4MB_t *)pde_entry;

    *entry = BASE_TO_PAGE_ADDR_4MB(large_pde->page_base_addr);
    *entry += PAGE_OFFSET_4MB(addr);

    return PT_ENTRY_LARGE_PAGE;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pde_entry->pt_base_addr);
    return PT_ENTRY_PAGE;
  }
}



/* Takes a virtual addr (addr) and returns the physical addr (entry) as defined in the page table
 */
pt_entry_type_t pte32_lookup(pte32_t * pt, addr_t addr, addr_t * entry) {
  pte32_t * pte_entry = &(pt[PTE32_INDEX(addr)]);

  if (!pte_entry->present) {
    *entry = 0;
    //    PrintDebug("Lookup at non present page (index=%d)\n", PTE32_INDEX(addr));
    return PT_ENTRY_NOT_PRESENT;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pte_entry->page_base_addr) + PAGE_OFFSET(addr);
    return PT_ENTRY_PAGE;
  }

}



/**
 * 
 *  32 bit PAE Page Table lookup functions
 *
 **/
pt_entry_type_t pdpe32pae_lookup(pdpe32pae_t * pdp, addr_t addr, addr_t * entry) {
  pdpe32pae_t * pdpe_entry = &(pdp[PDPE32PAE_INDEX(addr)]);
  
  if (!pdpe_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pdpe_entry->pd_base_addr);
    return PT_ENTRY_PAGE;
  }
}

pt_entry_type_t pde32pae_lookup(pde32pae_t * pd, addr_t addr, addr_t * entry) {
  pde32pae_t * pde_entry = &(pd[PDE32PAE_INDEX(addr)]);

  if (!pde_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else if (pde_entry->large_page) {
    pde32pae_2MB_t * large_pde = (pde32pae_2MB_t *)pde_entry;

    *entry = BASE_TO_PAGE_ADDR_2MB(large_pde->page_base_addr);
    *entry += PAGE_OFFSET_2MB(addr);

    return PT_ENTRY_LARGE_PAGE;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pde_entry->pt_base_addr);
    return PT_ENTRY_PAGE;
  }
}

pt_entry_type_t pte32pae_lookup(pte32pae_t * pt, addr_t addr, addr_t * entry) {
  pte32pae_t * pte_entry = &(pt[PTE32PAE_INDEX(addr)]);

  if (!pte_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pte_entry->page_base_addr) + PAGE_OFFSET(addr);
    return PT_ENTRY_PAGE;
  }
}



/**
 * 
 *  64 bit Page Table lookup functions
 *
 **/
pt_entry_type_t pml4e64_lookup(pml4e64_t * pml, addr_t addr, addr_t * entry) {
  pml4e64_t * pml_entry = &(pml[PML4E64_INDEX(addr)]);

  if (!pml_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pml_entry->pdp_base_addr);
    return PT_ENTRY_PAGE;
  }
}

pt_entry_type_t pdpe64_lookup(pdpe64_t * pdp, addr_t addr, addr_t * entry) {
  pdpe64_t * pdpe_entry = &(pdp[PDPE64_INDEX(addr)]);
  
  if (!pdpe_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else if (pdpe_entry->large_page) {
    PrintError("1 Gigabyte pages not supported\n");
    V3_ASSERT(0);
    return -1;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pdpe_entry->pd_base_addr);
    return PT_ENTRY_PAGE;
  }
}

pt_entry_type_t pde64_lookup(pde64_t * pd, addr_t addr, addr_t * entry) {
  pde64_t * pde_entry = &(pd[PDE64_INDEX(addr)]);

  if (!pde_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else if (pde_entry->large_page) {
    pde64_2MB_t * large_pde = (pde64_2MB_t *)pde_entry;

    *entry = BASE_TO_PAGE_ADDR_2MB(large_pde->page_base_addr);
    *entry += PAGE_OFFSET_2MB(addr);

    return PT_ENTRY_LARGE_PAGE;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pde_entry->pt_base_addr);
    return PT_ENTRY_PAGE;
  }
}

pt_entry_type_t pte64_lookup(pte64_t * pt, addr_t addr, addr_t * entry) {
  pte64_t * pte_entry = &(pt[PTE64_INDEX(addr)]);

  if (!pte_entry->present) {
    *entry = 0;
    return PT_ENTRY_NOT_PRESENT;
  } else {
    *entry = BASE_TO_PAGE_ADDR(pte_entry->page_base_addr) + PAGE_OFFSET(addr);
    return PT_ENTRY_PAGE;
  }
}








/* 
 *
 * Page Table Access Checks
 *
 */






int v3_check_host_pt_32(v3_reg_t host_cr3, addr_t vaddr, pf_error_t access_type, pt_access_status_t * access_status) {
  pde32_t * host_pde = (pde32_t *)CR3_TO_PDE32_VA(host_cr3);
  pte32_t * host_pte = 0;

  int pt_level = 2;

  // Check accessibility of PDE
  *access_status = v3_can_access_pde32(host_pde, vaddr, access_type);
  
  if (*access_status != PT_ACCESS_OK) {
    return pt_level;
  } 

  pt_level--;
  
  switch (pde32_lookup(host_pde, vaddr, (addr_t *)&host_pte)) {
  case PT_ENTRY_LARGE_PAGE:
    return 0;
  case PT_ENTRY_PAGE:
    *access_status = v3_can_access_pte32(V3_VAddr(host_pte), vaddr, access_type);
    
    if (*access_status != PT_ACCESS_OK) {
      return pt_level;
    }

    return 0;
  default: 
    return -1;
  }
  
  // should never get here
  return -1;
}

int v3_check_host_pt_32pae(v3_reg_t host_cr3, addr_t vaddr, pf_error_t access_type, pt_access_status_t * access_status) {
  pdpe32pae_t * host_pdpe = (pdpe32pae_t *)CR3_TO_PDPE32PAE_VA(host_cr3);
  pde32pae_t * host_pde = NULL;
  pte32pae_t * host_pte = NULL;
  int pt_level = 3;

  *access_status = v3_can_access_pdpe32pae(host_pdpe, vaddr, access_type);

  if (*access_status != PT_ACCESS_OK) {
    return pt_level;
  }

  pt_level--;

  switch (pdpe32pae_lookup(host_pdpe, vaddr, (addr_t *)&host_pde)) {
  case PT_ENTRY_PAGE:
    *access_status = v3_can_access_pde32pae(V3_VAddr(host_pde), vaddr, access_type);

    if (*access_status != PT_ACCESS_OK) {
      return pt_level;
    }

    pt_level--;

    switch (pde32pae_lookup(V3_VAddr(host_pde), vaddr, (addr_t *)&host_pte)) {
    case PT_ENTRY_LARGE_PAGE:
      return 0;
    case PT_ENTRY_PAGE:
      *access_status = v3_can_access_pte32pae(V3_VAddr(host_pte), vaddr, access_type);

      if (*access_status != PT_ACCESS_OK) {
	return pt_level;
      }

      return 0;
    default:
      return -1;
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}



int v3_check_host_pt_64(v3_reg_t host_cr3, addr_t vaddr, pf_error_t access_type, pt_access_status_t * access_status) {
  pml4e64_t * host_pmle = (pml4e64_t *)CR3_TO_PML4E64_VA(host_cr3);
  pdpe64_t * host_pdpe = NULL;
  pde64_t * host_pde = NULL;
  pte64_t * host_pte = NULL;
  int pt_level = 4;


  *access_status = v3_can_access_pml4e64(host_pmle, vaddr, access_type);

  if (*access_status != PT_ACCESS_OK) {
    return pt_level;
  }

  pt_level--;

  switch(pml4e64_lookup(host_pmle, vaddr, (addr_t *)&host_pdpe)) {
  case PT_ENTRY_PAGE:
    *access_status = v3_can_access_pdpe64(V3_VAddr(host_pdpe), vaddr, access_type);

    if (*access_status != PT_ACCESS_OK) {
      return pt_level;
    }

    pt_level--;

    switch(pdpe64_lookup(V3_VAddr(host_pdpe), vaddr, (addr_t *)&host_pde)) {
    case PT_ENTRY_LARGE_PAGE:
      return 0;
    case PT_ENTRY_PAGE:
      *access_status = v3_can_access_pde64(V3_VAddr(host_pde), vaddr, access_type);

      if (*access_status != PT_ACCESS_OK) {
	return pt_level;
      }

      pt_level--;

      switch (pde64_lookup(V3_VAddr(host_pde), vaddr, (addr_t *)&host_pte)) {
      case PT_ENTRY_LARGE_PAGE:
	return 0;
      case PT_ENTRY_PAGE:
	*access_status = v3_can_access_pte64(V3_VAddr(host_pte), vaddr, access_type);

	if (*access_status != PT_ACCESS_OK) {
	  return pt_level;
	}

	return 0;
      default:
	return -1;
      }
    default:
      return -1;
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}





int v3_check_guest_pt_32(struct guest_info * info, v3_reg_t guest_cr3, addr_t vaddr, 
			 pf_error_t access_type, pt_access_status_t * access_status) {
  addr_t guest_pde_pa = CR3_TO_PDE32_PA(guest_cr3);
  pde32_t * guest_pde = NULL;
  addr_t guest_pte_pa = 0;
  int pt_level = 2;

  if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t*)&guest_pde) == -1) {
    PrintError("Could not get virtual address of Guest PDE32 (PA=%p)\n", 
	       (void *)guest_pde_pa);
    return -1;
  }
  

  // Check accessibility of PDE
  *access_status = v3_can_access_pde32(guest_pde, vaddr, access_type);
  
  if (*access_status != PT_ACCESS_OK) {
    return pt_level;
  } 

  pt_level--;
  
  switch (pde32_lookup(guest_pde, vaddr, &guest_pte_pa)) {
  case PT_ENTRY_LARGE_PAGE:
    return 0;
  case PT_ENTRY_PAGE:
    {
      pte32_t * guest_pte = NULL;

      if (guest_pa_to_host_va(info, guest_pte_pa, (addr_t*)&guest_pte) == -1) {
	PrintError("Could not get virtual address of Guest PTE32 (PA=%p)\n", 
		   (void *)guest_pte_pa);
	return -1;
      }

      *access_status = v3_can_access_pte32(guest_pte, vaddr, access_type);
      
      if (*access_status != PT_ACCESS_OK) {
	return pt_level;
      }
      return 0;
    }
  default: 
    return -1;
  }
  
  // should never get here
  return -1;
}





int v3_check_guest_pt_32pae(struct guest_info * info, v3_reg_t guest_cr3, addr_t vaddr, 
			    pf_error_t access_type, pt_access_status_t * access_status) {
  addr_t guest_pdpe_pa = CR3_TO_PDPE32PAE_PA(guest_cr3);
  pdpe32pae_t * guest_pdpe = NULL;
  addr_t guest_pde_pa = 0;
  int pt_level = 3;

  if (guest_pa_to_host_va(info, guest_pdpe_pa, (addr_t*)&guest_pdpe) == -1) {
    PrintError("Could not get virtual address of Guest PDPE32PAE (PA=%p)\n",
	       (void *)guest_pdpe_pa);
    return -1;
  }

  *access_status = v3_can_access_pdpe32pae(guest_pdpe, vaddr, access_type);

  if (*access_status != PT_ACCESS_OK) {
    return pt_level;
  }

  pt_level--;

  switch (pdpe32pae_lookup(guest_pdpe, vaddr, &guest_pde_pa)) {
  case PT_ENTRY_PAGE:
    {
      pde32pae_t * guest_pde = NULL;
      addr_t guest_pte_pa = 0;
	
      if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t *)&guest_pde) == -1) {
	PrintError("Could not get virtual Address of Guest PDE32PAE (PA=%p)\n", 
		   (void *)guest_pde_pa);
	return -1;
      }
      
      *access_status = v3_can_access_pde32pae(guest_pde, vaddr, access_type);
      
      if (*access_status != PT_ACCESS_OK) {
	return pt_level;
      }
      
      pt_level--;
      
      switch (pde32pae_lookup(guest_pde, vaddr, &guest_pte_pa)) {
      case PT_ENTRY_LARGE_PAGE:
	return 0;
      case PT_ENTRY_PAGE:
	{
	  pte32pae_t * guest_pte = NULL;

	  if (guest_pa_to_host_va(info, guest_pte_pa, (addr_t *)&guest_pte) == -1) {
	    PrintError("Could not get virtual Address of Guest PTE32PAE (PA=%p)\n", 
		       (void *)guest_pte_pa);
	    return -1;
	  }

	  *access_status = v3_can_access_pte32pae(guest_pte, vaddr, access_type);
	
	  if (*access_status != PT_ACCESS_OK) {
	    return pt_level;
	  }
	
	  return 0;
	}
      default:
	return -1;
      }
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}


  pte64_t * guest_pte = NULL;

int v3_check_guest_pt_64(struct guest_info * info, v3_reg_t guest_cr3, addr_t vaddr, 
			 pf_error_t access_type, pt_access_status_t * access_status) {
  addr_t guest_pml4_pa = CR3_TO_PML4E64_PA(guest_cr3);
  pml4e64_t * guest_pmle = NULL; 
  addr_t guest_pdpe_pa = 0;
  int pt_level = 4;

  if (guest_pa_to_host_va(info, guest_pml4_pa, (addr_t*)&guest_pmle) == -1) {
    PrintError("Could not get virtual address of Guest PML4E64 (PA=%p)\n", 
	       (void *)guest_pml4_pa);
    return -1;
  }

  *access_status = v3_can_access_pml4e64(guest_pmle, vaddr, access_type);

  if (*access_status != PT_ACCESS_OK) {
    return pt_level;
  }

  pt_level--;

  switch(pml4e64_lookup(guest_pmle, vaddr, &guest_pdpe_pa)) {
  case PT_ENTRY_PAGE:
    {
      pdpe64_t * guest_pdp = NULL;
      addr_t guest_pde_pa = 0;

      if (guest_pa_to_host_va(info, guest_pdpe_pa, (addr_t *)&guest_pdp) == -1) {
	PrintError("Could not get virtual address of Guest PDPE64 (PA=%p)\n", 
		   (void *)guest_pdpe_pa);
	return -1;
      }

      *access_status = v3_can_access_pdpe64(guest_pdp, vaddr, access_type);
      
      if (*access_status != PT_ACCESS_OK) {
	return pt_level;
      }
      
      pt_level--;
      
      switch(pdpe64_lookup(guest_pdp, vaddr, &guest_pde_pa)) {
      case PT_ENTRY_LARGE_PAGE:
	return 0;
      case PT_ENTRY_PAGE:
	{
	  pde64_t * guest_pde = NULL;
  	  addr_t guest_pte_pa = 0;
	  
	  if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t *)&guest_pde) == -1) {
	    PrintError("Could not get virtual address of guest PDE64 (PA=%p)\n", 
		       (void *)guest_pde_pa);
	    return -1;
	  }

	  *access_status = v3_can_access_pde64(guest_pde, vaddr, access_type);
	  
	  if (*access_status != PT_ACCESS_OK) {
	    return pt_level;
	  }
	  
	  pt_level--;
	  
	  switch (pde64_lookup(guest_pde, vaddr, &guest_pte_pa)) {
	  case PT_ENTRY_LARGE_PAGE:
	    return 0;
	  case PT_ENTRY_PAGE:
	    {
	      pte64_t * guest_pte = NULL;
	      
	      if (guest_pa_to_host_va(info, guest_pte_pa, (addr_t *)&guest_pte) == -1) {
		PrintError("Could not get virtual address of guest PTE64 (PA=%p)\n", 
			   (void *)guest_pte_pa);
		return -1;
	      }

	      *access_status = v3_can_access_pte64(guest_pte, vaddr, access_type);
	      
	      if (*access_status != PT_ACCESS_OK) {
		return pt_level;
	      }
	      
	      return 0;
	    }
	  default:
	    return -1;
	  }
	}
      default:
	return -1;
      }
    }
  default:
    return -1;
  }

  // should never get here
  return -1;
}





static pt_access_status_t can_access_pt_entry(gen_pt_t * pt, pf_error_t access_type) {
  if (pt->present == 0) {
    return PT_ACCESS_NOT_PRESENT;
  } else if ((pt->writable == 0) && (access_type.write == 1)) {
    return PT_ACCESS_WRITE_ERROR;
  } else if ((pt->user_page == 0) && (access_type.user == 1)) {
    // Check CR0.WP?
    return PT_ACCESS_USER_ERROR;
  }

  return PT_ACCESS_OK;
}



/*
 *   32 bit access checks
 */
pt_access_status_t inline v3_can_access_pde32(pde32_t * pde, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pde[PDE32_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

pt_access_status_t inline v3_can_access_pte32(pte32_t * pte, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pte[PTE32_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}


/*
 *  32 bit PAE access checks
 */
pt_access_status_t inline v3_can_access_pdpe32pae(pdpe32pae_t * pdpe, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pdpe[PDPE32PAE_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

pt_access_status_t inline v3_can_access_pde32pae(pde32pae_t * pde, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pde[PDE32PAE_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

pt_access_status_t inline v3_can_access_pte32pae(pte32pae_t * pte, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pte[PTE32PAE_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

/*
 *   64 Bit access checks
 */
pt_access_status_t inline v3_can_access_pml4e64(pml4e64_t * pmle, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pmle[PML4E64_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

pt_access_status_t inline v3_can_access_pdpe64(pdpe64_t * pdpe, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pdpe[PDPE64_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

pt_access_status_t inline v3_can_access_pde64(pde64_t * pde, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pde[PDE32_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}

pt_access_status_t inline v3_can_access_pte64(pte64_t * pte, addr_t addr, pf_error_t access_type) {
  gen_pt_t * entry = (gen_pt_t *)&pte[PTE64_INDEX(addr)];
  return can_access_pt_entry(entry, access_type);
}










/* We generate a page table to correspond to a given memory layout
 * pulling pages from the mem_list when necessary
 * If there are any gaps in the layout, we add them as unmapped pages
 */
pde32_t * create_passthrough_pts_32(struct guest_info * guest_info) {
  addr_t current_page_addr = 0;
  int i, j;
  struct shadow_map * map = &(guest_info->mem_map);

  pde32_t * pde = V3_VAddr(V3_AllocPages(1));

  for (i = 0; i < MAX_PDE32_ENTRIES; i++) {
    int pte_present = 0;
    pte32_t * pte = V3_VAddr(V3_AllocPages(1));
    

    for (j = 0; j < MAX_PTE32_ENTRIES; j++) {
      struct shadow_region * region = get_shadow_region_by_addr(map, current_page_addr);

      if (!region || 
	  (region->host_type == HOST_REGION_HOOK) || 
	  (region->host_type == HOST_REGION_UNALLOCATED) || 
	  (region->host_type == HOST_REGION_MEMORY_MAPPED_DEVICE) || 
	  (region->host_type == HOST_REGION_REMOTE) ||
	  (region->host_type == HOST_REGION_SWAPPED)) {
	pte[j].present = 0;
	pte[j].writable = 0;
	pte[j].user_page = 0;
	pte[j].write_through = 0;
	pte[j].cache_disable = 0;
	pte[j].accessed = 0;
	pte[j].dirty = 0;
	pte[j].pte_attr = 0;
	pte[j].global_page = 0;
	pte[j].vmm_info = 0;
	pte[j].page_base_addr = 0;
      } else {
	addr_t host_addr;
	pte[j].present = 1;
	pte[j].writable = 1;
	pte[j].user_page = 1;
	pte[j].write_through = 0;
	pte[j].cache_disable = 0;
	pte[j].accessed = 0;
	pte[j].dirty = 0;
	pte[j].pte_attr = 0;
	pte[j].global_page = 0;
	pte[j].vmm_info = 0;

	if (guest_pa_to_host_pa(guest_info, current_page_addr, &host_addr) == -1) {
	  // BIG ERROR
	  // PANIC
	  return NULL;
	}
	
	pte[j].page_base_addr = host_addr >> 12;
	
	pte_present = 1;
      }

      current_page_addr += PAGE_SIZE;
    }

    if (pte_present == 0) { 
      V3_FreePage(V3_PAddr(pte));

      pde[i].present = 0;
      pde[i].writable = 0;
      pde[i].user_page = 0;
      pde[i].write_through = 0;
      pde[i].cache_disable = 0;
      pde[i].accessed = 0;
      pde[i].reserved = 0;
      pde[i].large_page = 0;
      pde[i].global_page = 0;
      pde[i].vmm_info = 0;
      pde[i].pt_base_addr = 0;
    } else {
      pde[i].present = 1;
      pde[i].writable = 1;
      pde[i].user_page = 1;
      pde[i].write_through = 0;
      pde[i].cache_disable = 0;
      pde[i].accessed = 0;
      pde[i].reserved = 0;
      pde[i].large_page = 0;
      pde[i].global_page = 0;
      pde[i].vmm_info = 0;
      pde[i].pt_base_addr = PAGE_BASE_ADDR((addr_t)V3_PAddr(pte));
    }

  }

  return pde;
}


/* We generate a page table to correspond to a given memory layout
 * pulling pages from the mem_list when necessary
 * If there are any gaps in the layout, we add them as unmapped pages
 */
pdpe32pae_t * create_passthrough_pts_32PAE(struct guest_info * guest_info) {
  addr_t current_page_addr = 0;
  int i, j, k;
  struct shadow_map * map = &(guest_info->mem_map);

  pdpe32pae_t * pdpe = V3_VAddr(V3_AllocPages(1));
  memset(pdpe, 0, PAGE_SIZE);

  for (i = 0; i < MAX_PDPE32PAE_ENTRIES; i++) {
    int pde_present = 0;
    pde32pae_t * pde = V3_VAddr(V3_AllocPages(1));

    for (j = 0; j < MAX_PDE32PAE_ENTRIES; j++) {


      int pte_present = 0;
      pte32pae_t * pte = V3_VAddr(V3_AllocPages(1));
      
      
      for (k = 0; k < MAX_PTE32PAE_ENTRIES; k++) {
	struct shadow_region * region = get_shadow_region_by_addr(map, current_page_addr);
	
	if (!region || 
	    (region->host_type == HOST_REGION_HOOK) || 
	    (region->host_type == HOST_REGION_UNALLOCATED) || 
	    (region->host_type == HOST_REGION_MEMORY_MAPPED_DEVICE) || 
	    (region->host_type == HOST_REGION_REMOTE) ||
	    (region->host_type == HOST_REGION_SWAPPED)) {
	  pte[k].present = 0;
	  pte[k].writable = 0;
	  pte[k].user_page = 0;
	  pte[k].write_through = 0;
	  pte[k].cache_disable = 0;
	  pte[k].accessed = 0;
	  pte[k].dirty = 0;
	  pte[k].pte_attr = 0;
	  pte[k].global_page = 0;
	  pte[k].vmm_info = 0;
	  pte[k].page_base_addr = 0;
	  pte[k].rsvd = 0;
	} else {
	  addr_t host_addr;
	  pte[k].present = 1;
	  pte[k].writable = 1;
	  pte[k].user_page = 1;
	  pte[k].write_through = 0;
	  pte[k].cache_disable = 0;
	  pte[k].accessed = 0;
	  pte[k].dirty = 0;
	  pte[k].pte_attr = 0;
	  pte[k].global_page = 0;
	  pte[k].vmm_info = 0;
	  
	  if (guest_pa_to_host_pa(guest_info, current_page_addr, &host_addr) == -1) {
	    // BIG ERROR
	    // PANIC
	    return NULL;
	  }
	  
	  pte[k].page_base_addr = host_addr >> 12;
	  pte[k].rsvd = 0;

	  pte_present = 1;
	}
	
	current_page_addr += PAGE_SIZE;
      }
      
      if (pte_present == 0) { 
	V3_FreePage(V3_PAddr(pte));
	
	pde[j].present = 0;
	pde[j].writable = 0;
	pde[j].user_page = 0;
	pde[j].write_through = 0;
	pde[j].cache_disable = 0;
	pde[j].accessed = 0;
	pde[j].avail = 0;
	pde[j].large_page = 0;
	pde[j].global_page = 0;
	pde[j].vmm_info = 0;
	pde[j].pt_base_addr = 0;
	pde[j].rsvd = 0;
      } else {
	pde[j].present = 1;
	pde[j].writable = 1;
	pde[j].user_page = 1;
	pde[j].write_through = 0;
	pde[j].cache_disable = 0;
	pde[j].accessed = 0;
	pde[j].avail = 0;
	pde[j].large_page = 0;
	pde[j].global_page = 0;
	pde[j].vmm_info = 0;
	pde[j].pt_base_addr = PAGE_BASE_ADDR((addr_t)V3_PAddr(pte));
	pde[j].rsvd = 0;

	pde_present = 1;
      }
      
    }
    
    if (pde_present == 0) { 
      V3_FreePage(V3_PAddr(pde));
      
      pdpe[i].present = 0;
      pdpe[i].rsvd = 0;
      pdpe[i].write_through = 0;
      pdpe[i].cache_disable = 0;
      pdpe[i].accessed = 0;
      pdpe[i].avail = 0;
      pdpe[i].rsvd2 = 0;
      pdpe[i].vmm_info = 0;
      pdpe[i].pd_base_addr = 0;
      pdpe[i].rsvd3 = 0;
    } else {
      pdpe[i].present = 1;
      pdpe[i].rsvd = 0;
      pdpe[i].write_through = 0;
      pdpe[i].cache_disable = 0;
      pdpe[i].accessed = 0;
      pdpe[i].avail = 0;
      pdpe[i].rsvd2 = 0;
      pdpe[i].vmm_info = 0;
      pdpe[i].pd_base_addr = PAGE_BASE_ADDR((addr_t)V3_PAddr(pde));
      pdpe[i].rsvd3 = 0;
    }
    
  }


  return pdpe;
}






pml4e64_t * create_passthrough_pts_64(struct guest_info * info) {
  addr_t current_page_addr = 0;
  int i, j, k, m;
  struct shadow_map * map = &(info->mem_map);
  
  pml4e64_t * pml = V3_VAddr(V3_AllocPages(1));

  for (i = 0; i < 1; i++) {
    int pdpe_present = 0;
    pdpe64_t * pdpe = V3_VAddr(V3_AllocPages(1));

    for (j = 0; j < 20; j++) {
      int pde_present = 0;
      pde64_t * pde = V3_VAddr(V3_AllocPages(1));

      for (k = 0; k < MAX_PDE64_ENTRIES; k++) {
	int pte_present = 0;
	pte64_t * pte = V3_VAddr(V3_AllocPages(1));


	for (m = 0; m < MAX_PTE64_ENTRIES; m++) {
	  struct shadow_region * region = get_shadow_region_by_addr(map, current_page_addr);
	  

	  
	  if (!region || 
	      (region->host_type == HOST_REGION_HOOK) || 
	      (region->host_type == HOST_REGION_UNALLOCATED) || 
	      (region->host_type == HOST_REGION_MEMORY_MAPPED_DEVICE) || 
	      (region->host_type == HOST_REGION_REMOTE) ||
	      (region->host_type == HOST_REGION_SWAPPED)) {
	    pte[m].present = 0;
	    pte[m].writable = 0;
	    pte[m].user_page = 0;
	    pte[m].write_through = 0;
	    pte[m].cache_disable = 0;
	    pte[m].accessed = 0;
	    pte[m].dirty = 0;
	    pte[m].pte_attr = 0;
	    pte[m].global_page = 0;
	    pte[m].vmm_info = 0;
	    pte[m].page_base_addr = 0;
	  } else {
	    addr_t host_addr;
	    pte[m].present = 1;
	    pte[m].writable = 1;
	    pte[m].user_page = 1;
	    pte[m].write_through = 0;
	    pte[m].cache_disable = 0;
	    pte[m].accessed = 0;
	    pte[m].dirty = 0;
	    pte[m].pte_attr = 0;
	    pte[m].global_page = 0;
	    pte[m].vmm_info = 0;
	    
	    if (guest_pa_to_host_pa(info, current_page_addr, &host_addr) == -1) {
	      // BIG ERROR
	      // PANIC
	      return NULL;
	    }

	    pte[m].page_base_addr = PAGE_BASE_ADDR(host_addr);

	    //PrintPTE64(current_page_addr, &(pte[m]));

	    pte_present = 1;	  
	  }




	  current_page_addr += PAGE_SIZE;
	}
	
	if (pte_present == 0) {
	  V3_FreePage(V3_PAddr(pte));

	  pde[k].present = 0;
	  pde[k].writable = 0;
	  pde[k].user_page = 0;
	  pde[k].write_through = 0;
	  pde[k].cache_disable = 0;
	  pde[k].accessed = 0;
	  pde[k].avail = 0;
	  pde[k].large_page = 0;
	  //pde[k].global_page = 0;
	  pde[k].vmm_info = 0;
	  pde[k].pt_base_addr = 0;
	} else {
	  pde[k].present = 1;
	  pde[k].writable = 1;
	  pde[k].user_page = 1;
	  pde[k].write_through = 0;
	  pde[k].cache_disable = 0;
	  pde[k].accessed = 0;
	  pde[k].avail = 0;
	  pde[k].large_page = 0;
	  //pde[k].global_page = 0;
	  pde[k].vmm_info = 0;
	  pde[k].pt_base_addr = PAGE_BASE_ADDR((addr_t)V3_PAddr(pte));

	  pde_present = 1;
	}
      }

      if (pde_present == 0) {
	V3_FreePage(V3_PAddr(pde));
	
	pdpe[j].present = 0;
	pdpe[j].writable = 0;
	pdpe[j].user_page = 0;
	pdpe[j].write_through = 0;
	pdpe[j].cache_disable = 0;
	pdpe[j].accessed = 0;
	pdpe[j].avail = 0;
	pdpe[j].large_page = 0;
	//pdpe[j].global_page = 0;
	pdpe[j].vmm_info = 0;
	pdpe[j].pd_base_addr = 0;
      } else {
	pdpe[j].present = 1;
	pdpe[j].writable = 1;
	pdpe[j].user_page = 1;
	pdpe[j].write_through = 0;
	pdpe[j].cache_disable = 0;
	pdpe[j].accessed = 0;
	pdpe[j].avail = 0;
	pdpe[j].large_page = 0;
	//pdpe[j].global_page = 0;
	pdpe[j].vmm_info = 0;
	pdpe[j].pd_base_addr = PAGE_BASE_ADDR((addr_t)V3_PAddr(pde));


	pdpe_present = 1;
      }

    }

    PrintDebug("PML index=%d\n", i);

    if (pdpe_present == 0) {
      V3_FreePage(V3_PAddr(pdpe));
      
      pml[i].present = 0;
      pml[i].writable = 0;
      pml[i].user_page = 0;
      pml[i].write_through = 0;
      pml[i].cache_disable = 0;
      pml[i].accessed = 0;
      pml[i].reserved = 0;
      //pml[i].large_page = 0;
      //pml[i].global_page = 0;
      pml[i].vmm_info = 0;
      pml[i].pdp_base_addr = 0;
    } else {
      pml[i].present = 1;
      pml[i].writable = 1;
      pml[i].user_page = 1;
      pml[i].write_through = 0;
      pml[i].cache_disable = 0;
      pml[i].accessed = 0;
      pml[i].reserved = 0;
      //pml[i].large_page = 0;
      //pml[i].global_page = 0;
      pml[i].vmm_info = 0;
      pml[i].pdp_base_addr = PAGE_BASE_ADDR((addr_t)V3_PAddr(pdpe));
    }
  }

  return pml;
}


int v3_walk_guest_pt_32(struct guest_info * info,  v3_reg_t guest_cr3,
			int (*callback)(int level, addr_t page_ptr, addr_t page_pa, void * private_data),
			void * private_data) {
  addr_t guest_pde_pa = CR3_TO_PDE32_PA(guest_cr3);
  pde32_t * guest_pde = NULL;
  int i, j;

  if (!callback) {
    PrintError("Call back was not specified\n");
    return -1;
  }

  if (guest_pa_to_host_va(info, guest_pde_pa, (addr_t *)&guest_pde) == -1) {
    PrintError("Could not get virtual address of Guest PDE32 (PA=%p)\n", 
	       (void *)guest_pde_pa);
    return -1;
  }

  callback(PAGE_PD32, (addr_t)guest_pde, guest_pde_pa, private_data);

  for (i = 0; i < MAX_PDE32_ENTRIES; i++) {
    if (guest_pde[i].present) {
      if (guest_pde[i].large_page) {
	pde32_4MB_t * large_pde = (pde32_4MB_t *)&(guest_pde[i]);
	addr_t large_page_pa = BASE_TO_PAGE_ADDR_4MB(large_pde->page_base_addr);
	addr_t large_page_va = 0;

	if (guest_pa_to_host_va(info, large_page_pa, &large_page_va) == -1) {
	  PrintError("Could not get virtual address of Guest 4MB Page (PA=%p)\n", 
		     (void *)large_page_pa);
	  return -1;
	}

	callback(PAGE_4MB, large_page_va, large_page_pa, private_data);
      } else {
	addr_t pte_pa = BASE_TO_PAGE_ADDR(guest_pde[i].pt_base_addr);
	pte32_t * tmp_pte = NULL;

	if (guest_pa_to_host_va(info, pte_pa, (addr_t *)&tmp_pte) == -1) {
	  PrintError("Could not get virtual address of Guest PTE32 (PA=%p)\n", 
		     (void *)pte_pa);
	  return -1;
	}

	callback(PAGE_PT32, (addr_t)tmp_pte, pte_pa, private_data);

	for (j = 0; j < MAX_PTE32_ENTRIES; j++) {
	  if (tmp_pte[j].present) {
	    addr_t page_pa = BASE_TO_PAGE_ADDR(tmp_pte[j].page_base_addr);
	    addr_t page_va = 0;

	    if (guest_pa_to_host_va(info, page_pa, &page_va) == -1) {
	      PrintError("Could not get virtual address of Guest 4KB Page (PA=%p)\n", 
			 (void *)page_pa);
	      return -1;
	    }
	    
	    callback(PAGE_4KB, page_va, page_pa, private_data);
	  }
	}
      }
    }
  }
  return 0;
}


int v3_walk_guest_pt_32pae(struct guest_info * info,  v3_reg_t guest_cr3,
			   int (*callback)(int level, addr_t page_ptr, addr_t page_pa, void * private_data),
			   void * private_data) {
  addr_t guest_pdpe_pa = CR3_TO_PDPE32PAE_PA(guest_cr3);
  pdpe32pae_t * guest_pdpe = NULL;
  int i, j, k;

  if (!callback) {
    PrintError("Call back was not specified\n");
    return -1;
  }

  if (guest_pa_to_host_va(info, guest_pdpe_pa, (addr_t *)&guest_pdpe) == -1) {
    PrintError("Could not get virtual address of Guest PDPE32PAE (PA=%p)\n", 
	       (void *)guest_pdpe_pa);
    return -1;
  }

  

  callback(PAGE_PDP32PAE, (addr_t)guest_pdpe, guest_pdpe_pa, private_data);

  for (i = 0; i < MAX_PDPE32PAE_ENTRIES; i++) {
    if (guest_pdpe[i].present) {
      addr_t pde_pa = BASE_TO_PAGE_ADDR(guest_pdpe[i].pd_base_addr);
      pde32pae_t * tmp_pde = NULL;

      if (guest_pa_to_host_va(info, pde_pa, (addr_t *)&tmp_pde) == -1) {
	PrintError("Could not get virtual address of Guest PDE32PAE (PA=%p)\n", 
		   (void *)pde_pa);
	return -1;
      }

      callback(PAGE_PD32PAE, (addr_t)tmp_pde, pde_pa, private_data);
      
      for (j = 0; j < MAX_PDE32PAE_ENTRIES; j++) {
	if (tmp_pde[j].present) {
	  if (tmp_pde[j].large_page) {
	    pde32pae_2MB_t * large_pde = (pde32pae_2MB_t *)&(tmp_pde[j]);
	    addr_t large_page_pa = BASE_TO_PAGE_ADDR_2MB(large_pde->page_base_addr);
	    addr_t large_page_va = 0;
	    
	    if (guest_pa_to_host_va(info, large_page_pa, &large_page_va) == -1) {
	      PrintError("Could not get virtual address of Guest 2MB Page (PA=%p)\n", 
			 (void *)large_page_pa);
	      return -1;
	    }
	    
	    callback(PAGE_2MB, large_page_va, large_page_pa, private_data);
	  } else {
	    addr_t pte_pa = BASE_TO_PAGE_ADDR(tmp_pde[j].pt_base_addr);
	    pte32pae_t * tmp_pte = NULL;
	    
	    if (guest_pa_to_host_va(info, pte_pa, (addr_t *)&tmp_pte) == -1) {
	      PrintError("Could not get virtual address of Guest PTE32PAE (PA=%p)\n", 
			 (void *)pte_pa);
	      return -1;
	    }
	    
	    callback(PAGE_PT32PAE, (addr_t)tmp_pte, pte_pa, private_data);
	    
	    for (k = 0; k < MAX_PTE32PAE_ENTRIES; k++) {
	      if (tmp_pte[k].present) {
		addr_t page_pa = BASE_TO_PAGE_ADDR(tmp_pte[k].page_base_addr);
		addr_t page_va = 0;
		
		if (guest_pa_to_host_va(info, page_pa, &page_va) == -1) {
		  PrintError("Could not get virtual address of Guest 4KB Page (PA=%p)\n", 
			     (void *)page_pa);
		  return -1;
		}
		
		callback(PAGE_4KB, page_va, page_pa, private_data);
	      }
	    }
	  }
	}
      }
    }
  }
  return 0;
}




int v3_walk_guest_pt_64(struct guest_info * info,  v3_reg_t guest_cr3,
			int (*callback)(int level, addr_t page_ptr, addr_t page_pa, void * private_data),
			void * private_data) {
  addr_t guest_pml_pa = CR3_TO_PML4E64_PA(guest_cr3);
  pml4e64_t * guest_pml = NULL;
  int i, j, k, m;

  if (!callback) {
    PrintError("Call back was not specified\n");
    return -1;
  }

  if (guest_pa_to_host_va(info, guest_pml_pa, (addr_t *)&guest_pml) == -1) {
    PrintError("Could not get virtual address of Guest PML464 (PA=%p)\n", 
	       (void *)guest_pml);
    return -1;
  }


  callback(PAGE_PML464, (addr_t)guest_pml, guest_pml_pa, private_data);

  for (i = 0; i < MAX_PML4E64_ENTRIES; i++) {
    if (guest_pml[i].present) {
      addr_t pdpe_pa = BASE_TO_PAGE_ADDR(guest_pml[i].pdp_base_addr);
      pdpe64_t * tmp_pdpe = NULL;
      
      
      if (guest_pa_to_host_va(info, pdpe_pa, (addr_t *)&tmp_pdpe) == -1) {
	PrintError("Could not get virtual address of Guest PDPE64 (PA=%p)\n", 
		   (void *)pdpe_pa);
	return -1;
      }
      
      callback(PAGE_PDP64, (addr_t)tmp_pdpe, pdpe_pa, private_data);
      
      for (j = 0; j < MAX_PDPE64_ENTRIES; j++) {
	if (tmp_pdpe[j].present) {
	  if (tmp_pdpe[j].large_page) {
	    pdpe64_1GB_t * large_pdpe = (pdpe64_1GB_t *)&(tmp_pdpe[j]);
	    addr_t large_page_pa = BASE_TO_PAGE_ADDR_1GB(large_pdpe->page_base_addr);
	    addr_t large_page_va = 0;

	    if (guest_pa_to_host_va(info, large_page_pa, &large_page_va) == -1) {
	      PrintError("Could not get virtual address of Guest 1GB page (PA=%p)\n", 
			 (void *)large_page_pa);
	      return -1;
	    }

	    callback(PAGE_1GB, (addr_t)large_page_va, large_page_pa, private_data);

	  } else {
	    addr_t pde_pa = BASE_TO_PAGE_ADDR(tmp_pdpe[j].pd_base_addr);
	    pde64_t * tmp_pde = NULL;
	    
	    if (guest_pa_to_host_va(info, pde_pa, (addr_t *)&tmp_pde) == -1) {
	      PrintError("Could not get virtual address of Guest PDE64 (PA=%p)\n", 
			 (void *)pde_pa);
	      return -1;
	    }
	    
	    callback(PAGE_PD64, (addr_t)tmp_pde, pde_pa, private_data);
	    
	    for (k = 0; k < MAX_PDE64_ENTRIES; k++) {
	      if (tmp_pde[k].present) {
		if (tmp_pde[k].large_page) {
		  pde64_2MB_t * large_pde = (pde64_2MB_t *)&(tmp_pde[k]);
		  addr_t large_page_pa = BASE_TO_PAGE_ADDR_2MB(large_pde->page_base_addr);
		  addr_t large_page_va = 0;
		  
		  if (guest_pa_to_host_va(info, large_page_pa, &large_page_va) == -1) {
		    PrintError("Could not get virtual address of Guest 2MB page (PA=%p)\n", 
			       (void *)large_page_pa);
		    return -1;
		  }
		  
		  callback(PAGE_2MB, large_page_va, large_page_pa, private_data);
		} else {
		  addr_t pte_pa = BASE_TO_PAGE_ADDR(tmp_pde[k].pt_base_addr);
		  pte64_t * tmp_pte = NULL;
		  
		  if (guest_pa_to_host_va(info, pte_pa, (addr_t *)&tmp_pte) == -1) {
		    PrintError("Could not get virtual address of Guest PTE64 (PA=%p)\n", 
			       (void *)pte_pa);
		    return -1;
		  }
		  
		  callback(PAGE_PT64, (addr_t)tmp_pte, pte_pa, private_data);
		  
		  for (m = 0; m < MAX_PTE64_ENTRIES; m++) {
		    if (tmp_pte[m].present) {
		      addr_t page_pa = BASE_TO_PAGE_ADDR(tmp_pte[m].page_base_addr);
		      addr_t page_va = 0;
		      
		      if (guest_pa_to_host_va(info, page_pa, &page_va) == -1) {
			PrintError("Could not get virtual address of Guest 4KB Page (PA=%p)\n", 
				   (void *)page_pa);
			return -1;
		      }
		      
		      callback(PAGE_4KB, page_va, page_pa, private_data);
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }
  return 0;
}

int v3_walk_host_pt_32(v3_reg_t host_cr3,
		       int (*callback)(int level, addr_t page_ptr, addr_t page_pa, void * private_data),
		       void * private_data) {
  pde32_t * host_pde = (pde32_t *)CR3_TO_PDE32_VA(host_cr3);
  addr_t pde_pa = CR3_TO_PDE32_PA(host_cr3);
  int i, j;

  if (!callback) {
    PrintError("Call back was not specified\n");
    return -1;
  }

  callback(PAGE_PD32, (addr_t)host_pde, pde_pa, private_data);

  for (i = 0; i < MAX_PDE32_ENTRIES; i++) {
    if (host_pde[i].present) {
      if (host_pde[i].large_page) {
	pde32_4MB_t * large_pde = (pde32_4MB_t *)&(host_pde[i]);
	addr_t large_page_pa = BASE_TO_PAGE_ADDR_4MB(large_pde->page_base_addr);

	callback(PAGE_4MB, (addr_t)V3_VAddr((void *)large_page_pa), large_page_pa, private_data);
      } else {
	addr_t pte_pa = BASE_TO_PAGE_ADDR(host_pde[i].pt_base_addr);
	pte32_t * tmp_pte = (pte32_t *)V3_VAddr((void *)pte_pa);

	callback(PAGE_PT32, (addr_t)tmp_pte, pte_pa, private_data);

	for (j = 0; j < MAX_PTE32_ENTRIES; j++) {
	  if (tmp_pte[j].present) {
	    addr_t page_pa = BASE_TO_PAGE_ADDR(tmp_pte[j].page_base_addr);
	    callback(PAGE_4KB, (addr_t)V3_VAddr((void *)page_pa), page_pa, private_data);
	  }
	}
      }
    }
  }
  return 0;
}
	




int v3_walk_host_pt_32pae(v3_reg_t host_cr3,
			  void (*callback)(page_type_t type, addr_t page_ptr, addr_t page_pa, void * private_data),
			  void * private_data) {
  pdpe32pae_t * host_pdpe = (pdpe32pae_t *)CR3_TO_PDPE32PAE_VA(host_cr3);
  addr_t pdpe_pa = CR3_TO_PDPE32PAE_PA(host_cr3);
  int i, j, k;
  
  if (!callback) {
    PrintError("Callback was not specified\n");
    return -1;
  }
  
  callback(PAGE_PDP32PAE, (addr_t)host_pdpe, pdpe_pa, private_data);
  
  for (i = 0; i < MAX_PDPE32PAE_ENTRIES; i++) {
    if (host_pdpe[i].present) {	
      addr_t pde_pa = BASE_TO_PAGE_ADDR(host_pdpe[i].pd_base_addr);
      pde32pae_t * tmp_pde = (pde32pae_t *)V3_VAddr((void *)pde_pa);
      
      callback(PAGE_PD32PAE, (addr_t)tmp_pde, pde_pa, private_data);
      
      for (j = 0; j < MAX_PDE32PAE_ENTRIES; j++) {
	if (tmp_pde[j].present) {
	  
	  if (tmp_pde[j].large_page) {
	    pde32pae_2MB_t * large_pde = (pde32pae_2MB_t *)&(tmp_pde[j]);
	    addr_t large_page_pa = BASE_TO_PAGE_ADDR_2MB(large_pde->page_base_addr);

	    callback(PAGE_2MB, (addr_t)V3_VAddr((void *)large_page_pa), large_page_pa, private_data);
	  } else {
	    addr_t pte_pa = BASE_TO_PAGE_ADDR(tmp_pde[j].pt_base_addr);
	    pte32pae_t * tmp_pte = (pte32pae_t *)V3_VAddr((void *)pte_pa);
	    
	    callback(PAGE_PT32PAE, (addr_t)tmp_pte, pte_pa, private_data);
	    
	    for (k = 0; k < MAX_PTE32PAE_ENTRIES; k++) {
	      if (tmp_pte[k].present) {
		addr_t page_pa = BASE_TO_PAGE_ADDR(tmp_pte[k].page_base_addr);
		callback(PAGE_4KB, (addr_t)V3_VAddr((void *)page_pa), page_pa, private_data);
	      }
	    }
	  }	    
	}
      }
    }
  }
  return 0;
}
			

int v3_walk_host_pt_64(v3_reg_t host_cr3,
		       void (*callback)(page_type_t type, addr_t page_ptr, addr_t page_pa, void * private_data),
		       void * private_data) {
  pml4e64_t * host_pml = (pml4e64_t *)CR3_TO_PML4E64_VA(host_cr3);
  addr_t pml_pa = CR3_TO_PML4E64_PA(host_cr3);
  int i, j, k, m;

  if (!callback) {
    PrintError("Callback was not specified\n");
    return -1;
  }

  callback(PAGE_PML464, (addr_t)host_pml, pml_pa, private_data);

  for (i = 0; i < MAX_PML4E64_ENTRIES; i++) {
    if (host_pml[i].present) {
      addr_t pdpe_pa = BASE_TO_PAGE_ADDR(host_pml[i].pdp_base_addr);
      pdpe64_t * tmp_pdpe = (pdpe64_t *)V3_VAddr((void *)pdpe_pa);

      callback(PAGE_PDP64, (addr_t)tmp_pdpe, pdpe_pa, private_data);

      for (j = 0; j < MAX_PDPE64_ENTRIES; j++) {
	if (tmp_pdpe[j].present) {
	  if (tmp_pdpe[j].large_page) {
	    pdpe64_1GB_t * large_pdp = (pdpe64_1GB_t *)&(tmp_pdpe[j]);
	    addr_t large_page_pa = BASE_TO_PAGE_ADDR_1GB(large_pdp->page_base_addr);

	    callback(PAGE_1GB, (addr_t)V3_VAddr((void *)large_page_pa), large_page_pa, private_data);	    
	  } else {
	    addr_t pde_pa = BASE_TO_PAGE_ADDR(tmp_pdpe[j].pd_base_addr);
	    pde64_t * tmp_pde = (pde64_t *)V3_VAddr((void *)pde_pa);

	    callback(PAGE_PD64, (addr_t)tmp_pde, pde_pa, private_data);

	    for (k = 0; k < MAX_PDE64_ENTRIES; k++) {
	      if (tmp_pde[k].present) {
		if (tmp_pde[k].large_page) {
		  pde64_2MB_t * large_pde = (pde64_2MB_t *)&(tmp_pde[k]);
		  addr_t large_page_pa = BASE_TO_PAGE_ADDR_2MB(large_pde->page_base_addr);
		  
		  callback(PAGE_2MB, (addr_t)V3_VAddr((void *)large_page_pa), large_page_pa, private_data);
		} else {
		  addr_t pte_pa = BASE_TO_PAGE_ADDR(tmp_pde[k].pt_base_addr);
		  pte64_t * tmp_pte = (pte64_t *)V3_VAddr((void *)pte_pa);

		  callback(PAGE_PT64, (addr_t)tmp_pte, pte_pa, private_data);

		  for (m = 0; m < MAX_PTE64_ENTRIES; m++) {
		    if (tmp_pte[m].present) {
		      addr_t page_pa = BASE_TO_PAGE_ADDR(tmp_pte[m].page_base_addr);
		      callback(PAGE_4KB, (addr_t)V3_VAddr((void *)page_pa), page_pa, private_data);
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
    }
  }
  return 0;
}
