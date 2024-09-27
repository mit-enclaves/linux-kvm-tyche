#ifndef _ASM_X86_TYCHE_H
#define _ASM_X86_TYCHE_H

#ifdef CONFIG_TYCHE_GUEST
void __init tyche_early_init(void);
#else 
static void __init tyche_early_init(void) { pr_err("Tyche Guest disabled\n");};
#endif

#endif
