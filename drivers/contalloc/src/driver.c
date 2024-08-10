#include "common_log.h"
#include "contalloc_ioctl.h"
#include "linux/kern_levels.h"
#include "linux/printk.h"
#include "linux/string.h"
#include "src/coloring_backend.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "common.h"

// —————————————————————————————— Module Info ——————————————————————————————— //

MODULE_LICENSE("GPL");
MODULE_AUTHOR("aghosn");
MODULE_DESCRIPTION("Continuous memory allocator");
MODULE_VERSION("0.01");

extern char boot_command_line[];

/**
 * @brief Check for the additional_mem kernel command line parameter and parse it
 * If this param is present we run with memory coloring and should allocate TD
 * memory from the memory ranges specified by the param
 * 
 * @param cmdline kernel cmdline 
 * @param results caller allocated result param that we will
 * @return int 
   - less than 0 if error
   - exactly   0 if coloring parameter not found
   - exactly   1 if coloring parameter was found
 */
static int check_for_additional_colors_param(char *cmdline,
					     coloring_info_t *coloring_info)
{
	char *values;
	char *token;
	char *rest;
	size_t index,token_count;
	char *keyword = "additional_mem=";
	char *found = strstr(cmdline, keyword);

	if (!found) {
		return 0;
	}

	found += strlen(keyword);

	// Copy the values to a temporary buffer
	values = kmalloc(strlen(found) + 1, GFP_KERNEL);
	if (!values) {
		printk(KERN_ERR
		       "Failed to allocate memory for values buffer\n");
		return -ENOMEM;
	}
	strncpy(values, found, strlen(found) + 1);

	// Tokenize the values using comma as delimiter
	rest = values;

	// Initialize the coloring_info_t struct
	coloring_info->bytes_for_color_len = 0;

	// Count the number of values
	token_count = 0;
	while ((token = strsep(&rest, ",")) != NULL) {
		//coloring_info->bytes_for_color_len++;
		token_count++;
	}

	// Allocate memory for bytes_for_color, -2 because first entry is color id offset and second entry is start gpa
	//only the reamining entries describe a mapped color.
	coloring_info->bytes_for_color_len = token_count - 2;
	coloring_info->bytes_for_color =
		kmalloc_array(coloring_info->bytes_for_color_len,
			      sizeof(size_t), GFP_KERNEL);
	if (!coloring_info->bytes_for_color) {
		printk(KERN_ERR
		       "Failed to allocate memory for bytes_for_color\n");
		kfree(values);
		return -ENOMEM;
	}

	// Reset tokenization to fill the struct
	strncpy(values, found, strlen(found) + 1);
	rest = values;

	//Parse the first value as first_color_id
	if ((token = strsep(&rest, ",")) != NULL) {
		if (kstrtoull(token, 0, &coloring_info->id_first_color)) {
			return -1;
		}
	}

	// Parse the second value as start_gpa
	if ((token = strsep(&rest, ",")) != NULL) {
		if (kstrtoull(token, 0, &coloring_info->start_gpa)) {
			return -1;
		}
	}

	// Parse the remaining values as bytes_for_color
	index = 0;
	while ((token = strsep(&rest, ",")) != NULL) {
		if (kstrtoull(
			    token, 0,
			    (unsigned long long *)&(
				    coloring_info->bytes_for_color[index++]))) {
			return -1;
		}
	}

	// Print the results for verification
	printk(KERN_INFO "start_gpa: 0x%llx\n", coloring_info->start_gpa);
	for (size_t i = 0; i < coloring_info->bytes_for_color_len; i++) {
		printk(KERN_INFO "bytes_for_color[%zu]: 0x%zx\n", i,
		       coloring_info->bytes_for_color[i]);
	}
	return 1;
}

// —————————————————————— Loading/Unloading  functions —————————————————————— //
static int __init contalloc_init(void)
{
	int result = 0;
	int color_check_result = -1;
	coloring_info_t coloring_info;
	printk(KERN_INFO "Loading contalloc driver.");
	printk(KERN_INFO "Checking if we have additional colors");

	color_check_result = check_for_additional_colors_param(boot_command_line,
						   &coloring_info);
	//error
	if (color_check_result < 0) {
		printk(KERN_ERR "Failed to check for coloring param");
		return result;
	}

	//common driver setup
	if( (result = contalloc_register()) ) {
		printk( KERN_ERR "Failed to register driver");
    	return result;
	}

	if( color_check_result == 0 ) {
    	init_regular_backend(&global_alloc_backend);
	} else if (color_check_result == 1) {
		//special setup for coloring backend
		if( (result = init_coloring_backend_state(&coloring_info))) {
      		return result;
    	}
		init_coloring_backend(&global_alloc_backend);
		return 0;
	} else {
		printk(KERN_ERR "Failed to check for coloring param");
		return result;
	}
	return result;
}

static void __exit contalloc_exit(void)
{
	printk(KERN_INFO "Removing contalloc driver.");
	contalloc_unregister();
}

// ————————————————————————— Module's Registration —————————————————————————— //

module_init(contalloc_init);
module_exit(contalloc_exit);
