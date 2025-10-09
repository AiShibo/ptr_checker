#ifndef PTR_CHECK_LIB_H
#define PTR_CHECK_LIB_H

#include <stddef.h>
#include <stdint.h>

/**
 * Check if the provided data buffer contains any pointers to valid memory regions.
 * If a pointer is detected, the function will print a message and raise SIGSEGV.
 *
 * @param data Pointer to the data buffer to check
 * @param size Size of the data buffer in bytes
 */
void check_pointers(const void *data, size_t size);

/**
 * Check if the provided data buffer contains any pointers to valid memory regions,
 * with VM region information printed to stdout.
 * If a pointer is detected, the function will print a message and raise SIGSEGV.
 *
 * @param data Pointer to the data buffer to check
 * @param size Size of the data buffer in bytes
 */
void check_pointers_with_vm_print(const void *data, size_t size);

#endif /* PTR_CHECK_LIB_H */
