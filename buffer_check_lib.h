#ifndef BUFFER_CHECK_LIB_H
#define BUFFER_CHECK_LIB_H

#include <stddef.h>
#include <stdint.h>

/**
 * Add a message to the skip list to avoid false positives in pointer checking.
 * The MD5 hash of the message is computed and stored. When check_pointers() or
 * check_pointers_with_vm_print() is called, if the message MD5 matches an entry
 * in the skip list, the check is skipped and the entry is removed.
 *
 * Note: This function accounts for OpenBSD imsg 16-byte headers. During checking,
 * both the full message and the message starting at offset 16 are checked against
 * the skip list.
 *
 * @param data Pointer to the message data buffer
 * @param size Size of the message data buffer in bytes
 */
void ptr_check_skip(const void *data, size_t size);

/**
 * Check if the provided data buffer contains any pointers to valid memory regions.
 * If a pointer is detected, the function will print a message and raise SIGBUS.
 *
 * Messages can be excluded from checking by calling ptr_check_skip() beforehand.
 *
 * @param data Pointer to the data buffer to check
 * @param size Size of the data buffer in bytes
 */
void check_pointers(const void *data, size_t size);

/**
 * Check if the provided data buffer contains uninitialized memory via MSAN.
 * If uninitialized memory is detected, a warning is printed and SIGBUS is raised.
 *
 * Note: This function only performs MSAN checks. To also check for pointers,
 * call check_pointers() separately or use check_buffer().
 *
 * @param data Pointer to the data buffer to check
 * @param size Size of the data buffer in bytes
 */
void check_buffer_with_msan(const void *data, size_t size);

/**
 * Perform both MSAN and pointer checks on the provided data buffer.
 * This function first checks for uninitialized memory (if ENABLE_MSAN_CHECK is set),
 * then checks for pointer leaks (if ENABLE_PTR_CHECK is set).
 *
 * If issues are detected, appropriate messages are printed and SIGBUS may be raised.
 *
 * Messages can be excluded from pointer checking by calling ptr_check_skip() beforehand.
 *
 * @param data Pointer to the data buffer to check
 * @param size Size of the data buffer in bytes
 */
void check_buffer(const void *data, size_t size);

#endif /* BUFFER_CHECK_LIB_H */
