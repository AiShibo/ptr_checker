#ifndef EOM_COUNTER_H
#define EOM_COUNTER_H

/**
 * Initialize the end-of-messages (EOM) counter.
 * Sets the expected number of EOMs that must be received before the program
 * terminates.
 *
 * @param expected_eom The expected number of end-of-messages to receive
 */
void eom_counter_init(int expected_eom);

/**
 * Increment the EOM counter.
 * If the number of EOMs received equals the expected number, the program
 * will terminate with exit(0).
 */
void eom_counter_inc(void);

#endif /* EOM_COUNTER_H */
