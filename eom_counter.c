#include "eom_counter.h"
#include <stdio.h>
#include <stdlib.h>

/* Global variable to store the expected number of EOMs */
static int expected_eom_count = 0;

/* Global variable to track the current number of EOMs received */
static int current_eom_count = 0;

void eom_counter_init(int expected_eom) {
    expected_eom_count = expected_eom;
    current_eom_count = 0;
}

void eom_counter_inc(void) {
    current_eom_count++;
	printf("%d number of eoms received!, %d expected\n", current_eom_count, expected_eom_count);

    if (current_eom_count >= expected_eom_count && expected_eom_count > 0) {
        exit(0);
    }
}
