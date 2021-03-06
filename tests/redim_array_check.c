#include <stdlib.h>
#include <assert.h>
#include "tools/redim_array.c"

static void check_empty(void)
{
	struct redim_array ra;
	assert(0 == redim_array_ctor(&ra, 5000, 1, __func__));
	assert(0 == ra.nb_entries);
	assert(0 == redim_array_foreach(&ra, NULL));
	redim_array_clear(&ra);
	redim_array_dtor(&ra);
}

static unsigned global_count = 0;
static int count(struct redim_array unused_ *ra, void unused_ *cell, va_list unused_ ap)
{
	global_count++;
	return 0;
}

static void check_stress(unsigned nb_entries)
{
	struct redim_array ra;
	assert(0 == redim_array_ctor(&ra, 1, sizeof(unsigned), __func__));

	// insert some entries
	for (unsigned e=0; e < nb_entries; e++) redim_array_push(&ra, &e);
	assert(nb_entries == ra.nb_entries);

	// pop them
	for (unsigned e=0; e < nb_entries; e++) redim_array_chop(&ra);
	assert(0 == ra.nb_entries);

	// reinsert
	for (unsigned e=0; e < nb_entries; e++) redim_array_push(&ra, &e);
	redim_array_clear(&ra);
	assert(0 == ra.nb_entries);

	// reinsert
	for (unsigned e=0; e < nb_entries; e++) redim_array_push(&ra, &e);
	global_count = 0;
	redim_array_foreach(&ra, count);
	assert(global_count == nb_entries);

	redim_array_dtor(&ra);
}

int main(void)
{
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("redim_array_check.log");

	check_empty();
	check_stress(10);

	return EXIT_SUCCESS;
}

