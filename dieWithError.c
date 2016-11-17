#include <stdio.h>
#include <stdlib.h>
#include "dieWithError.h"

void DieWithError(char *errorMessage)
{
	fprintf(stderr,"%s\n", errorMessage);
	exit(1);
}
