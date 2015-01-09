#include <data.h>

off_t fsize(const char *filename)
{
    struct stat st;

    if (stat(filename, &st) == 0)
        return st.st_size;

    fprintf(stderr, "Cannot determine size of %s: %s\n",
            filename, strerror(errno));

    return -1;
}

int load_file(   const char   *filename,
               unsigned char  **array,
               unsigned long   *size)
{
  FILE *fpIn;
  unsigned int tmp;

  *size = fsize(filename);
  if (*size == -1) return -1;
  *array = malloc(*size);
  fpIn = fopen(filename, "r");

  for(unsigned long i=0; i<*size; i++) {
    fscanf(fpIn, "%02x", &tmp);
    (*array)[i] = (unsigned char)tmp;
  }

  fclose(fpIn);
  return 0;
}