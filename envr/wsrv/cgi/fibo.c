#include <stdio.h>
#include <stdlib.h>

int fibonacci(int n)
{
  if (n>2)
    return fibonacci(n-1) + fibonacci(n-2);
  else if (n==2)
    return 1;
  else if (n==1)       
    return 1;
  else if (n==0)
    return 0;
  else
	return -1;
}

int main(void)
{
    int num;

    for (num = 0; num <= 36; num++)
    {
      printf("%d\n", fibonacci(num));
    }
   
  return 0;
}
