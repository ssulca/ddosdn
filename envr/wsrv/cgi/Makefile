# @file Makefile
# @brief Makefile para la página web que hace cálculos de fibonacci.
# @author  Lopez Gastón, Sergio Sulca.

# usar tabulador (no espacios) en make
# Flags de compilacion:
# -Wall mostrará todos los avisos que produzca el compilador, no solamente los errores. 
#       Los avisos indican dónde y/o porqué podría surgir algún error en el programa.
# -pedantic aporta más información sobre los errores y los avisos mostrados por GCC.
# -Werror tratara a cualquier warning como si un error se tratase. 
# -std=gnu99 se escribe para el correcto funcionamiento en la Raspberry.
FLAGS = -O3 -march=native -mtune=native

all: fibo

fibo: fibo.c
	gcc -o fibo $(FLAGS) fibo.c -std=gnu99
clean:
	rm fibo

