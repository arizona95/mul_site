all: mal_site

mal_site: mal_site.o
   gcc -o mal_site mal_site.o

mal_site.o: mal_site.c
   gcc -o mal_site.o -c mal_site.c

clean:
   rm -f *.o
