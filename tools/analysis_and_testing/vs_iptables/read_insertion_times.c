#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

void writeToFile(char *buf, char *filename) {
   FILE * fp;
   int i;

   fp = fopen (filename,"w");
 
	if(fp == NULL) {
		printf("File pointer is NULL\n");
		return;
	}

	fprintf (fp, "%s", buf);
 
   /* close the file*/  
   fclose (fp);
}

int main(int argc, char **argv) {

	long int len;
	char *buf, *filename;
	int n = 0;
  
	
	if(argc > 1) {
		filename = argv[1];
	} else {
		filename = "firewallOutput.txt";
	}
	//open the proc
	int f = open("/proc/firewallExtensionTest", O_RDONLY);
	if(f < 0){
		printf("ERROR: cannot open /proc/firewallExtension\n");
		return -1;
	}

	do {
		len = n+10;

 		buf = malloc((size_t)len);
		if(buf == NULL){
			printf("ERROR: malloc failed\n");
			return -1;
		}

		n = read(f, buf, len);
		if(n < 0){
			printf("ERROR: reading");
			close(f);
			return n;
		}

	} while (n != 0);
  

	//print
	//printf("BUFFER: %s\n", buf);

	writeToFile(buf, filename);
	free(buf);
 	close(f);
 	return 0;
}

