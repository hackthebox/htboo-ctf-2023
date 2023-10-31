#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RED           "\e[1;31m"
#define GREEN         "\e[1;32m"
#define YELLOW        "\e[1;33m"
#define BLUE          "\e[1;34m"
#define MAGENTA       "\e[1;35m"
#define CYAN          "\e[1;36m"
#define LIGHT_GRAY    "\e[1;37m"
#define RESET         "\e[0m"
#define SIZE 64

// ANSI escape codes for cursor movement
#define MOVE_UP(n) printf("\033[%dA", (n))
#define MOVE_DOWN(n) printf("\033[%dB", (n))
#define MOVE_RIGHT(n) printf("\033[%dC", (n))
#define MOVE_LEFT(n) printf("\033[%dD", (n))

size_t X = 13, Y = 15;

/*
* Compile a program with older libc:
 docker run -v "${PWD}:/mnt" -it debian:latest bash
 apt update; apt install -y gcc make vim gdb tmux && cd /mnt
*/

void cls(){
  printf("\033[2J");
  printf("\033[%d;%dH", 0, 0);
}

void read_flag(){
  char c;
  int fp = open("./flag.txt", O_RDONLY);
  if (fp < 0){
    perror("\nError opening flag.txt, please contact an Administrator.\n");
    exit(EXIT_FAILURE);
  }
  while ( read(fp, &c, 1) > 0 )
    fprintf(stdout, "%c", c);
  close(fp);
}

unsigned long int read_num(){
  char temp[32] = {0};
  read(0, temp, 31);
  return strtoul(temp, 0x0, 0);
}

void printstr(char *s, size_t check){
  for (size_t i = 0; i < strlen(s); i++){
    putchar(s[i]);
    usleep(15000);
  }
  if (check){
    for (size_t i = 0; i < strlen(s); i++){
      putchar('\b');
      putchar(' ');       // Overwrite with a space
      putchar('\b');      // Move cursor back again
      fflush(stdout);
      usleep(15000);
    }
  }
}

void banner(void){
  puts(CYAN);
  cls();
  printf(
    "▛▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▜\n"
    "▌▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▓▒▐\n"
    "▌▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▐\n"
    "█            |             █\n"
    "█            |             █\n"
    "█            |             █\n"
    "█         /▔▔ ▔▔\\          █\n"
    "█        |       |         █\n"
    "█         \\     /          █\n"
    "█                          █\n"
    "█                          █\n"
    "█        __________        █\n"
    "█        |flag.txt|        █\n"
    "████████████████████████████\n\n"
    );
}

void moves(){
  for (;;){
    size_t m;
    printf("Press '1' to move left, '2' to move right, '9' to grab the prize!\n\n>> ");
    m = read_num();
    // Move to the left
    if (m == 1){
      if (X > 7){
        MOVE_UP(Y);
        MOVE_RIGHT(X-1);
        // Move rope
        for (size_t i = 0; i < 3; i++){
          printf("| ");
          MOVE_DOWN(1);
          MOVE_LEFT(2); 
        }
        MOVE_LEFT(3);
        printf("/▔▔ ▔▔\\ ");  

        MOVE_DOWN(1);
        MOVE_LEFT(9);
        printf("|       | ");

        MOVE_DOWN(1);
        MOVE_LEFT(9);
        printf("\\     / ");
        MOVE_DOWN(7);    
        X--;
        printf("\r");
      }
      else {
        MOVE_UP(3);
        printf("\r");
      }
    }
    // Move to the right
    else if (m == 2){
      if (X < 20){
        MOVE_UP(Y);
        MOVE_RIGHT(X);
        // Move rope
        for (size_t i = 0; i < 3; i++){
          printf(" |");
          MOVE_DOWN(1);
          MOVE_LEFT(2); 
        }
        MOVE_LEFT(3);
        printf(" /▔▔ ▔▔\\ ");  

        MOVE_DOWN(1);
        MOVE_LEFT(10);
        printf(" |       | ");

        MOVE_DOWN(1);
        MOVE_LEFT(10);
        printf(" \\     / ");
        MOVE_DOWN(7);    
        X++;
        printf("\r");
      } 
      else {
        MOVE_UP(3);
        printf("\r");
      }
    }
    else if (m == 9){
      MOVE_UP(Y-3);
      MOVE_RIGHT(X-3);
      printf("   |   ");
      usleep(17000);
      MOVE_DOWN(1);
      MOVE_LEFT(8);
      printf("    |      ");
      usleep(17000);
      MOVE_DOWN(1);
      MOVE_LEFT(11);
      printf("    |    ");
      MOVE_DOWN(1);
      MOVE_LEFT(8);
      usleep(17000);
      printf("/▔▔ ▔▔\\ ");
      MOVE_DOWN(1);
      MOVE_LEFT(9);
      usleep(17000);
      printf("|       | ");
      MOVE_DOWN(1);
      MOVE_LEFT(10);
      printf(" \\     /  ");
      MOVE_DOWN(4);
      printf("\x1b[2K\r%s[-] You broke the box and couldn't get the prize!\n\n%s", RED, CYAN);
      break;
    }
    else {
      MOVE_UP(3);
      printf("\r");
    }
  }
}

void fb(){
  char ans[3] = {0};
  char name[0x11] = {0};
  char feedback[SIZE] = {0};
  printf("Would you like to rate our game? (y/n)\n\n>> ");
  read(0, ans, 2);
  if (ans[0] == 'y' || ans[0] == 'Y'){
    printf("\nEnter your name: ");
    read(0, name, 0x10);
    printf("\nThank you for giving feedback ");
    printf(name);
    printf("\nLeave your feedback here: ");
    read(0, feedback, SIZE + 0x1e);
  }
  printf("\nThank you for playing!\n\n");
} 

void setup(void){
  setvbuf(stdin,  NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(0x7f);	
}

int main(void){
  setup();
  banner();
  moves();
  fb();
  return 0;
}