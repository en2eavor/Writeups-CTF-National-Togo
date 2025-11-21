#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 100

void win() {
    printf("\n🎉 Congratulations! You've found the hidden function!\n");
    printf("Here's your shell:\n");
    system("/bin/sh");
}

void play_game() {
    char username[BUFFER_SIZE];
    char girlfriend_name[BUFFER_SIZE];
    int secret_number;
    int guess;
    int choice;
    
    printf("=================================\n");
    printf("   Bienvenue au Jeu de Devinette!\n");
    printf("=================================\n\n");
    
    // Step 1: Ask for username
    printf("Entrez votre pseudo: ");
    fgets(username, BUFFER_SIZE, stdin);
    username[strcspn(username, "\n")] = 0; // Remove newline
    
    printf("\nBonjour %s! Commençons le jeu.\n\n", username);
    
    // Step 2: Number guessing game with time-based seed
    srand(time(NULL));
    secret_number = rand() % 100 + 1;
    
    printf("J'ai choisi un nombre entre 1 et 100.\n");
    printf("Devinez le nombre: ");
    scanf("%d", &guess);
    getchar(); // Clear newline
    
    if (guess != secret_number) {
        printf("Désolé! Le nombre était %d. Réessayez!\n", secret_number);
        return;
    }
    
    printf("\n🎉 Bravo! Vous avez deviné le nombre!\n\n");
    
    // Step 3: Menu options
    while (1) {
        printf("=================================\n");
        printf("Que voulez-vous faire?\n");
        printf("a) Quitter le jeu\n");
        printf("b) Continuer\n");
        printf("=================================\n");
        printf("Votre choix: ");
        
        char option[10];
        fgets(option, sizeof(option), stdin);
        
        if (option[0] == 'a' || option[0] == 'A') {
            printf("\nMerci d'avoir joué! Au revoir!\n");
            break;
        }
        else if (option[0] == 'b' || option[0] == 'B') {
            printf("\n--- Mode Continuer ---\n");
            printf("Entrez le nom de votre petite amie: ");
            
            // VULNERABILITY 1: gets() allows buffer overflow (up to 1000 chars)
            gets(girlfriend_name);
            
            printf("\n");
            // VULNERABILITY 2: Format string vulnerability
            // Using printf without format specifier
            printf(girlfriend_name);
            printf(" est belle!\n\n");
            
            printf("Adresse de girlfriend_name: %p\n", girlfriend_name);
        }
        else {
            printf("Option invalide! Veuillez choisir 'a' ou 'b'.\n\n");
        }
    }
}

int main() {
    // Disable buffering for better interaction
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    printf("Hidden win() function at: %p\n\n", win);
    
    play_game();
    
    return 0;
}
