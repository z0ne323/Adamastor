// List of header files
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

extern char **environ; 

int check_length_input(char *input_provided, int maximum_length) 
{
    /*
    Description:
        Check the length of the input provided by the player
    Parameters:
        input_provided (char *): Input provided to check the length out of it
        maximum_length (int): Maximum length authorized for the given input
    Returns:
        0 (int): Return 0 if the length is respected
        1 (int): Return 1 if the length exceed !
    */
    if (strlen(input_provided) > maximum_length) 
    {
        printf("[-] Invalid input length.\n");
        return 1;
    }
}

int obfuscate_function(char *obfuscated_target_argument) 
{
    /*
    Description:
        Obfuscating the string provided with "complex" mathematical operations (addition, multiplication and XOR)
    Parameters:
        obfuscated_target_argument (char *): Argument used to pass to the function the initial string that need to be obfuscated
    Returns:
        No returns
    */
    int obfuscated_target_argument_length = strlen(obfuscated_target_argument);
    for (int i = 0; i < obfuscated_target_argument_length; i++) 
    {
        int obfuscated_value = ((int)obfuscated_target_argument[i] + 5) * 3 ^ 0x10;  
        obfuscated_target_argument[i] = (char)((obfuscated_value % (126 - 32 + 1)) + 32); 
    }
    return 0;
}

char *get_input(void) 
{
    /*
    Description:
        Get our user input when needed
    Parameters:
        No parameters
    Returns:
        input_from_player (char *): used to store the string the player provided in input
    */
    char *input_from_player = (char *)malloc(49 * sizeof(char));

    if (input_from_player == NULL) 
    {
        fprintf(stderr, "[-] Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    scanf("%49s", input_from_player); 

    return input_from_player;
}

int check_environment_variable(const char *environment_variable_to_check) 
{
    /*
    Description:
        Check if the provided argument exist as an environment variable on the system
    Parameters:
        environment_variable_to_check (const char *): Parameters used to store the environment variable we need to check
    Returns:
        0 (int): Environment variable doesn't exist / Environment variable list is not available
        1 (int): Environment variable does exist
    */
    if (environ == NULL) 
    {
        printf("[-] Error: Environment variable list is not available.\n");
        return 0;
    }

    size_t provided_environment_variable_name_length = strlen(environment_variable_to_check);

    for (char **environment_variables_list = environ; *environment_variables_list != NULL; ++environment_variables_list) 
    {
        char *equal_sign = strchr(*environment_variables_list, '=');
        if (equal_sign == NULL) 
        {
            continue; 
        }

        size_t environment_variable_name_length = equal_sign - *environment_variables_list;

        if (environment_variable_name_length == provided_environment_variable_name_length &&
            strncmp(*environment_variables_list, environment_variable_to_check, environment_variable_name_length) == 0) 
        {
            return 1; 
        }
    }

    return 0;
}

int receive_data(const char *server_ip, int server_port, char *received_data, size_t maximum_length_received_data) 
{
    /*
    Description:
        Receiving our key later used in the last challenge from the server
    Parameters:
        server_ip (int): Server's IP to connect to
        server_port (int): Server's port to connect to
        received_data (char *): Buffer used to store the key the server is going to send us
        maximum_length_received_data (size_t): Maximum authorized length for received_data buffer
    Returns:
        No returns
    */
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) 
    {
        perror("[-] Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &(server_address.sin_addr));

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) 
    {
        perror("[-] Connection failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    ssize_t bytes_received = recv(client_socket, received_data, maximum_length_received_data - 1, 0);

    if (bytes_received == -1) 
    {
        perror("[-] Receive failed");
    } 
    else if (bytes_received == 0) 
    {
        printf("[-] Connection closed by the server\n");
    } 
    else 
    {
        received_data[bytes_received] = '\0';
    }

    close(client_socket);
    return 0;
}

char *guess_the_cipher_my_friend(char *ciphered_target_argument, const char *key_argument) 
{
    /*
    Description:
        Deciphering the string provided using Vigenere cipher
    Parameters:
        ciphered_target_argument (char *): Ciphered text provided to get deciphered
        key_argument (const char *): Key provided alongside the cipher text to get deciphered
    Returns:
        ciphered_target_argument (char *): Returning the deciphered string to main in our initial ciphered_target_argument variable
    */
    int ciphered_target_argument_length = strlen(ciphered_target_argument);
    int key_argument_length = strlen(key_argument);

    for (int i = 0; i < ciphered_target_argument_length; ++i) 
    {
        if (isalpha(ciphered_target_argument[i])) 
        {
            char base = islower(ciphered_target_argument[i]) ? 'a' : 'A';
            int diff = (ciphered_target_argument[i] - base - (tolower(key_argument[i % key_argument_length]) - 'a') + 26) % 26;
            ciphered_target_argument[i] = base + diff;
        }
    }

    return ciphered_target_argument;
}

int get_shell(void)
{
    /*
    Description:
        Prompt a root shell for the player when he passed all challenges
    Parameters:
        No parameters
    Returns:
        No returns
    */
    printf("[+] Finally you've arrived ! Welcome to the Cape of Good Hope: \n");
    setuid(0);
    system("/bin/sh");
    return 0;
}

int main(int argc, char *argv[]) 
{
    if (argc != 2) 
    {
        printf("[-] Usage: %s <hex_input>\n", argv[0]);
        return 1;
    }

    if (check_length_input(argv[1], 8) == 1) 
    {
        return 1;
    }

    int xor_user_input;

    if (sscanf(argv[1], "%x", &xor_user_input) != 1) 
    {
        printf("[-] Invalid hexadecimal input.\n");
        return 1;
    }

    int xor_result = xor_user_input ^ 0x12345678;

    if (xor_result == 0xDEADBEEF) 
    {
        printf("[+] Congratulations! You've passed the XOR challenge.\n");

        char obfuscated_target[] = "=28NQvkf0R"; 
        obfuscate_function(obfuscated_target);

        printf("[*] Now, provide an input for the second challenge: ");

        char *obfuscated_user_input = get_input();

        if (check_length_input(obfuscated_user_input, 10) == 1) 
        {
            return 1;
        }

        if (strncmp(obfuscated_user_input, obfuscated_target, 10) == 0) 
        {
            free(obfuscated_user_input);

            printf("[+] Well done! You've passed the obfuscation challenge.\n");

            const char *environment_variables_to_pass[] = {"DATA_DETAILS_01", "DATA_DETAILS_02"};
            size_t size_environment_variables = sizeof(environment_variables_to_pass) / sizeof(environment_variables_to_pass[0]);

            for (size_t i = 0; i < size_environment_variables; ++i) 
            {
                if (check_environment_variable(environment_variables_to_pass[i]) == 0)
                {
                    printf("[-] Environment variable %s does not exist.\n", environment_variables_to_pass[i]);
                    return 1;
                }
            }

            const char *server_ip = getenv(environment_variables_to_pass[0]); 
            int server_port = atoi(getenv(environment_variables_to_pass[1]));               

            if (server_ip == NULL || server_port == 0) 
            {
                printf("[-] Error: Environment variables not properly set.\n");
                return 1;
            }   

            char received_data[49];

            receive_data(server_ip, server_port, received_data, sizeof(received_data));

            char *key = received_data;

            char ciphered_target[] = "TkeeuhxfjAcjXaoJgfxkFhhHxhqGjtvrlst";

            char *deciphered_target = guess_the_cipher_my_friend(ciphered_target, key);

            printf("[*] Finally, provide an input for the last challenge: ");

            char *deciphered_user_input = get_input();

            if (check_length_input(deciphered_user_input, 35) == 1) 
            {
                return 1;
            }

            if (strncmp(deciphered_user_input, deciphered_target, 35) == 0) 
            {
                free(deciphered_user_input);
                printf("[+] Well done! You've passed the final challenge!\n");
                get_shell();
                char *our_next_adventure =  "⠀⠀⠀⠈⠉⠛⢷⣦⡀⠀⣀⣠⣤⠤⠄\n"
                                            "⠀⠀⠀⠀⠀⣀⣻⣿⣿⣿⣋⣀⡀⠀⠀⢀⣠⣤⣄⡀\n"
                                            "⠀⠀⠀⣠⠾⠛⠛⢻⣿⣿⣿⠟⠛⠛⠓⠢⠀⠀⠉⢿⣿⣆⣀⣠⣤⣀⣀\n"
                                            "⠀⠀⠘⠁⠀⠀⣰⡿⠛⠿⠿⣧⡀⠀⠀⢀⣤⣤⣤⣼⣿⣿⣿⡿⠟⠋⠉⠉\n"
                                            "⠀⠀⠀⠀⠀⠠⠋⠀⠀⠀⠀⠘⣷⡀⠀⠀⠀⠀⠹⣿⣿⣿⠟⠻⢶⣄\n"
                                            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⠀⠀⢠⡿⠁   ⠀⠀⠀⠈\n"
                                            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⠀⠀⢠⡟\n"
                                            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⣾⠁\n"
                                            "⠀⣤⣤⣤⣤⣤⣤⡤⠄⠀⠀⣀⡀⢸⡇⢠⣤⣁⣀⠀⠀⠠⢤⣤⣤⣤⣤⣤⣤\n"
                                            "⠀⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣷⣤⣤⣾⣿⣿⣿⣿⣷⣶⣤⣀\n"
                                            "⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄\n"
                                            "⠀⠀⠼⠿⣿⣿⠿⠛⠉⠉⠉⠙⠛⠿⣿⣿⠿⠛⠛⠛⠛⠿⢿⣿⣿⠿⠿⠇\n"
                                            "⠀⢶⣤⣀⣀⣠⣴⠶⠛⠋⠙⠻⣦⣄⣀⣀⣠⣤⣴⠶⠶⣦⣄⣀⣀⣠⣤⣤⡶\n"
                                            "⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠀⠉⠉⠉⠉\n"
                                            "      [*] Costa Rica...\n";

                printf("%s\n", our_next_adventure);
            }
            else
            {
                printf("[-] Try again! Wrong input: %s\n", deciphered_user_input);
                free(deciphered_user_input);
            }
        } 
        else 
        {
            printf("[-] Try again! Wrong input: %s\n", obfuscated_user_input);
            free(obfuscated_user_input);
        }

    } 
    else 
    {
        printf("[-] Try again! (XOR result: %X)\n", xor_result);
    }
    return 0;
}