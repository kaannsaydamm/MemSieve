#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// MemSieve Vault: A dummy "secure" storage application for fuzzing practice.
// Vulnerabilities: Stack Overflow, Heap Overflow, Format String, Null
// Dereference

void banner() {
  printf("======================================\n");
  printf("      MemSieve Vault v1.0 (SECURE)    \n");
  printf("======================================\n");
}

void log_activity(char *msg) {
  printf("[LOG] ");
  // VULNERABILITY: Format String Bug
  // If msg contains format specifiers like %x, %s, %n, printf will parse them.
  printf(msg);
  printf("\n");
}

void process_store(char *data) {
  char buffer[64];
  printf("[*] Processing STORE command...\n");

  // VULNERABILITY: Stack Buffer Overflow
  // Using strcpy without checking if data length > 64
  strcpy(buffer, data);

  printf("[+] Stored %lu bytes secure in stack.\n", strlen(buffer));
}

void process_read(char *data) {
  printf("[*] Processing READ command...\n");

  // Allocate small chunk
  char *heap_buf = (char *)malloc(64);
  if (!heap_buf)
    return;

  // VULNERABILITY: Heap Overflow
  // If data starts with "RAW:", we copy blindly.
  if (strncmp(data, "RAW:", 4) == 0) {
    // Overflow heap chunk
    strcpy(heap_buf, data + 4);
  } else {
    strncpy(heap_buf, data, 63);
    heap_buf[63] = '\0';
  }

  printf("[+] Read from heap: %s\n", heap_buf);
  free(heap_buf);
}

void process_admin(char *data) {
  printf("[*] Checking Admin Credentials...\n");

  // VULNERABILITY: Null Pointer Dereference
  // Magic backdoor password triggers crash
  if (strcmp(data, "root123") == 0) {
    printf("[!] Access Granted! (Not really)\n");
    int *p = NULL;
    *p = 1337; // CRASH
  } else {
    printf("[-] Access Denied.\n");
  }
}

int main(int argc, char **argv) {
  banner();
  if (argc < 2) {
    printf("Usage: %s <command_string>\n", argv[0]);
    printf("Commands:\n");
    printf("  STORE:<data>  - Store data securely\n");
    printf("  READ:<key>    - Read data\n");
    printf("  ADMIN:<pass>  - Admin login\n");
    return 1;
  }

  char *input = argv[1];

  // Command Dispatcher
  if (strncmp(input, "STORE:", 6) == 0) {
    process_store(input + 6);
  } else if (strncmp(input, "READ:", 5) == 0) {
    process_read(input + 5);
  } else if (strncmp(input, "ADMIN:", 6) == 0) {
    process_admin(input + 6);
  } else {
    // VULNERABILITY PATH: Format String
    // Construct error message and log it
    char log_buf[512];
    snprintf(log_buf, sizeof(log_buf) - 1, "Unknown command: %s", input);
    log_activity(log_buf);
  }

  return 0;
}
