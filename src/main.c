#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

#include <curl/curl.h>

#include <ldap.h>
#include <lber.h>

// For some reason, these functions are not defined in the header file
//  Gosh, I hope I'm using buggy deprecated stuff.

/// Synchronous LDAP bind operation
int ldap_bind_s(LDAP *ld, const char *who, const char *cred, int method);

/// Synchronoud LDAP unbind operation
int ldap_unbind_s(LDAP *ld);

char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *attr);

void ldap_value_free(char **vals);

/// Global timeout for LDAP operations
struct timeval timeout = {
    .tv_sec = 5,
    .tv_usec = 0,
};

const char *service_account_cn = "service_account";

/// @brief Exit the program with a status code
/// @param status The status code to exit with
/// @return void
void print_and_quit(int status)
{
    printf("FAIL! Exit code: %d\n", status);
    exit(0);
    // exit(status);
}

/// @brief Create a password reset link and email it to the user
void email_user()
{
    // This is called as a cgi post request, so we need to read the username from the post data
    //  and then look up the user's email address in LDAP.
    // The post data should be supplied in stdin.

    // For now, just print stdin to stdout for debugging purposes.

    // Read the length of the post data from the environment.
    char *content_length_str = getenv("CONTENT_LENGTH");
    if (content_length_str == NULL)
    {
        printf("No content length\n");
        exit(1);
    }

    // Convert the content length to an integer
    int content_length = atoi(content_length_str);

    // Allocate a buffer to read the post data into
    char *post_data = malloc(content_length + 1);
    if (post_data == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }

    // Read the post data from stdin
    int bytes_read = fread(post_data, 1, content_length, stdin);
    if (bytes_read != content_length)
    {
        printf("Failed to read post data\n");
        exit(1);
    }

    // Null-terminate the post data
    post_data[content_length] = 0;

    // unescape the post data
    CURL *curl = curl_easy_init();
    if (curl == NULL)
    {
        printf("Failed to initialize curl\n");
        exit(1);
    }

    int post_data_decoded_len;
    char *post_data_decoded = curl_easy_unescape(curl, post_data, content_length, &post_data_decoded_len);
    if (post_data_decoded == NULL)
    {
        printf("Failed to decode post data\n");
        exit(1);
    }

    // Now, the post data is in the format "userid=<username>&ldap_uri=<server_uri>+<server_basedn>"
    //  We need to extract the username and the ldap_uri uri and base dn from this string.

    // Find the username
    char *username = strstr(post_data_decoded, "userid=");
    if (username == NULL)
    {
        printf("No username found\n");
        exit(1);
    }

    username += 7; // Skip past "userid="
    char *username_end = strchr(username, '&');
    if (username_end == NULL)
    {
        printf("No username end found\n");
        exit(1);
    }

    *username_end = 0; // Null-terminate the username

    // Find the server uri and base dn
    char *ldap_uri = strstr(username_end + 1, "server=");
    if (ldap_uri == NULL)
    {
        printf("No server found\n");
        exit(1);
    }

    ldap_uri += 7; // Skip past "ldap_uri="
    char *server_end = strchr(ldap_uri, '+');
    if (server_end == NULL)
    {
        printf("No server end found\n");
        exit(1);
    }

    *server_end = 0; // Null-terminate the server uri

    char *basedn = server_end + 1; // Skip past the '+'

    // Now, we have the username, server uri, and base dn.
    // We need to look up the user's email address in LDAP and send them a password reset link.

    printf("Finding user with the following details:\n");
    printf("username: %s\n", username);
    printf("server: %s\n", ldap_uri);
    printf("basedn: %s\n\n", basedn);

    // Now, we need to determine the bind dn and password for the service account.
    char *bind_dn = malloc(strlen("cn=") + strlen(service_account_cn) + strlen(",") + strlen(basedn) + 1);
    if (bind_dn == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }
    sprintf(bind_dn, "cn=%s,%s", service_account_cn, basedn);

    // The password lives in a file in the working directory called ".password.service_account"
    FILE *password_file = fopen(".password.service_account", "r");
    if (password_file == NULL)
    {
        printf("Failed to open password file\n");
        exit(1);
    }

    // Read one line from the password file
    char bind_pw[255];
    if (fgets(bind_pw, 255, password_file) == NULL)
    {
        printf("Failed to read password\n");
        exit(1);
    }

    // Remove the newline from the password
    char *newline = strchr(bind_pw, '\n');
    if (newline != NULL)
    {
        *newline = 0;
    }

    printf("Connecting to LDAP as %s\n", bind_dn);
    // Initialize the LDAP connection
    LDAP *ld;
    ldap_initialize(&ld, ldap_uri);

    // Bind to the server
    int status = ldap_bind_s(
        ld,
        bind_dn,
        bind_pw,
        LDAP_AUTH_SIMPLE);

    if (status != LDAP_SUCCESS)
    {
        printf("Failed to bind to LDAP\n");
        print_and_quit(status);
    }

    printf("Bind successful\n");

    /// Buffer for a single LDAP search result
    unsigned char ldap_search_result_buf[sizeof(LDAPMessage *)];
    LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

    char ldap_search_str[255] = {
        0,
    };

    snprintf(ldap_search_str, 255, "(SamAccountName=%s)", username); // TODO: maybe use dangerous sprintf

    status = ldap_search_ext_s(
        ld,
        basedn,
        LDAP_SCOPE_SUBTREE,
        ldap_search_str,
        (char *[]){"mail", NULL},
        0,
        NULL,
        NULL,
        &timeout,
        1,
        res);

    printf("search status: %d: %s\n", status, ldap_err2string(status));

    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    // Read the distinguishedName and store it as user_dn
    // char *user_dn = *ldap_get_values(ld, *res, "distinguishedName");
    // if (user_dn == NULL)
    // {
    //     printf("User not found\n");
    //     print_and_quit(1);
    // }
    // printf("user_dn: %s\n", user_dn);

    // Read the email address and store it as email
    printf("Getting email address\n");
    // char *email = *ldap_get_values(ld, *res, "mail");
    // printf("email: %s\n", email);
    // if (email == NULL)
    // {
    //     printf("Email not found\n");
    //     print_and_quit(1);
    // }
    // printf("email: %s\n", email);
}

/// @brief Set the password for a user via LDAP
void set_password()
{
}

void debug()
{
    /// Buffer for a single LDAP search result
    unsigned char ldap_search_result_buf[sizeof(LDAPMessage *) * 5];
    LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

    // Read environment variables to decide what to do
    const char *bind_dn = getenv("CPWD_BIND_DN");        // e.g. "cn=admin,dc=example,dc=com"
    const char *bind_pw = getenv("CPWD_BIND_PW");        // e.g. "password"
    const char *ldap_uri = getenv("CPWD_LDAP_URI");      // e.g. "ldap://localhost:389"
    const char *ldap_base = getenv("CPWD_LDAP_BASE");    // e.g. "dc=example,dc=com"
    const char *username = getenv("CPWD_USERNAME");      // e.g. "ldaptest"
    const char *newpasswd = getenv("CPWD_PASSWORD_NEW"); // e.g. "passwordAa1!";

    // Exit if any required environment variables are missing
    if (!bind_dn || !bind_pw || !ldap_uri || !ldap_base || !username || !newpasswd)
    {
        printf("Missing required environment variables\n");
        exit(1);
    }

    // Initialize the LDAP connection
    LDAP *ld;
    ldap_initialize(&ld, ldap_uri);

    // Bind to the server
    int status = ldap_bind_s(
        ld,
        bind_dn,
        bind_pw,
        LDAP_AUTH_SIMPLE);

    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    char ldap_search_str[255] = {
        0,
    };

    snprintf(ldap_search_str, 255, "(SamAccountName=%s)", username); // TODO: maybe use dangerous sprintf

    status = ldap_search_ext_s(
        ld,
        ldap_base,
        LDAP_SCOPE_SUBTREE,
        ldap_search_str,
        (char *[]){"distinguishedName", "mail", NULL},
        0,
        NULL,
        NULL,
        &timeout,
        1,
        res);

    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    // Read the distinguishedName and store it as user_dn
    char *user_dn = *ldap_get_values(ld, *res, "distinguishedName");
    printf("user_dn: %s\n", user_dn);
    if (user_dn == NULL)
    {
        printf("User not found\n");
        print_and_quit(1);
    }

    // Read the email address and store it as email
    // char *email = *ldap_get_values(ld, *res, "mail");
    // if (email == NULL)
    // {
    //     printf("Email not found\n");
    //     print_and_quit(1);
    // }

    // // TODO: Check to see if we're talking to AD or OpenLDAP
    // // If we're talking to AD, we need to use the unicodePwd attribute
    // // If we're talking to OpenLDAP, we need to use the userPassword attribute

    // // This is AD:

    // // The AD unicodePwd attribute is very fiddly. We'll need to do the following:
    // // 1. Enclose the password in quotes
    // // 2. Convert the password to UTF-16LE (No BOM)
    // // 3. Send the password as a binary value in an LDAP modify operation

    // // So, first, add the quotes.
    // char *newpasswd_quoted = malloc(strlen(newpasswd) + 3); // 2 characters for the quotes, 1 for the null terminator
    // newpasswd_quoted[0] = '"';
    // strcpy(newpasswd_quoted + 1, newpasswd);
    // newpasswd_quoted[strlen(newpasswd) + 1] = '"';
    // newpasswd_quoted[strlen(newpasswd) + 2] = 0;

    // // Then, convert the quoted password to UTF-16LE (No BOM)
    // uint8_t *newpasswd_utf16le = malloc(strlen(newpasswd_quoted) * 2); // 2 bytes per character, no null terminator or BOM

    // for (int i = 0; i < (int)strlen(newpasswd_quoted); i++)
    // {
    //     newpasswd_utf16le[i * 2] = newpasswd_quoted[i];
    //     newpasswd_utf16le[i * 2 + 1] = 0;
    // }

    // struct berval passwd_berval = {
    //     .bv_len = strlen(newpasswd_quoted) * 2,
    //     .bv_val = (char *)newpasswd_utf16le,
    // };

    // // Change the password
    // LDAPMod mod = {
    //     .mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, // Binary replacement operation
    //     .mod_type = "unicodePwd",
    //     .mod_vals.modv_bvals = (struct berval *[]){&passwd_berval, NULL},
    // };

    // LDAPMod *mods[] = {&mod, NULL};

    // status = ldap_modify_ext_s(
    //     ld,
    //     user_dn,
    //     mods,
    //     NULL,
    //     NULL);

    // printf("modify status: %d: %s\n", status, ldap_err2string(status));
    // if (status != LDAP_SUCCESS)
    // {
    //     print_and_quit(status);
    // }

    status = ldap_unbind_s(ld);
    // printf("unbind status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }
}

int main(int argc, char **argv)
{

    printf("Content-Type: text/plain;charset=us-ascii\n\n");

    // This program operates based on a bunch of symlinks to the actual binary.
    // If the binary is called as "email-user", it will email the user a password reset link by
    //  calling the function email_user().
    // If the binary is called as `set-password`, it will generate a new password for the user,
    //  set it via LDAP, and display the new password to the user.
    // If the binary is called as anything else, it will print an error message and exit???

    if (argc != 1)
    {
        printf("Invalid number of arguments\n");
        exit(1);
    }

    // Check to see if the binary was called as a command that ends with "email-user" or "set-password"
    if (strstr(argv[0], "email-user") != NULL)
    {
        email_user();
    }
    else if (strstr(argv[0], "set-password") != NULL)
    {
        set_password();
    }
    else if (strstr(argv[0], "crappasswd") != NULL)
    {
        debug();
    }
    else
    {
        printf("Invalid command\n");
        exit(1);
    }
}
