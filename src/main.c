#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

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

/// @brief Exit the program with a status code
/// @param status The status code to exit with
/// @return void
void print_and_quit(int status)
{
    printf("QUITTING!\n");
    exit(status);
}

int main()
{
    /// Buffer for a single LDAP search result
    unsigned char ldap_search_result_buf[sizeof(LDAPMessage *)];
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

    // TODO: Check to see if we're talking to AD or OpenLDAP
    // If we're talking to AD, we need to use the unicodePwd attribute
    // If we're talking to OpenLDAP, we need to use the userPassword attribute

    // This is AD:

    // The AD unicodePwd attribute is very fiddly. We'll need to do the following:
    // 1. Enclose the password in quotes
    // 2. Convert the password to UTF-16LE (No BOM)
    // 3. Send the password as a binary value in an LDAP modify operation

    // So, first, add the quotes.
    char *newpasswd_quoted = malloc(strlen(newpasswd) + 3); // 2 characters for the quotes, 1 for the null terminator
    newpasswd_quoted[0] = '"';
    strcpy(newpasswd_quoted + 1, newpasswd);
    newpasswd_quoted[strlen(newpasswd) + 1] = '"';
    newpasswd_quoted[strlen(newpasswd) + 2] = 0;

    // Then, convert the quoted password to UTF-16LE (No BOM)
    uint8_t *newpasswd_utf16le = malloc(strlen(newpasswd_quoted) * 2); // 2 bytes per character, no null terminator or BOM

    for (int i = 0; i < (int)strlen(newpasswd_quoted); i++)
    {
        newpasswd_utf16le[i * 2] = newpasswd_quoted[i];
        newpasswd_utf16le[i * 2 + 1] = 0;
    }

    struct berval passwd_berval = {
        .bv_len = strlen(newpasswd_quoted) * 2,
        .bv_val = (char *)newpasswd_utf16le,
    };

    // Change the password
    LDAPMod mod = {
        .mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, // Binary replacement operation
        .mod_type = "unicodePwd",
        .mod_vals.modv_bvals = (struct berval *[]){&passwd_berval, NULL},
    };

    LDAPMod *mods[] = {&mod, NULL};

    status = ldap_modify_ext_s(
        ld,
        user_dn,
        mods,
        NULL,
        NULL);

    printf("modify status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    status = ldap_unbind_s(ld);
    // printf("unbind status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }
}
