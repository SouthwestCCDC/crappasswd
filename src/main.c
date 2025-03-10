#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <ldap.h>

// For some reason, these functions are not defined in the header file
//  Gosh, I hope I'm using buggy deprecated stuff.

/// Synchronous LDAP bind operation
int ldap_bind_s(LDAP *ld, const char *who, const char *cred, int method);

/// Synchronoud LDAP unbind operation
int ldap_unbind_s(LDAP *ld);

char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *attr);

void ldap_value_free(char **vals);

/// Buffer for a single LDAP search result
unsigned char ldap_search_result_buf[sizeof(LDAPMessage *)];
LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

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

    // TODO: Remove?
    printf("bind status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    char ldap_search_str[255] = {
        0,
    };

    snprintf(ldap_search_str, 255, "(sAMAccountName=%s)", username); // TODO: maybe use dangerous sprintf

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

    printf("search status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    // Read the distinguishedName and store it as user_dn
    char *user_dn = *ldap_get_values(ld, *res, "distinguishedName");
    if (user_dn == NULL)
    {
        printf("User not found\n");
        print_and_quit(1);
    }
    printf("user_dn: %s\n", user_dn);

    // Change the password
    LDAPMod mod = {
        .mod_op = LDAP_MOD_REPLACE,
        .mod_type = "unicodePwd",
        .mod_vals.modv_strvals = (char *[]){(char *)newpasswd, NULL},
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

    // Clean up:

    // Free the memory allocated by ldap_get_values
    ldap_value_free(&user_dn);

    status = ldap_unbind_s(ld);
    printf("unbind status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }
}
