/*
 * kow-keyd — the keychain client for keys-on-the-wire.
 *
 * WHY THIS EXISTS AT ALL
 *
 * A macOS keychain item's access control binds to the *code identity* of the
 * process that created it. kow is distributed through PyPI and Homebrew, so
 * kow's process is `python3.13` — an unsigned interpreter shared with every
 * other script on the machine. Granting keychain access to "kow" would
 * therefore grant it to any Python script an agent can write, which is the
 * precise hole this program closes: a small, separately signed binary that is
 * not an interpreter, so its code identity means something.
 *
 * It is a short-lived helper, exec'd once per operation, NOT a daemon. A daemon
 * would need a socket, and any process running as the same user could connect
 * to that socket — a second door into the same room. There is no same-uid peer
 * authentication on macOS worth the name, so the design does not pretend to
 * offer one. What it offers is exactly this: the keychain answers *this binary*
 * and refuses everything else.
 *
 * TWO BACKENDS, ONE BINARY
 *
 *   file-based keychain (default) — works with ANY signing identity, including
 *       a self-signed certificate you generate yourself. Access is an ACL
 *       naming this binary's designated requirement. A non-listed process gets
 *       a prompt, or a clean refusal when UI is suppressed.
 *
 *   data-protection keychain (--data-protection) — requires a Team ID and a
 *       keychain-access-groups entitlement, i.e. an Apple Developer Program
 *       membership. Strictly stronger: it is ACL-free, so there is no prompt at
 *       all and therefore no "Always Allow" dialog for an attacker to social-
 *       engineer, and /usr/bin/security cannot reach it by any means.
 *
 * The value NEVER travels on argv: the macOS process table is world-readable,
 * so a credential on a command line is a credential published to every local
 * user. `set` reads it from stdin; `get` writes it to stdout.
 *
 * Build:  sh helper/build.sh
 * Usage:  kow-keyd get|set|replace|delete|list --service S [--account A]
 *                  [--keychain PATH] [--data-protection] [--access-group G]
 *
 * WHAT THIS IS NOT (ADR-0051)
 *
 * Not an access boundary against a same-UID attacker. The ACL on an item names
 * this binary's code identity, and anyone who can run this binary satisfies it
 * — there is no caller authentication here and there cannot be one. Treat this
 * as a binary-safe transport. The security boundary is the macOS user account,
 * exactly as ADR-0046 says.
 *
 * Exit codes are the contract with the Python caller:
 *   0   ok
 *   1   failure (message on stderr)
 *   2   usage error
 *   44  item not found        (errSecItemNotFound, matching security(1))
 *   51  interaction required  (errSecInteractionNotAllowed — locked keychain,
 *                              or a caller this item's ACL does not list)
 *   34  missing entitlement   (errSecMissingEntitlement, -34018 — the binary is
 *                              unsigned or lacks the access group)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* SecAccessCreate and SecTrustedApplicationCreateFromPath are deprecated as of
 * macOS 10.15 with no replacement — Apple's position is that the whole
 * file-keychain ACL concept is legacy, and the data-protection keychain is the
 * successor. We use them deliberately on the file-keychain path because they
 * are the only way to express "only this binary" without a Team ID, and that
 * path exists precisely for people who do not have one. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

#define EXIT_FAIL 1
#define EXIT_USAGE 2
#define EXIT_MISSING_ENTITLEMENT 34
#define EXIT_NOT_FOUND 44
#define EXIT_INTERACTION 51

#define SERVICE_LABEL "keys-on-the-wire"

struct opts {
    const char *verb;
    const char *service;
    const char *account;
    const char *keychain;
    const char *access_group;
    int data_protection;
};

static CFStringRef cfstr(const char *s) {
    return CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
}

static void warn_status(const char *doing, OSStatus st) {
    CFStringRef msg = SecCopyErrorMessageString(st, NULL);
    char buf[512];
    if (msg && CFStringGetCString(msg, buf, sizeof buf, kCFStringEncodingUTF8)) {
        fprintf(stderr, "kow-keyd: %s failed (%d): %s\n", doing, (int)st, buf);
    } else {
        fprintf(stderr, "kow-keyd: %s failed (%d)\n", doing, (int)st);
    }
    if (msg) CFRelease(msg);
}

/* Map an OSStatus to this program's exit-code contract. The three special
 * cases are the ones the caller must be able to tell apart: "no such item" is a
 * different fact from "the keychain would not answer", which is different again
 * from "this binary is not entitled". */
static int status_to_exit(OSStatus st) {
    switch (st) {
        case errSecItemNotFound:          return EXIT_NOT_FOUND;
        case errSecInteractionNotAllowed: return EXIT_INTERACTION;
        case errSecInteractionRequired:   return EXIT_INTERACTION;
        /* errSecAuthFailed (-25293) is the SAME fact reached by a different
         * route: macOS returns it when interaction has been disabled explicitly
         * (which main() does), where a process with no session instead gets
         * errSecInteractionNotAllowed (-25308). Both mean "this caller is not
         * authorised for this item". Mapping only the second one made an
         * ACL denial arrive at the caller as a generic exit 1, so kow reported
         * "kow-keyd failed (exit 1)" instead of naming the legacy ACL and
         * telling the operator to re-add the secret. Found on a real Mac by
         * tests/vm-e2e/macos-keyd-e2e.sh step 12c; the deny-probes further up
         * that same file had already documented the two-status behaviour. */
        case errSecAuthFailed:            return EXIT_INTERACTION;
        case errSecMissingEntitlement:    return EXIT_MISSING_ENTITLEMENT;
        default:                          return EXIT_FAIL;
    }
}

/* Read every byte of stdin. The credential arrives here rather than on argv,
 * which is the whole point — argv is world-readable through the process table.
 * Binary-safe: a NUL in the value is preserved, unlike the security(1) path. */
static int read_all_stdin(unsigned char **out, size_t *out_len) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return -1;
    for (;;) {
        if (len == cap) {
            size_t ncap = cap * 2;
            /* A credential is not megabytes. A runaway pipe is a bug or an
             * attack, not a secret; refuse rather than exhaust memory. */
            if (ncap > (1u << 20)) { free(buf); return -1; }
            unsigned char *n = realloc(buf, ncap);
            if (!n) { free(buf); return -1; }
            buf = n; cap = ncap;
        }
        ssize_t r = read(STDIN_FILENO, buf + len, cap - len);
        if (r < 0) { free(buf); return -1; }
        if (r == 0) break;
        len += (size_t)r;
    }
    *out = buf; *out_len = len;
    return 0;
}

/* Open an explicit keychain file, or NULL for the user's default (login). */
static SecKeychainRef open_keychain(const struct opts *o, OSStatus *st) {
    *st = errSecSuccess;
    if (!o->keychain) return NULL;
    SecKeychainRef kc = NULL;
    *st = SecKeychainOpen(o->keychain, &kc);
    return kc;
}

/* An access object whose ACL lists exactly one trusted application: this
 * binary. Passing NULL as the path means "the calling process", so the ACL
 * records OUR designated requirement — which is stable across rebuilds as long
 * as the signing certificate stays the same. That stability is the entire
 * mechanism; an ad-hoc signature changes every build and would re-prompt
 * forever.
 *
 * NOTE: an item's ACL can only be set at creation — macOS requires user
 * interaction to change one afterwards, by design. That is a fact about the
 * ACL, not about the data: `set` updates kSecValueData in place on an existing
 * item and only creates one when it is absent, because an item this binary
 * already owns already has the ACL below. See do_write. */
static OSStatus make_self_only_access(SecAccessRef *out) {
    SecTrustedApplicationRef self = NULL;
    OSStatus st = SecTrustedApplicationCreateFromPath(NULL, &self);
    if (st != errSecSuccess) return st;
    CFArrayRef apps = CFArrayCreate(NULL, (const void **)&self, 1, &kCFTypeArrayCallBacks);
    CFStringRef label = CFSTR(SERVICE_LABEL);
    st = SecAccessCreate(label, apps, out);
    CFRelease(apps);
    CFRelease(self);
    return st;
}

/* Common query scaffolding: class + service (+ account), and whichever keychain
 * selector this build is using. */
static CFMutableDictionaryRef base_query(const struct opts *o, SecKeychainRef kc) {
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);

    CFStringRef svc = cfstr(o->service);
    CFDictionarySetValue(q, kSecAttrService, svc);
    CFRelease(svc);

    if (o->account) {
        CFStringRef acct = cfstr(o->account);
        CFDictionarySetValue(q, kSecAttrAccount, acct);
        CFRelease(acct);
    }

    if (o->data_protection) {
        CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
        if (o->access_group) {
            CFStringRef ag = cfstr(o->access_group);
            CFDictionarySetValue(q, kSecAttrAccessGroup, ag);
            CFRelease(ag);
        }
    } else if (kc) {
        /* Legacy search list: restrict lookups to the named keychain so a
         * same-named item in the login keychain can never be read by mistake. */
        CFArrayRef list = CFArrayCreate(NULL, (const void **)&kc, 1, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(q, kSecMatchSearchList, list);
        CFRelease(list);
    }
    return q;
}

static int do_get(const struct opts *o, SecKeychainRef kc) {
    CFMutableDictionaryRef q = base_query(o, kc);
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching(q, &result);
    CFRelease(q);
    if (st != errSecSuccess) {
        warn_status("read", st);
        return status_to_exit(st);
    }
    CFDataRef data = (CFDataRef)result;
    const UInt8 *bytes = CFDataGetBytePtr(data);
    CFIndex n = CFDataGetLength(data);
    /* Raw bytes, no trailing newline: the caller reads to EOF, so a value that
     * legitimately ends in whitespace survives intact. security(1) appends a
     * newline here and every caller has to remember to strip exactly one. */
    ssize_t w = write(STDOUT_FILENO, bytes, (size_t)n);
    CFRelease(result);
    if (w != (ssize_t)n) {
        fprintf(stderr, "kow-keyd: short write to stdout\n");
        return EXIT_FAIL;
    }
    return 0;
}

static int do_delete_quiet(const struct opts *o, SecKeychainRef kc, OSStatus *st_out) {
    CFMutableDictionaryRef q = base_query(o, kc);
    OSStatus st = SecItemDelete(q);
    CFRelease(q);
    if (st_out) *st_out = st;
    return (st == errSecSuccess || st == errSecItemNotFound) ? 0 : status_to_exit(st);
}

static int do_delete(const struct opts *o, SecKeychainRef kc) {
    OSStatus st = errSecSuccess;
    int rc = do_delete_quiet(o, kc, &st);
    /* Absent item is a no-op, so delete is idempotent — the caller can use it
     * to guarantee a clean slate without racing. */
    if (rc != 0) warn_status("delete", st);
    return rc;
}

/* Change an existing item's data, leaving its ACL alone.
 *
 * ADR-0051: this is what `set` does when the item is already there, and the
 * reason is that the alternative destroys credentials. Delete-then-add opens a
 * window in which the item does not exist, so a crash, a timeout, a failed ACL
 * construction or a failed SecItemAdd between the two steps leaves the operator
 * with NO value — and the caller's read-back detects that only after it is
 * irreversible. In-place update has no such window.
 *
 * The ACL is not touched because it does not need to be: an item this binary
 * already owns already has the ACL we want. An item owned by something else
 * cannot be updated without authorisation, so this returns
 * errSecInteractionNotAllowed and the caller is told how to migrate it —
 * which is the honest outcome, not a silent downgrade of the item's access.
 *
 * Returns the raw OSStatus so do_write can tell errSecItemNotFound ("create it
 * instead") from every other failure. An earlier version asked a boolean
 * item_exists() first, which folded authentication, interaction, parameter and
 * database errors all into "absent" and then tried to CREATE the item — turning
 * a reportable failure into a spurious add. */
static OSStatus update_in_place(const struct opts *o, SecKeychainRef kc,
                                const unsigned char *val, size_t len) {
    CFMutableDictionaryRef q = base_query(o, kc);
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef data = CFDataCreate(NULL, val, (CFIndex)len);
    if (!q || !attrs || !data) {
        if (q) CFRelease(q);
        if (attrs) CFRelease(attrs);
        if (data) CFRelease(data);
        return errSecAllocate;
    }
    CFDictionarySetValue(attrs, kSecValueData, data);

    OSStatus st = SecItemUpdate(q, attrs);

    CFRelease(data);
    CFRelease(attrs);
    CFRelease(q);
    return st;
}

/* `replace` is 1 only for the explicit migration verb, which recreates the item
 * so the ACL becomes ours. `set` never takes that path on its own. */
static int do_write(const struct opts *o, SecKeychainRef kc, int replace) {
    unsigned char *val = NULL;
    size_t len = 0;
    if (read_all_stdin(&val, &len) != 0) {
        fprintf(stderr, "kow-keyd: could not read the value from stdin\n");
        return EXIT_FAIL;
    }

    if (replace) {
        /* The deletion's status is CHECKED, not discarded. A failed delete
         * followed by an add produces a duplicate, which makes every later
         * first-match operation ambiguous. */
        OSStatus dst = errSecSuccess;
        int drc = do_delete_quiet(o, kc, &dst);
        if (drc != 0) {
            warn_status("delete before replace", dst);
            memset(val, 0, len); free(val);
            return drc;
        }
    } else {
        /* Try the update FIRST and let the keychain answer the existence
         * question. Only errSecItemNotFound means "create it"; every other
         * status is a real failure and is reported as one. */
        OSStatus ust = update_in_place(o, kc, val, len);
        if (ust == errSecSuccess) {
            memset(val, 0, len); free(val);
            return 0;
        }
        if (ust != errSecItemNotFound) {
            warn_status("update", ust);
            memset(val, 0, len); free(val);
            return status_to_exit(ust);
        }
        /* Absent. Fall through to SecItemAdd below. */
    }

    CFMutableDictionaryRef q = base_query(o, kc);
    CFDataRef data = CFDataCreate(NULL, val, (CFIndex)len);
    CFDictionarySetValue(q, kSecValueData, data);

    SecAccessRef access = NULL;
    OSStatus st;
    if (o->data_protection) {
        /* AfterFirstUnlock, not WhenUnlocked: kow runs as a LaunchAgent and
         * must keep serving when the screen is locked. ThisDeviceOnly keeps the
         * item off iCloud — the credential belongs to this machine. */
        CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
    } else {
        st = make_self_only_access(&access);
        if (st != errSecSuccess) {
            warn_status("building the access list", st);
            CFRelease(data); CFRelease(q);
            memset(val, 0, len); free(val);
            return status_to_exit(st);
        }
        CFDictionarySetValue(q, kSecAttrAccess, access);
        if (kc) CFDictionarySetValue(q, kSecUseKeychain, kc);
    }

    st = SecItemAdd(q, NULL);

    CFRelease(data);
    CFRelease(q);
    if (access) CFRelease(access);
    /* Wipe our copy before returning it to the allocator. Not a strong
     * guarantee — the kernel may have paged it — but it costs nothing. */
    memset(val, 0, len);
    free(val);

    if (st != errSecSuccess) {
        warn_status("write", st);
        return status_to_exit(st);
    }
    return 0;
}

static int do_list(const struct opts *o, SecKeychainRef kc) {
    struct opts scoped = *o;
    scoped.account = NULL; /* list every account under this service */
    CFMutableDictionaryRef q = base_query(&scoped, kc);
    CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching(q, &result);
    CFRelease(q);
    if (st == errSecItemNotFound) return 0; /* empty is not an error */
    if (st != errSecSuccess) {
        warn_status("enumerate", st);
        return status_to_exit(st);
    }

    CFArrayRef items = (CFArrayRef)result;
    CFIndex count = CFArrayGetCount(items);
    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef item = CFArrayGetValueAtIndex(items, i);
        CFStringRef acct = CFDictionaryGetValue(item, kSecAttrAccount);
        if (!acct) continue;
        /* Sized from the string, not a fixed 512 bytes. A name that did not fit
         * used to be skipped SILENTLY, which made the caller's pre-write
         * duplicate count read as zero for exactly the item it was checking —
         * a false all-clear. Now enumeration either renders every name or
         * fails visibly. */
        CFIndex cap = CFStringGetMaximumSizeForEncoding(
                          CFStringGetLength(acct), kCFStringEncodingUTF8) + 1;
        char *buf = malloc((size_t)cap);
        if (!buf || !CFStringGetCString(acct, buf, cap, kCFStringEncodingUTF8)) {
            free(buf);
            CFRelease(result);
            fprintf(stderr, "kow-keyd: could not render an account name; refusing to "
                            "report a partial list\n");
            return EXIT_FAIL;
        }
        printf("%s\n", buf);
        free(buf);
    }
    CFRelease(result);
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "usage: kow-keyd get|set|replace|delete|list --service S [--account A]\n"
        "                [--keychain PATH] [--data-protection] [--access-group G]\n"
        "\n"
        "  set reads the value from stdin; get writes it to stdout.\n"
        "  The value never appears on argv.\n"
        "\n"
        "  set      updates an existing item in place, creates it when absent.\n"
        "  replace  deletes and recreates, so the new item's ACL is this binary's.\n"
        "           Only for migrating an item written by something else; it has a\n"
        "           window in which the credential does not exist.\n");
}

int main(int argc, char **argv) {
    struct opts o = {0};
    if (argc < 2) { usage(); return EXIT_USAGE; }
    o.verb = argv[1];

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--service") && i + 1 < argc)           o.service = argv[++i];
        else if (!strcmp(argv[i], "--account") && i + 1 < argc)      o.account = argv[++i];
        else if (!strcmp(argv[i], "--keychain") && i + 1 < argc)     o.keychain = argv[++i];
        else if (!strcmp(argv[i], "--access-group") && i + 1 < argc) o.access_group = argv[++i];
        else if (!strcmp(argv[i], "--data-protection"))              o.data_protection = 1;
        else { fprintf(stderr, "kow-keyd: unknown argument %s\n", argv[i]); usage(); return EXIT_USAGE; }
    }

    if (!o.service) { fprintf(stderr, "kow-keyd: --service is required\n"); return EXIT_USAGE; }
    if (!o.account && strcmp(o.verb, "list") != 0) {
        fprintf(stderr, "kow-keyd: --account is required for %s\n", o.verb);
        return EXIT_USAGE;
    }
    if (o.data_protection && o.keychain) {
        fprintf(stderr, "kow-keyd: --keychain names a file-based keychain and cannot be combined "
                        "with --data-protection\n");
        return EXIT_USAGE;
    }

    /* Never raise a dialog. A LaunchAgent has nobody to answer one, and an
     * unanswerable modal is worse than a clean error: it hangs the proxy and
     * leaves a prompt on screen that a passing human might approve. With UI
     * suppressed, a caller the ACL does not list gets errSecInteractionNotAllowed
     * and we exit 51. */
    SecKeychainSetUserInteractionAllowed(false);

    OSStatus open_st = errSecSuccess;
    SecKeychainRef kc = open_keychain(&o, &open_st);
    if (open_st != errSecSuccess) {
        warn_status("opening the keychain", open_st);
        return status_to_exit(open_st);
    }

    int rc;
    if (!strcmp(o.verb, "get"))          rc = do_get(&o, kc);
    else if (!strcmp(o.verb, "set"))     rc = do_write(&o, kc, 0);
    else if (!strcmp(o.verb, "replace")) rc = do_write(&o, kc, 1);
    else if (!strcmp(o.verb, "delete")) rc = do_delete(&o, kc);
    else if (!strcmp(o.verb, "list"))   rc = do_list(&o, kc);
    else { fprintf(stderr, "kow-keyd: unknown verb %s\n", o.verb); usage(); rc = EXIT_USAGE; }

    if (kc) CFRelease(kc);
    return rc;
}

#pragma clang diagnostic pop
