#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

/**
 * @brief a generic key/value structure
 */
struct evhtp_keyval_ {
    char * kv_key;
    char * kv_val;

    size_t kv_klen;
    size_t kv_vlen;

    char kv_key_heaped; /**< set to 1 if the key can be free()'d */
    char kv_val_heaped; /**< set to 1 if the val can be free()'d */

    TAILQ_ENTRY(struct evhtp_keyval_) next;
};

TAILQ_HEAD(evhtp_keyvals_, struct evhtp_keyval_);


struct evhtp_keyvals_ *
evhtp_keyval_new(void)
{
    struct evhtp_keyvals_ * keyval;

    if ((keyval = malloc(sizeof(struct evhtp_keyvals_))) == NULL)
    {
        return NULL;
    }

    TAILQ_INIT(keyval);

    return keyval;
}

evhtp_kv_t *
evhtp_kv_new(const char * key, const char * val, char kalloc, char valloc)
{
    evhtp_kv_t * kv;

    kv           = malloc(sizeof(evhtp_kv_t));
    evhtp_alloc_assert(kv);

    kv->k_heaped = kalloc;
    kv->v_heaped = valloc;
    kv->klen     = 0;
    kv->vlen     = 0;
    kv->key      = NULL;
    kv->val      = NULL;

    if (key != NULL)
    {
        kv->klen = strlen(key);

        if (kalloc == 1)
        {
            char * s;

            if (!(s = malloc(kv->klen + 1)))
            {
                evhtp_safe_free(kv, free);

                return NULL;
            }

            memcpy(s, key, kv->klen);

            s[kv->klen] = '\0';
            kv->key     = s;
        } else {
            kv->key = (char *)key;
        }
    }

    if (val != NULL)
    {
        kv->vlen = strlen(val);

        if (valloc == 1)
        {
            char * s = malloc(kv->vlen + 1);

            s[kv->vlen] = '\0';
            memcpy(s, val, kv->vlen);
            kv->val     = s;
        } else {
            kv->val = (char *)val;
        }
    }

    return kv;
}     /* evhtp_kv_new */

void
evhtp_kv_free(evhtp_kv_t * kv)
{
    if (evhtp_unlikely(kv == NULL))
    {
        return;
    }

    if (kv->k_heaped)
    {
        evhtp_safe_free(kv->key, free);
    }

    if (kv->v_heaped)
    {
        evhtp_safe_free(kv->val, free);
    }

    evhtp_safe_free(kv, free);
}

void
evhtp_kv_rm_and_free(struct evhtp_keyvals_ * keyval, evhtp_kv_t * kv)
{
    if (evhtp_unlikely(keyval == NULL || kv == NULL))
    {
        return;
    }

    TAILQ_REMOVE(keyval, kv, next);

    evhtp_kv_free(kv);
}

void
evhtp_keyval_free(struct evhtp_keyvals_ * keyval)
{
    evhtp_kv_t * kv;
    evhtp_kv_t * save;

    if (evhtp_unlikely(keyval == NULL))
    {
        return;
    }

    kv   = NULL;
    save = NULL;

    for (kv = TAILQ_FIRST(keyval); kv != NULL; kv = save)
    {
        save = TAILQ_NEXT(kv, next);

        TAILQ_REMOVE(keyval, kv, next);

        evhtp_safe_free(kv, evhtp_kv_free);
    }

    evhtp_safe_free(keyval, free);
}

int
evhtp_keyval_for_each(struct evhtp_keyvals_ * keyval, evhtp_keyval_iterator cb, void * arg)
{
    evhtp_kv_t * kv;

    if (keyval == NULL || cb == NULL)
    {
        return -1;
    }

    TAILQ_FOREACH(kv, keyval, next)
    {
        int res;

        if ((res = cb(kv, arg)))
        {
            return res;
        }
    }

    return 0;
}

const char *
evhtp_kv_find(struct evhtp_keyvals_ * keyval, const char * key)
{
    evhtp_kv_t * kv;

    if (evhtp_unlikely(keyval == NULL || key == NULL))
    {
        return NULL;
    }

    TAILQ_FOREACH(kv, keyval, next)
    {
        if (strcasecmp(kv->key, key) == 0)
        {
            return kv->val;
        }
    }

    return NULL;
}

evhtp_kv_t *
evhtp_keyval_find_kv(struct evhtp_keyvals_ * keyval, const char * key)
{
    evhtp_kv_t * kv;

    if (evhtp_unlikely(keyval == NULL || key == NULL))
    {
        return NULL;
    }

    TAILQ_FOREACH(kv, keyval, next)
    {
        if (strcasecmp(kv->key, key) == 0)
        {
            return kv;
        }
    }

    return NULL;
}

void
evhtp_keyval_add_kv(struct evhtp_keyvals_ * keyval, evhtp_kv_t * kv)
{
    if (evhtp_unlikely(keyval == NULL || kv == NULL))
    {
        return;
    }

    TAILQ_INSERT_TAIL(keyval, kv, next);
}

void
evhtp_keyval_add_keyval(struct evhtp_keyvals_ * dst, struct evhtp_keyvals_ * src)
{
    if (dst == NULL || src == NULL)
    {
        return;
    }

    evhtp_kv_t * kv;

    TAILQ_FOREACH(kv, src, next)
    {
        evhtp_keyval_add_kv(dst, evhtp_kv_new(kv->key,
                                              kv->val,
                                              kv->k_heaped,
                                              kv->v_heaped));
    }
}

