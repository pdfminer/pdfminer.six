STRICT = True

try:
    from django.conf import django_settings
    STRICT = getattr(django_settings, 'PDF_MINER_IS_STRICT', STRICT)
except Exception:
    # in case it's not a django project
    pass
