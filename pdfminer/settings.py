STRICT = False

try:
    from django.conf import settings
    STRICT = getattr(settings, 'PDF_MINER_IS_STRICT', STRICT)
except Exception:
    # in case it's not a django project
    pass
