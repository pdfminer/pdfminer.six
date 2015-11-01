try:
    from django.conf import django_settings
except ImportError:
    # in case it's not a django project
    django_settings = None

# Get defaults from django settings
STRICT = getattr(django_settings, 'PDF_MINER_IS_STRICT', True)
